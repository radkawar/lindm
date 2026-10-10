//go:build linux

package nativehelper

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/config"
	"lindm/internal/agent/firewallprovider"
	"lindm/internal/resource"
)

const observationTimeout = 8 * time.Second

// ObserveResource opens a separate read-only native boundary only for facts the
// resident executor cannot read in its unchanged sandbox. It grants no effects.
func ObserveResource(ctx context.Context, stateDirectory string, input *agentv1.NativeResourceObservationRequest) (_ *agentv1.NativeHelperResult, resultErr error) {
	if os.Geteuid() != 0 || input == nil {
		return nil, errors.New("native_observation_root_required")
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	request := proto.CloneOf(input)
	request.ObservationId = uuid.NewString()
	request.Nonce = make([]byte, 32)
	if _, err := rand.Read(request.Nonce); err != nil {
		return nil, err
	}
	if err := resource.ValidateDesired(request.GetDesired()); err != nil {
		return nil, err
	}
	encoded, err := encodeRecord(request)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	bus, err := openBus(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, bus.close()) }()
	directory, err := observationDirectory(ctx, bus, stateDirectory, request.GetObservationId())
	if err != nil {
		return nil, err
	}
	unit := "lindm-observe-" + request.GetObservationId() + ".service"
	attempted, complete := false, false
	defer func() {
		if !attempted || complete {
			resultErr = errors.Join(resultErr, removeObservation(directory))
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		active, _, err := bus.active(cleanup, unit)
		if err != nil {
			resultErr = errors.Join(resultErr, err)
			return
		}
		if active {
			resultErr = errors.Join(resultErr, bus.stop(cleanup, unit))
			return
		}
		resultErr = errors.Join(resultErr, removeObservation(directory))
	}()
	properties, err := observationProperties(ctx, directory, request)
	if err != nil {
		return nil, err
	}
	if err := writeProtected(directory, "observe-request.pb", encoded); err != nil {
		return nil, err
	}
	socketPath := filepath.Join(directory, "observe-control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, listener.Close()) }()
	if err := os.Chmod(socketPath, 0600); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		return nil, err
	}
	attempted = true
	if err := bus.startUnit(ctx, unit, properties); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	connection, err := listener.AcceptUnix()
	stop()
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, connection.Close()) }()
	if err := requireRootPeer(connection); err != nil {
		return nil, err
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stopConnection := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopConnection()
	message, err := receiveMessage(connection)
	if err != nil {
		return nil, err
	}
	result := message.GetResult()
	digest := sha256.Sum256(encoded)
	if result == nil || !bytes.Equal(result.GetRequestSha256(), digest[:]) || !bytes.Equal(result.GetNonce(), request.GetNonce()) {
		return nil, errors.New("native_observation_result_binding")
	}
	retained := new(agentv1.NativeHelperResult)
	if err := readRecordInto(directory, "observe-result.pb", retained); err != nil {
		return nil, err
	}
	if !proto.Equal(retained, result) {
		return nil, errors.New("native_observation_retained_mismatch")
	}
	if result.GetOutcome() != agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_OBSERVED {
		return nil, errors.New("native_observation_failed")
	}
	if request.GetDesired().GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE {
		if result.GetEncryption() == nil || result.GetAfter() != nil {
			return nil, errors.New("native_observation_kind_mismatch")
		}
	} else if result.GetAfter() == nil || result.GetEncryption() != nil || !resource.RefEqual(result.GetAfter().GetObservation().GetRef(), request.GetDesired().GetRef()) {
		return nil, errors.New("native_observation_kind_mismatch")
	}
	if (request.GetFirewallVerification() != nil) != (result.GetFirewallEvidence() != nil) {
		return nil, errors.New("native_firewall_proof_missing")
	}
	complete = true
	return result, nil
}

func removeObservation(directory string) error {
	// No recursive deletion: the fixed observer creates only these bounded files.
	for _, name := range []string{"observe-request.pb", "observe-invocation.pb", "observe-result.pb", "observe-control.sock"} {
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(directory)
}

// RunObservation reads native facts. Firewall verification additionally emits
// bounded packets and socket-owned trace-only tables, never desired policy.
func RunObservation(ctx context.Context, document *config.Document, observationID string) error {
	if os.Geteuid() != 0 || document == nil {
		return errors.New("native_observation_root_configuration_required")
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	directory, err := resourceDirectory(document.StateDirectory, "resource-observations", observationID, false)
	if err != nil {
		return err
	}
	request := new(agentv1.NativeResourceObservationRequest)
	encoded, err := readRecord(directory, "observe-request.pb", request)
	if err != nil {
		return err
	}
	defer clear(encoded)
	custody, err := helperCustody(directory)
	if err != nil {
		return err
	}
	defer custody.Close()
	if request.GetObservationId() != observationID {
		return errors.New("native_observation_identity")
	}
	if err := resource.ValidateDesired(request.GetDesired()); err != nil {
		return err
	}
	if err := writeProtected(directory, "observe-invocation.pb", encoded); err != nil {
		return err
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(directory, "observe-control.sock"))
	if err != nil {
		return err
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return errors.New("native_observation_channel")
	}
	defer func() { _ = connection.Close() }()
	if err := requireRootPeer(connection); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	hash := sha256.Sum256(encoded)
	result := &agentv1.NativeHelperResult{RequestSha256: hash[:], Nonce: bytes.Clone(request.GetNonce()), Outcome: agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_OBSERVED}
	switch request.GetDesired().GetRef().GetKind() {
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:
		result.After, err = accountprovider.ObserveNative(ctx, accountprovider.NativeConfig{Native: document.Proto.GetAccountProvider(), Platform: request.GetPlatform(), ExecutorIncarnation: request.GetExecutorIncarnation(), NativeDigest: custody.Digest}, request.GetDesired())
	case resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:
		template := &resourcev1.ResourceObservation{Ref: proto.CloneOf(request.GetDesired().GetRef()), Metadata: &resourcev1.ObservationMetadata{ExecutorIncarnation: request.GetExecutorIncarnation(), Backend: proto.CloneOf(request.GetBackend())}}
		result.After, err = firewallprovider.ReadNative(ctx, document.Proto.GetFirewallProvider(), template)
		if err == nil && request.GetFirewallVerification() != nil {
			var verifierClose func() error
			verifier, closeVerifier, openErr := newFirewallVerifier(ctx, document, request)
			verifierClose = closeVerifier
			if openErr != nil {
				err = openErr
			} else {
				result.FirewallAllow, result.FirewallDeny, result.FirewallEvidence, err = verifier.ProbeVerification(ctx, request.GetDesired().GetFirewallZone(), request.GetFirewallVerification())
				err = errors.Join(err, verifierClose())
			}
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE:
		var evidence *actionprovider.RootEncryptionEvidence
		evidence, err = actionprovider.ObserveRootEncryption(ctx)
		if err == nil {
			result.Encryption = &agentv1.NativeRootEncryptionEvidence{LuksRoot: evidence.LUKSRoot, Target: proto.CloneOf(evidence.Target), NativeSha256: bytes.Clone(evidence.NativeSHA256), MetadataSha256: bytes.Clone(evidence.MetadataSHA256), TpmBound: evidence.TPMBound, Reason: evidence.Reason}
			for _, recovery := range evidence.Recovery {
				result.Encryption.Recovery = append(result.Encryption.Recovery, &agentv1.NativeRootRecoveryEvidence{ActionId: recovery.ActionID, Keyslot: recovery.Keyslot, KeySha256: bytes.Clone(recovery.KeySHA256)})
			}
		}
	default:
		err = errors.New("native_observation_kind_not_supported")
	}
	if err != nil {
		result.After = nil
		result.Encryption = nil
		result.FirewallAllow = nil
		result.FirewallDeny = nil
		result.FirewallEvidence = nil
		result.Outcome = agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_FAILED
		result.Reason = "native_observation_unavailable"
	}
	encodedResult, encodeErr := encodeRecord(result)
	if encodeErr != nil {
		return errors.Join(err, encodeErr)
	}
	defer clear(encodedResult)
	if writeErr := writeProtected(directory, "observe-result.pb", encodedResult); writeErr != nil {
		return errors.Join(err, writeErr)
	}
	return errors.Join(err, sendMessage(connection, &agentv1.NativeHelperMessage{Message: &agentv1.NativeHelperMessage_Result{Result: result}}))
}

func observationProperties(ctx context.Context, directory string, request *agentv1.NativeResourceObservationRequest) ([]unitProperty, error) {
	properties := transientProperties(directory, request.GetObservationId(), "prepare")
	properties = setProperty(properties, "Description", "Lindm bounded native resource observation")
	properties = setProperty(properties, "ExecStart", []unitExec{{Path: helperExecutable, Arguments: []string{helperExecutable, "resource-observe", "-observation", request.GetObservationId()}}})
	properties = setProperty(properties, "RuntimeMaxUSec", uint64(observationTimeout/time.Microsecond))
	properties = setProperty(properties, "TimeoutStopUSec", uint64(time.Second/time.Microsecond))
	properties = setProperty(properties, "PrivateNetwork", true)
	properties = setProperty(properties, "RestrictAddressFamilies", struct {
		AllowList bool
		Families  []string
	}{true, []string{"AF_UNIX"}})
	properties = setProperty(properties, "MemoryMax", uint64(128<<20))
	properties = setProperty(properties, "TasksMax", uint64(64))
	switch request.GetDesired().GetRef().GetKind() {
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP:
		properties = setProperty(properties, "ProtectHome", "read-only")
		properties = setProperty(properties, "PrivateNetwork", false)
		properties = setProperty(properties, "RestrictAddressFamilies", struct {
			AllowList bool
			Families  []string
		}{true, []string{"AF_UNIX", "AF_INET", "AF_INET6"}})
	case resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:
		properties = setProperty(properties, "PrivateNetwork", false)
		properties = setProperty(properties, "CapabilityBoundingSet", uint64(1)<<unix.CAP_NET_ADMIN|uint64(1)<<unix.CAP_DAC_READ_SEARCH)
		properties = setProperty(properties, "RestrictAddressFamilies", struct {
			AllowList bool
			Families  []string
		}{true, []string{"AF_UNIX", "AF_NETLINK"}})
		if request.GetFirewallVerification() != nil {
			properties = setProperty(properties, "CapabilityBoundingSet", uint64(1)<<unix.CAP_NET_ADMIN|uint64(1)<<unix.CAP_NET_RAW|uint64(1)<<unix.CAP_DAC_READ_SEARCH)
			properties = setProperty(properties, "RestrictAddressFamilies", struct {
				AllowList bool
				Families  []string
			}{true, []string{"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"}})
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE:
		devices, err := actionprovider.RootEncryptionReadDevices(ctx)
		if err != nil {
			return nil, err
		}
		if len(devices) != 0 {
			type devicePermission struct {
				Path        string
				Permissions string
			}
			allow := make([]devicePermission, 0, len(devices))
			for _, path := range devices {
				mode := "r"
				if path == "/dev/mapper/control" || path == "/dev/tpmrm0" {
					mode = "rw"
				}
				allow = append(allow, devicePermission{path, mode})
			}
			properties = setProperty(properties, "PrivateDevices", false)
			properties = setProperty(properties, "DevicePolicy", "closed")
			properties = setProperty(properties, "DeviceAllow", allow)
			properties = setProperty(properties, "CapabilityBoundingSet", uint64(1)<<unix.CAP_SYS_ADMIN|uint64(1)<<unix.CAP_DAC_READ_SEARCH)
		}
	default:
		return nil, errors.New("native_observation_kind_not_supported")
	}
	return properties, nil
}
