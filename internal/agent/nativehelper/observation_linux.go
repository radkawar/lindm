// SPDX-License-Identifier: Apache-2.0

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
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/agent/sshprovider"
	"lindm/internal/resource"
)

const observationTimeout = 8 * time.Second

func resourceObservationTimeout(request *agentv1.NativeResourceObservationRequest) time.Duration {
	if request.GetDesired().GetManagedFile().GetKernelModuleBlocklist() != nil {
		return 2 * time.Minute
	}
	return observationTimeout
}

// ObserveResource opens a separate read-only native boundary only for facts the
// resident executor cannot read in its unchanged sandbox. It grants no effects.
func ObserveResource(ctx context.Context, stateDirectory string, input *agentv1.NativeResourceObservationRequest) (_ *agentv1.NativeHelperResult, resultErr error) {
	if os.Geteuid() != 0 || input == nil {
		return nil, errors.New("native_observation_root_required")
	}
	ctx, cancel := context.WithTimeout(ctx, resourceObservationTimeout(input))
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
		if request.GetDesired().GetSshServer() != nil {
			switch result.GetReason() {
			case "ssh_banner_native_conflict":
				return nil, sshprovider.ErrConflict
			case "ssh_banner_native_unsupported":
				return nil, sshprovider.ErrUnsupported
			}
		}
		return nil, errors.New("native_observation_failed")
	}
	kind, err := observedKind(request.GetDesired().GetRef().GetKind())
	if err != nil {
		return nil, err
	}
	if kind.evidence {
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
	ctx, cancel := context.WithTimeout(ctx, resourceObservationTimeout(request))
	defer cancel()
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
	kind, err := observedKind(request.GetDesired().GetRef().GetKind())
	if err == nil {
		env := resourceprovider.NativeEnv{Config: document.Proto, ProtectedPaths: document.ProtectedPaths, Directory: directory, Digest: custody.Digest, Platform: request.GetPlatform(), ExecutorIncarnation: request.GetExecutorIncarnation()}
		err = kind.observe(ctx, document, env, request, result)
	}
	if err != nil {
		result.After = nil
		result.Encryption = nil
		result.FirewallAllow = nil
		result.FirewallDeny = nil
		result.FirewallEvidence = nil
		result.Outcome = agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_FAILED
		result.Reason = "native_observation_unavailable"
		if request.GetDesired().GetSshServer() != nil {
			switch {
			case errors.Is(err, sshprovider.ErrConflict), errors.Is(err, nativefile.ErrConflict), errors.Is(err, nativefile.ErrUnsafePath):
				result.Reason = "ssh_banner_native_conflict"
			case errors.Is(err, sshprovider.ErrUnsupported), errors.Is(err, nativefile.ErrUnsupported):
				result.Reason = "ssh_banner_native_unsupported"
			}
		}
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
	properties = setProperty(properties, "RuntimeMaxUSec", uint64(resourceObservationTimeout(request)/time.Microsecond))
	properties = setProperty(properties, "TimeoutStopUSec", uint64(time.Second/time.Microsecond))
	properties = setProperty(properties, "PrivateNetwork", true)
	properties = setProperty(properties, "RestrictAddressFamilies", addressFamilies("AF_UNIX"))
	properties = setProperty(properties, "MemoryMax", uint64(128<<20))
	properties = setProperty(properties, "TasksMax", uint64(64))
	kind, err := observedKind(request.GetDesired().GetRef().GetKind())
	if err != nil {
		return nil, err
	}
	if kind.observation == nil {
		return properties, nil
	}
	return kind.observation(ctx, properties, request)
}
