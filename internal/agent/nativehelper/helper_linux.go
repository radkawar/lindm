//go:build linux

package nativehelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/packageprovider"
)

// Run is the fixed installed helper entrypoint. The operation and all native
// inputs come from a bounded immutable root-owned protobuf, never command argv.
func Run(ctx context.Context, document *config.Document, transactionID, phase string) (resultErr error) {
	if os.Geteuid() != 0 || document == nil {
		return errors.New("package_helper_root_configuration_required")
	}
	ctx, cancel := context.WithTimeout(ctx, transactionTimeout)
	defer cancel()
	directory, err := transactionDirectory(document.StateDirectory, transactionID)
	if err != nil {
		return err
	}
	if phase != "prepare" && phase != "apply" {
		return errors.New("package_helper_phase")
	}
	request := new(agentv1.NativePackageTransactionRequest)
	encoded, err := readRecord(directory, phase+"-request.pb", request)
	if err != nil {
		return err
	}
	defer clear(encoded)
	expectedPhase, err := phaseName(request.GetOperation())
	if err != nil || expectedPhase != phase || request.GetTransactionId() != transactionID {
		return errors.New("package_helper_request_identity")
	}
	approved := false
	for _, source := range document.Proto.GetPackageProvider().GetSources() {
		if proto.Equal(source, request.GetSource()) {
			approved = true
			break
		}
	}
	if !approved {
		return errors.New("package_helper_source_not_approved")
	}
	if err := notCancelled(directory); err != nil {
		return err
	}
	if phase == "apply" {
		// The confined apply unit cannot read PID 1's namespace links without
		// ptrace authority. A systemd PrivateNetwork namespace has only loopback.
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		if len(interfaces) != 1 || interfaces[0].Name != "lo" {
			return errors.New("package_helper_private_network_required")
		}
	}
	// A second helper process cannot replay either an interrupted invocation or
	// a completed one. Incomplete receipts remain visible for reconciliation.
	if err := writeProtected(directory, phase+"-invocation.pb", encoded); err != nil {
		return fmt.Errorf("reserve package helper invocation: %w", err)
	}
	requestHash := sha256.Sum256(encoded)
	if phase == "prepare" {
		ctx, deadlineCancel := context.WithDeadline(ctx, request.GetStagingExpiresAt().AsTime())
		defer deadlineCancel()
		resultErr = packageprovider.PrepareNative(ctx, document.StateDirectory, request)
		result := &agentv1.NativeHelperResult{
			RequestSha256: bytes.Clone(requestHash[:]), Nonce: bytes.Clone(request.GetNonce()),
			Outcome: agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_PREPARED,
		}
		if resultErr == nil {
			result.DeclaredBytes, result.ObservedBytes, resultErr = packageprovider.PreparationStats(directory)
		}
		if resultErr != nil {
			result.Outcome = agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_FAILED
			result.Reason = "native_staging_failed"
			if errors.Is(resultErr, packageprovider.ErrBusy) {
				result.Reason = reasonNativeBusy
			}
		}
		resultBytes, err := encodeRecord(result)
		if err != nil {
			return errors.Join(resultErr, err)
		}
		defer clear(resultBytes)
		return errors.Join(resultErr, writeProtected(directory, "prepare-result.pb", resultBytes))
	}
	return serveEffect(ctx, directory, encoded, request.GetNonce(), func(ctx context.Context, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
		return nil, packageprovider.ExecuteNative(ctx, document.StateDirectory, request, gate)
	})
}

func serveEffect(ctx context.Context, directory string, encoded, nonce []byte, execute func(context.Context, func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error)) (resultErr error) {
	const phase = "apply"
	requestHash := sha256.Sum256(encoded)
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(directory, phase+"-control.sock"))
	if err != nil {
		return err
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		return errors.Join(errors.New("package_helper_channel_transport"), raw.Close())
	}
	defer func() { resultErr = errors.Join(resultErr, connection.Close()) }()
	if err := requireRootPeer(connection); err != nil {
		return err
	}
	if err := connection.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	started := false
	result := &agentv1.NativeHelperResult{RequestSha256: bytes.Clone(requestHash[:]), Nonce: bytes.Clone(nonce)}
	result.After, resultErr = execute(ctx, func(gateContext context.Context) error {
		if started {
			return errors.New("package_helper_effect_gate_reused")
		}
		if err := gateContext.Err(); err != nil {
			return err
		}
		ready := &agentv1.NativeHelperReady{RequestSha256: bytes.Clone(requestHash[:]), Nonce: bytes.Clone(nonce)}
		if err := sendMessage(connection, &agentv1.NativeHelperMessage{Message: &agentv1.NativeHelperMessage_Ready{Ready: ready}}); err != nil {
			return err
		}
		message, err := receiveMessage(connection)
		if err != nil {
			return err
		}
		permit := message.GetPermit()
		if permit == nil || !bytes.Equal(permit.GetRequestSha256(), requestHash[:]) || !bytes.Equal(permit.GetNonce(), nonce) {
			return errors.New("package_helper_permit_binding")
		}
		if err := validatePermit(permit); err != nil {
			return err
		}
		permitBytes, err := encodeRecord(permit)
		if err != nil {
			return err
		}
		defer clear(permitBytes)
		if err := writeProtected(directory, "apply-started.pb", permitBytes); err != nil {
			return err
		}
		started = true
		// Disk sync and message transfer never extend signed authority. The
		// kernel suspend-aware clock is checked immediately before mutation.
		return validatePermit(permit)
	})
	result.Outcome = agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_SUCCEEDED
	if resultErr == nil && !started {
		resultErr = errors.New("package_helper_effect_gate_not_consumed")
	}
	if resultErr != nil {
		result.Outcome = agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_FAILED
		result.Reason = "native_precondition_or_configuration_failure"
		if errors.Is(resultErr, packageprovider.ErrBusy) {
			result.Reason = reasonNativeBusy
		}
		if started {
			result.Outcome = agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_UNKNOWN
			result.Reason = "native_effect_outcome_unknown"
		}
	}
	resultBytes, err := encodeRecord(result)
	if err != nil {
		return errors.Join(resultErr, err)
	}
	defer clear(resultBytes)
	if err := writeProtected(directory, phase+"-result.pb", resultBytes); err != nil {
		return errors.Join(resultErr, err)
	}
	// A dead executor does not erase native completion or cause a helper replay.
	// Persisted evidence above remains authoritative if this final delivery fails.
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return errors.Join(resultErr, err)
	}
	return errors.Join(resultErr, sendMessage(connection, &agentv1.NativeHelperMessage{Message: &agentv1.NativeHelperMessage_Result{Result: result}}))
}

func validatePermit(permit *agentv1.NativeEffectPermit) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(boot)) != permit.GetBootId() {
		return errors.New("package_helper_boot_changed")
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return err
	}
	if now.Nano() < 0 || uint64(now.Nano()) >= permit.GetStartDeadlineBoottimeNs() {
		return errors.New("package_helper_start_expired")
	}
	return nil
}
