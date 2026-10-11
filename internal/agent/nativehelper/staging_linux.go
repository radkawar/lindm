//go:build linux

package nativehelper

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/packageprovider"
	"lindm/internal/agent/statefs"
)

// Stage starts or inspects a durable effect-free staging unit without waiting for
// native resolution or downloads. The immutable action request and retained
// result survive executor restarts. An interrupted helper is never replayed.
func Stage(ctx context.Context, stateDirectory string, input *agentv1.NativePackageTransactionRequest) (_ bool, resultErr error) {
	if os.Geteuid() != 0 || input.GetOperation() != agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_PREPARE || input.GetActionId() != input.GetTransactionId() {
		return false, errors.New("package_staging_identity")
	}
	directory, err := transactionDirectory(stateDirectory, input.GetTransactionId())
	if err != nil {
		return false, err
	}
	unlock, err := stagingLock(directory)
	if err != nil {
		return false, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	if err := notCancelled(directory); err != nil {
		return false, err
	}
	if !time.Now().Before(input.GetStagingExpiresAt().AsTime()) {
		return false, errors.New("package_staging_expired")
	}
	request := new(agentv1.NativePackageTransactionRequest)
	encoded, err := readRecord(directory, "prepare-request.pb", request)
	fresh := errors.Is(err, os.ErrNotExist)
	if err != nil && !fresh {
		return false, err
	}
	if fresh {
		request = proto.CloneOf(input)
		request.Nonce = make([]byte, 32)
		if _, err := rand.Read(request.Nonce); err != nil {
			return false, err
		}
		encoded, err = encodeRecord(request)
		if err != nil {
			return false, err
		}
		if err := writeProtected(directory, "prepare-request.pb", encoded); err != nil {
			return false, err
		}
	} else {
		candidate := proto.CloneOf(input)
		candidate.Nonce = bytes.Clone(request.GetNonce())
		if !proto.Equal(candidate, request) {
			return false, errors.New("package_staging_request_changed")
		}
	}
	digest := sha256.Sum256(encoded)
	result := new(agentv1.NativeHelperResult)
	if err := readRecordInto(directory, "prepare-result.pb", result); err == nil {
		if !bytes.Equal(result.GetRequestSha256(), digest[:]) || !bytes.Equal(result.GetNonce(), request.GetNonce()) {
			return false, errors.New("package_staging_result_binding")
		}
		if result.GetOutcome() != agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_PREPARED {
			return false, errors.New("package_staging_native_failed")
		}
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	bus, err := openBus(ctx)
	if err != nil {
		return false, err
	}
	defer func() { resultErr = errors.Join(resultErr, bus.close()) }()
	active, exists, err := bus.active(ctx, unitName(request.GetTransactionId(), "prepare"))
	if err != nil {
		return false, err
	}
	if active {
		return false, nil
	}
	if exists {
		return false, errors.New("package_staging_interrupted_without_result")
	}
	if err := readRecordInto(directory, "prepare-invocation.pb", new(agentv1.NativePackageTransactionRequest)); err == nil {
		return false, errors.New("package_staging_interrupted_without_result")
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := packageprovider.ValidateStagingProjection(request); err != nil {
		return false, err
	}
	if request.CandidatePinContents != nil {
		if err := writeExclusive(directory, candidatePinName, request.GetCandidatePinContents()); err != nil && !errors.Is(err, os.ErrExist) {
			return false, err
		}
		retained, err := readRecordBytes(directory, candidatePinName)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(retained, request.GetCandidatePinContents()) {
			return false, errors.New("package_staging_candidate_pin_changed")
		}
	}
	return false, bus.start(ctx, directory, request, "prepare")
}

// candidatePinName holds the projected native lock document (DNF5 TOML or the
// DNF4 plugin list) bound read-only over its original path during staging.
const candidatePinName = "candidate-versionlock"

func stagingLock(directory string) (func() error, error) {
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return func() error { return unix.Close(fd) }, nil
}

func notCancelled(directory string) error {
	err := readRecordInto(directory, "cancelled.pb", new(agentv1.NativePackageStagingCancellation))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("package_staging_cancelled")
}

// CancelStage tombstones the action before stopping its staging unit. Cleanup
// waits for native helper termination and never deletes another transaction or
// effect receipt. Repeated calls finish interrupted cleanup, never restart work.
func CancelStage(ctx context.Context, stateDirectory, actionID string) (resultErr error) {
	directory, err := transactionDirectory(stateDirectory, actionID)
	if err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	unlock, err := stagingLock(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	marker := &agentv1.NativePackageStagingCancellation{ActionId: actionID}
	encoded, err := encodeRecord(marker)
	if err != nil {
		return err
	}
	if err := writeProtected(directory, "cancelled.pb", encoded); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := readRecordInto(directory, "apply-started.pb", new(agentv1.NativeEffectPermit)); err == nil {
		return errors.New("package_staging_effect_already_started")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	bus, err := openBus(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, bus.close()) }()
	active, _, err := bus.active(ctx, unitName(actionID, "prepare"))
	if err != nil {
		return err
	}
	if active {
		if err := bus.stop(ctx, unitName(actionID, "prepare")); err != nil {
			return err
		}
		return errors.New("package_staging_cleanup_pending")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "cancelled.pb", "prepare-request.pb", "prepare-result.pb", "prepare-invocation.pb":
			continue
		}
		if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	return errors.Join(unix.Fsync(fd), unix.Close(fd))
}
