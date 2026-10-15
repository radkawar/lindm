// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/advisory/feed"
	"lindm/internal/labhost"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
	"lindm/internal/vmlab"
)

// A distinct status survives local/SSH admission without disguising teardown,
// record persistence or stdout failures as a missing vendor prerequisite.
const cinnamonLockGateExitCode = 3

func labExitCode(err error) int {
	if err == nil {
		return 0
	}
	if vmlab.IsCinnamonLockGate(err) || cinnamonLockGateExit(err) {
		return cinnamonLockGateExitCode
	}
	return 1
}

func cinnamonLockGateExit(err error) bool {
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		children := e.Unwrap()
		return len(children) == 1 && cinnamonLockGateExit(children[0])
	case interface{ Unwrap() error }:
		return cinnamonLockGateExit(e.Unwrap())
	case *exec.ExitError:
		return e.ExitCode() == cinnamonLockGateExitCode
	default:
		return false
	}
}

// Hash the same bounded native document that is inspected, including trailing
// whitespace. These records describe the native run, not product authority.
func readCinnamonLockRecord(path string) (_ *vmlab.VMDeviceActionsResult, sum string, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, "", errors.New("native Cinnamon lock evidence must be a bounded regular JSON file")
	}
	hash := sha256.New()
	decoder := json.NewDecoder(io.TeeReader(io.LimitReader(file, (1<<20)+1), hash))
	decoder.DisallowUnknownFields()
	result := new(vmlab.VMDeviceActionsResult)
	if err := decoder.Decode(result); err != nil {
		return nil, "", fmt.Errorf("decode Cinnamon lock evidence: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, "", errors.New("native Cinnamon lock evidence must contain exactly one JSON object")
	}
	return result, hex.EncodeToString(hash.Sum(nil)), nil
}

// Compare the upstream dpkg version: an epoch cannot turn Cinnamon 6.6 into
// 6.7.9, and a 6.7.9~rc build remains below the fixed upstream release.
func cinnamonLockVersionFixed(version string) (bool, error) {
	if _, err := feed.Compare("dpkg", version, version); err != nil {
		return false, err
	}
	_, upstream, hasEpoch := strings.Cut(version, ":")
	if !hasEpoch {
		upstream = version
	}
	if i := strings.LastIndexByte(upstream, '-'); i >= 0 {
		upstream = upstream[:i]
	}
	comparison, err := feed.Compare("dpkg", upstream, platform.CinnamonLockMinimumVersion)
	return comparison >= 0, err
}

func validateCinnamonLockRecord(result *vmlab.VMDeviceActionsResult, imageID string) (labv1.MatrixVerdict, string, error) {
	fail := func(reason string) (labv1.MatrixVerdict, string, error) {
		return labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, "", errors.New(reason)
	}
	if result == nil || result.Scenario != "wipe" || result.WipePhase != "cinnamon-lock-confirmation" || result.EncryptionPhase != "" || result.DesktopProfile != "cinnamon" || result.CinnamonLock == nil {
		return fail("record is not the native Cinnamon lock-confirmation phase")
	}
	if result.ImageID == "" || (imageID != "" && result.ImageID != imageID) || result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		return fail("Cinnamon lock record has inconsistent image or run metadata")
	}
	evidence := result.CinnamonLock
	if evidence.MinimumVersion != platform.CinnamonLockMinimumVersion {
		return fail("Cinnamon lock record changed the fixed platform minimum version")
	}
	installedFixed, err := cinnamonLockVersionFixed(evidence.InstalledVersion)
	if err != nil {
		return fail("Cinnamon lock record has an invalid installed package version")
	}
	candidateFixed := false
	if evidence.CandidateVersion != "" {
		candidateFixed, err = cinnamonLockVersionFixed(evidence.CandidateVersion)
		if err != nil {
			return fail("Cinnamon lock record has an invalid vendor candidate version")
		}
	}
	validDigest := func(value string) bool {
		if len(value) != sha256.Size*2 {
			return false
		}
		for _, c := range value {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
		return true
	}
	for _, digest := range []string{result.ImageSHA256, result.PackageSHA256, result.LabSHA256, result.LindmdSHA256} {
		if !validDigest(digest) {
			return fail("Cinnamon lock record lacks native image or executable digests")
		}
	}
	if result.Escrow != nil || result.CommittedRotation != nil || result.InterruptedRotation != nil || result.TPMBind != nil || result.TPMReferenceRepair != nil || result.TPMPolicyBind != nil || result.Recovery != nil || result.LiveErase != nil || result.LiveEraseReportLoss != nil || len(result.OriginalRecovery) != 0 || len(result.AccountLocks) != 0 || len(result.Quarantine) != 0 || len(result.Denials) != 0 {
		return fail("Cinnamon lock-only record contains unrelated device actions")
	}
	if evidence.GateReason != "" {
		if installedFixed || candidateFixed || evidence.CandidateVersion == "" || result.Passed || result.Failure != evidence.GateReason || result.HostObservationError != "" || evidence.NativeLocker || result.Lock != nil || result.LockRelease != nil || result.DesktopBefore != nil || result.DesktopAfter != nil || result.DesktopAfterRelease != nil || evidence.LogindRequest != nil || evidence.AfterLogindPAM != nil || evidence.AfterPAM != nil {
			return fail("Cinnamon prerequisite gate contains actions, observations or a native failure")
		}
		return labv1.MatrixVerdict_MATRIX_VERDICT_GATED, evidence.GateReason, nil
	}
	if !installedFixed || !candidateFixed || evidence.InstalledVersion != evidence.CandidateVersion || !result.Passed || result.Failure != "" || !evidence.NativeLocker {
		return fail("Cinnamon lock confirmation lacks a successful fixed native locker run")
	}
	if result.Lock == nil || result.LockRelease == nil || result.Lock.ActionID == "" || result.LockRelease.ActionID == "" || result.Lock.ActionID == result.LockRelease.ActionID {
		return fail("Cinnamon lock record lacks distinct signed lock and release actions")
	}
	// The dispatch evidence type is private to vmlab; inspect its exported
	// fields directly without introducing another serialized result schema.
	lock, release := result.Lock, result.LockRelease
	if !validDigest(lock.IntentSHA256) || !validDigest(release.IntentSHA256) || lock.RootState != "DEVICE_ACTION_STATE_SUCCEEDED" || lock.ServerState != "DEVICE_ACTION_STATE_SUCCEEDED" || release.RootState != "DEVICE_ACTION_STATE_SUCCEEDED" || release.ServerState != "DEVICE_ACTION_STATE_SUCCEEDED" || lock.Failure != "DEVICE_ACTION_FAILURE_NONE" || release.Failure != "DEVICE_ACTION_FAILURE_NONE" || lock.StartedAt.IsZero() || release.StartedAt.IsZero() || lock.ObservedAt.Before(lock.StartedAt) || release.ObservedAt.Before(release.StartedAt) || release.StartedAt.Before(lock.ObservedAt) || lock.StartedAt.Before(result.StartedAt) || result.FinishedAt.Before(release.ObservedAt) {
		return fail("Cinnamon lock record lacks successful signed action evidence")
	}
	before := result.DesktopBefore
	if before == nil || before.SessionID == "" || before.Type != "x11" || before.Class != "user" || before.User != "lindm-desktop-test" || before.Service != "lightdm-autologin" || before.Locker != "cinnamon org.cinnamon.ScreenSaver.GetActive" || before.LockedHint || before.ScreenSaverActive {
		return fail("Cinnamon lock record lacks the initial unlocked native session")
	}
	// All six independent observations must refer to the same real session.
	for i := range 5 {
		observed := result.DesktopAfter
		locked := true
		switch i {
		case 0:
			observed = evidence.LogindRequest
		case 1:
			observed, locked = evidence.AfterLogindPAM, false
		case 3:
			observed = result.DesktopAfterRelease
		case 4:
			observed, locked = evidence.AfterPAM, false
		}
		if observed == nil || observed.SessionID != before.SessionID || observed.Type != before.Type || observed.Class != before.Class || observed.User != before.User || observed.Service != before.Service || observed.Desktop != before.Desktop || observed.Locker != before.Locker || observed.LockedHint != locked || observed.ScreenSaverActive != locked {
			return fail("Cinnamon lock record lacks complete native, logind and normal PAM observations")
		}
	}
	return labv1.MatrixVerdict_MATRIX_VERDICT_PASS, "", nil
}

func cinnamonLockRunOutcome(path string, c *labmatrix.Cell, laneErr error) (labv1.MatrixVerdict, string, string, error) {
	if c.Spec.GetLane() != "device-actions" || !c.Spec.GetCinnamonLockConfirmation() || labhost.FlagValue(c.Spec.GetArgs(), "scenario") != "wipe" || labhost.FlagValue(c.Spec.GetArgs(), "wipe-phase") != "cinnamon-lock-confirmation" {
		return labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, "", "", errors.New("invalid Cinnamon lock-confirmation cell phase")
	}
	if _, ok := c.Release.Lab.Session.Desktops["cinnamon"]; !ok {
		return labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, "", "", errors.New("native Cinnamon lock evidence cannot qualify another desktop")
	}
	result, sum, err := readCinnamonLockRecord(path)
	if err != nil {
		return labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, "", "", err
	}
	verdict, gate, err := validateCinnamonLockRecord(result, c.Manifest.Image.GetId())
	if err != nil {
		return labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, "", sum, err
	}
	if (verdict == labv1.MatrixVerdict_MATRIX_VERDICT_PASS && laneErr != nil) || (verdict == labv1.MatrixVerdict_MATRIX_VERDICT_GATED && !cinnamonLockGateExit(laneErr)) {
		return labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, "", sum, errors.New("native Cinnamon lock process did not finish with its matching native outcome")
	}
	return verdict, gate, sum, nil
}

func cinnamonLockImportEvidence(path string, release *platform.Release, entry *labv1.MatrixLedgerEntry, imageID string) (string, string, error) {
	if _, ok := release.Lab.Session.Desktops["cinnamon"]; !ok || entry.GetScope() != labmatrix.CinnamonLockConfirmationScope {
		return "", "", errors.New("native Cinnamon lock import requires its Cinnamon desktop and exact version-qualified native-lock-only scope")
	}
	result, sum, err := readCinnamonLockRecord(path)
	if err != nil {
		return "", "", err
	}
	verdict, gate, err := validateCinnamonLockRecord(result, imageID)
	if err != nil {
		return "", "", err
	}
	if verdict != entry.GetVerdict() {
		return "", "", errors.New("native Cinnamon lock import verdict differs from the native evidence")
	}
	return sum, gate, nil
}
