// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
	"lindm/internal/vmlab"
)

// Controlled records test accounting, not native Cinnamon qualification. Only
// the disposable native lane can produce qualification evidence for the ledger.
func cinnamonRecordFixture(t *testing.T, gated bool) *vmlab.VMDeviceActionsResult {
	t.Helper()
	digest := strings.Repeat("a", 64)
	record := map[string]any{
		"scenario": "wipe", "wipe_phase": "cinnamon-lock-confirmation", "desktop_profile": "cinnamon",
		"image_id": "mint-encrypted", "image_sha256": digest, "package_sha256": digest,
		"lab_sha256": digest, "lindmd_sha256": digest,
		"started_at": "2026-10-15T01:00:00Z", "finished_at": "2026-10-15T01:01:00Z", "passed": !gated,
	}
	evidence := map[string]any{"minimum_version": platform.CinnamonLockMinimumVersion}
	record["cinnamon_lock"] = evidence
	if gated {
		evidence["installed_version"], evidence["candidate_version"] = "6.6.4+zena", "6.6.4+zena"
		evidence["gate_reason"] = "no fixed vendor Cinnamon package is available"
		record["failure"] = evidence["gate_reason"]
	} else {
		evidence["installed_version"], evidence["candidate_version"], evidence["native_locker"] = "6.7.9-1", "6.7.9-1", true
		observation := func(locked bool) map[string]any {
			return map[string]any{"session_id": "c2", "type": "x11", "class": "user", "user": "lindm-desktop-test", "service": "lightdm-autologin", "desktop": "X-Cinnamon", "locker": "cinnamon org.cinnamon.ScreenSaver.GetActive", "locked_hint": locked, "screen_saver_active": locked}
		}
		record["desktop_before"], record["desktop_after"], record["desktop_after_release"] = observation(false), observation(true), observation(true)
		evidence["logind_request"], evidence["after_logind_pam"], evidence["after_pam"] = observation(true), observation(false), observation(false)
		action := func(id, start, observed string) map[string]any {
			return map[string]any{"action_id": id, "intent_sha256": digest, "server_state": "DEVICE_ACTION_STATE_SUCCEEDED", "root_state": "DEVICE_ACTION_STATE_SUCCEEDED", "failure": "DEVICE_ACTION_FAILURE_NONE", "started_at": start, "observed_at": observed}
		}
		record["lock"] = action("lock-id", "2026-10-15T01:00:10Z", "2026-10-15T01:00:20Z")
		record["lock_release"] = action("release-id", "2026-10-15T01:00:30Z", "2026-10-15T01:00:40Z")
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	result := new(vmlab.VMDeviceActionsResult)
	if err := json.Unmarshal(data, result); err != nil {
		t.Fatal(err)
	}
	return result
}

func writeCinnamonRecord(t *testing.T, result *vmlab.VMDeviceActionsResult) string {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cinnamonMatrixCell(t *testing.T) *labmatrix.Cell {
	t.Helper()
	release, ok := platform.Lookup("linuxmint-22.3")
	if !ok {
		t.Fatal("Mint is missing from the registry")
	}
	return &labmatrix.Cell{Release: release, Architecture: "x86_64", Spec: &labv1.MatrixCell{Name: "cinnamon-lock-confirmation", Title: "Cinnamon lock confirmation only", Capabilities: []string{"lock"}, Image: labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER, Lane: "device-actions", Args: []string{"-scenario=wipe", "-wipe-phase=cinnamon-lock-confirmation"}, CinnamonLockConfirmation: true}, Manifest: &labmatrix.Manifest{Image: &labv1.ImageManifest{Id: "mint-encrypted"}}}
}

func cinnamonProcessExit(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	if code != 0 && err == nil {
		t.Fatal("test process did not return its requested status")
	}
	return err
}

func TestCinnamonVersionFloorUsesUpstreamDpkgOrdering(t *testing.T) {
	for _, tc := range []struct {
		version string
		fixed   bool
	}{
		{"6.6.4+zena", false}, {"99:6.6.4-1", false}, {"6.7.8-9", false},
		{"6.7.9~rc1-1", false}, {"6.7.9", true}, {"1:6.7.9-1", true},
		{"6.7.9+mint1", true}, {"6.8.0-1", true},
	} {
		if fixed, err := cinnamonLockVersionFixed(tc.version); err != nil || fixed != tc.fixed {
			t.Fatalf("%s fixed=%t, want %t: %v", tc.version, fixed, tc.fixed, err)
		}
	}
	for _, version := range []string{"", "(none)", "not-a-version", "bad:6.8.0"} {
		if _, err := cinnamonLockVersionFixed(version); err == nil {
			t.Fatalf("invalid package version %q was accepted", version)
		}
	}
}

func TestCinnamonNativeRecordRequiresCompleteIndependentProof(t *testing.T) {
	result := cinnamonRecordFixture(t, false)
	if verdict, gate, err := validateCinnamonLockRecord(result, "mint-encrypted"); err != nil || verdict != labv1.MatrixVerdict_MATRIX_VERDICT_PASS || gate != "" {
		t.Fatalf("complete fixed-version proof rejected: %v %q %v", verdict, gate, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*vmlab.VMDeviceActionsResult)
	}{
		{"missing evidence", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock = nil }},
		{"wrong phase", func(r *vmlab.VMDeviceActionsResult) { r.WipePhase = "live-actions" }},
		{"wrong scenario", func(r *vmlab.VMDeviceActionsResult) { r.Scenario = "all" }},
		{"wrong profile", func(r *vmlab.VMDeviceActionsResult) { r.DesktopProfile = "gnome" }},
		{"wrong image", func(r *vmlab.VMDeviceActionsResult) { r.ImageID = "another-image" }},
		{"changed minimum", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.MinimumVersion = "6.6.0" }},
		{"old installed", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.InstalledVersion = "99:6.6.4-1" }},
		{"release candidate", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.InstalledVersion = "6.7.9~rc1-1" }},
		{"malformed installed", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.InstalledVersion = "unknown" }},
		{"malformed candidate", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.CandidateVersion = "(none)" }},
		{"missing candidate", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.CandidateVersion = "" }},
		{"old candidate", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.CandidateVersion = "6.6.9+zena" }},
		{"different candidate", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.CandidateVersion = "6.7.10-1" }},
		{"native failure", func(r *vmlab.VMDeviceActionsResult) { r.Passed = false; r.Failure = "cleanup failed" }},
		{"forged Passed", func(r *vmlab.VMDeviceActionsResult) { r.Failure = "cleanup failed" }},
		{"external locker", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.NativeLocker = false }},
		{"missing logind request", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.LogindRequest = nil }},
		{"unconfirmed logind request", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.LogindRequest.LockedHint = false }},
		{"missing logind PAM", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.AfterLogindPAM = nil }},
		{"missing final PAM", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.AfterPAM = nil }},
		{"PAM left locker active", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.AfterPAM.ScreenSaverActive = true }},
		{"wrong session", func(r *vmlab.VMDeviceActionsResult) { r.DesktopAfter.SessionID = "other" }},
		{"wrong native oracle", func(r *vmlab.VMDeviceActionsResult) { r.DesktopBefore.Locker = "standalone screensaver" }},
		{"lock lacks hint", func(r *vmlab.VMDeviceActionsResult) { r.DesktopAfter.LockedHint = false }},
		{"release unlocked", func(r *vmlab.VMDeviceActionsResult) { r.DesktopAfterRelease.ScreenSaverActive = false }},
		{"missing signed action", func(r *vmlab.VMDeviceActionsResult) { r.Lock = nil }},
		{"unknown lock", func(r *vmlab.VMDeviceActionsResult) { r.Lock.RootState = "DEVICE_ACTION_STATE_OUTCOME_UNKNOWN" }},
		{"missing signed digest", func(r *vmlab.VMDeviceActionsResult) { r.Lock.IntentSHA256 = "" }},
		{"unknown action failure", func(r *vmlab.VMDeviceActionsResult) { r.Lock.Failure = "DEVICE_ACTION_FAILURE_UNSPECIFIED" }},
		{"same action", func(r *vmlab.VMDeviceActionsResult) { r.LockRelease.ActionID = r.Lock.ActionID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := cinnamonRecordFixture(t, false)
			tc.mutate(result)
			if verdict, gate, err := validateCinnamonLockRecord(result, "mint-encrypted"); err == nil || verdict != labv1.MatrixVerdict_MATRIX_VERDICT_FAIL || gate != "" {
				t.Fatalf("incomplete or forged native result became %v %q: %v", verdict, gate, err)
			}
		})
	}
}

func TestCinnamonOldPackageGateRequiresNormalNoActionResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*vmlab.VMDeviceActionsResult)
	}{
		{"passed true", func(r *vmlab.VMDeviceActionsResult) { r.Passed = true }},
		{"cleanup failed", func(r *vmlab.VMDeviceActionsResult) { r.Failure += "\ncleanup failed" }},
		{"missing candidate", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.CandidateVersion = "" }},
		{"malformed version", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.InstalledVersion = "?" }},
		{"fixed candidate", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.CandidateVersion = "6.7.9-1" }},
		{"fixed installed", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.InstalledVersion = "6.8.0" }},
		{"locker started", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.NativeLocker = true }},
		{"desktop prepared", func(r *vmlab.VMDeviceActionsResult) { r.DesktopBefore = cinnamonRecordFixture(t, false).DesktopBefore }},
		{"action dispatched", func(r *vmlab.VMDeviceActionsResult) { r.Lock = cinnamonRecordFixture(t, false).Lock }},
		{"host observation IO failed", func(r *vmlab.VMDeviceActionsResult) { r.HostObservationError = "read host resources failed" }},
		{"missing package identity", func(r *vmlab.VMDeviceActionsResult) { r.PackageSHA256 = "" }},
		{"other signed action", func(r *vmlab.VMDeviceActionsResult) { r.Escrow = cinnamonRecordFixture(t, false).Lock }},
		{"missing gate reason", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.GateReason = "" }},
		{"APT refresh failed", func(r *vmlab.VMDeviceActionsResult) { r.CinnamonLock.GateReason = ""; r.Failure = "APT refresh failed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := cinnamonRecordFixture(t, true)
			tc.mutate(result)
			if verdict, gate, err := validateCinnamonLockRecord(result, "mint-encrypted"); err == nil || verdict != labv1.MatrixVerdict_MATRIX_VERDICT_FAIL || gate != "" {
				t.Fatalf("unsafe runtime gate accepted: %v %q %v", verdict, gate, err)
			}
		})
	}
}

func TestCinnamonRunOutcomePreservesProcessAndEvidenceFailures(t *testing.T) {
	gateExit, failedExit := cinnamonProcessExit(t, cinnamonLockGateExitCode), cinnamonProcessExit(t, 1)
	for _, tc := range []struct {
		name    string
		gated   bool
		process error
		want    labv1.MatrixVerdict
	}{
		{"native pass", false, nil, labv1.MatrixVerdict_MATRIX_VERDICT_PASS},
		{"native pass with IO failure", false, failedExit, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL},
		{"old package retryable gate", true, gateExit, labv1.MatrixVerdict_MATRIX_VERDICT_GATED},
		{"gate with post-record IO failure", true, failedExit, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL},
		{"gate with nil process error", true, nil, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCinnamonRecord(t, cinnamonRecordFixture(t, tc.gated))
			verdict, gate, sum, err := cinnamonLockRunOutcome(path, cinnamonMatrixCell(t), tc.process)
			if verdict != tc.want || len(sum) != 64 || (tc.want == labv1.MatrixVerdict_MATRIX_VERDICT_FAIL) != (err != nil) || (gate != "") != (tc.want == labv1.MatrixVerdict_MATRIX_VERDICT_GATED) {
				t.Fatalf("outcome %v %q %q %v", verdict, gate, sum, err)
			}
		})
	}
	for _, data := range []string{"", "{", "{}", `{"passed":true}`, `{} {}`} {
		path := filepath.Join(t.TempDir(), "record.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if verdict, gate, _, err := cinnamonLockRunOutcome(path, cinnamonMatrixCell(t), nil); err == nil || verdict != labv1.MatrixVerdict_MATRIX_VERDICT_FAIL || gate != "" {
			t.Fatal("malformed or missing native result counted as a pass or gate")
		}
	}
	if verdict, _, _, err := cinnamonLockRunOutcome(filepath.Join(t.TempDir(), "missing.json"), cinnamonMatrixCell(t), nil); err == nil || verdict != labv1.MatrixVerdict_MATRIX_VERDICT_FAIL {
		t.Fatal("missing result counted as a pass")
	}
	wrongPhase := cinnamonMatrixCell(t)
	wrongPhase.Spec.Args = []string{"-scenario=wipe", "-wipe-phase=live-actions"}
	if verdict, _, _, err := cinnamonLockRunOutcome(writeCinnamonRecord(t, cinnamonRecordFixture(t, false)), wrongPhase, nil); err == nil || verdict != labv1.MatrixVerdict_MATRIX_VERDICT_FAIL {
		t.Fatal("Cinnamon evidence was accepted for another configured phase")
	}
}

func TestCinnamonGateExitCannotHideJoinedCleanupOrIO(t *testing.T) {
	exit := cinnamonProcessExit(t, cinnamonLockGateExitCode)
	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0}, {exit, cinnamonLockGateExitCode}, {fmt.Errorf("remote command: %w", errors.Join(exit)), cinnamonLockGateExitCode},
		{errors.Join(exit, errors.New("collect record failed")), 1},
		{errors.Join(exit, errors.New("stdout failed")), 1},
		{errors.Join(exit, errors.New("release lease failed")), 1},
	} {
		if got := labExitCode(tc.err); got != tc.want {
			t.Fatalf("exit code %d, want %d for %v", got, tc.want, tc.err)
		}
	}
}

func TestCinnamonImportCannotInflateWholeFeatures(t *testing.T) {
	c := cinnamonMatrixCell(t)
	path := writeCinnamonRecord(t, cinnamonRecordFixture(t, false))
	entry := &labv1.MatrixLedgerEntry{Verdict: labv1.MatrixVerdict_MATRIX_VERDICT_PASS, Scope: labmatrix.CinnamonLockConfirmationScope}
	if sum, gate, err := cinnamonLockImportEvidence(path, c.Release, entry, c.Manifest.Image.GetId()); err != nil || len(sum) != 64 || gate != "" {
		t.Fatalf("scoped native evidence rejected: %q %q %v", sum, gate, err)
	}
	for _, cell := range []string{"device-actions", "encrypted", "assistance", "deploy", "lifecycle"} {
		for _, scope := range []string{"", "lock, wipe, quarantine", labmatrix.CinnamonLockConfirmationScope} {
			if _, err := matrixImportEvidenceSHA256(path, cell, scope); err == nil {
				t.Fatalf("native-lock-only proof imported as %s scope %q", cell, scope)
			}
		}
	}
	entry.Scope = ""
	if _, _, err := cinnamonLockImportEvidence(path, c.Release, entry, ""); err == nil {
		t.Fatal("unscoped Cinnamon import accepted")
	}
	entry.Scope = labmatrix.CinnamonLockConfirmationScope
	if _, _, err := cinnamonLockImportEvidence(path, c.Release, entry, "wrong-image"); err == nil {
		t.Fatal("wrong image accepted")
	}
	other, _ := platform.Lookup("ubuntu-24.04")
	if _, _, err := cinnamonLockImportEvidence(path, other, entry, ""); err == nil {
		t.Fatal("non-Cinnamon import accepted")
	}
	entry.Verdict = labv1.MatrixVerdict_MATRIX_VERDICT_GATED
	if _, _, err := cinnamonLockImportEvidence(path, c.Release, entry, ""); err == nil {
		t.Fatal("pass imported as gate")
	}
}

func TestCinnamonDeclarativeCellUsesItsDedicatedPhaseAndDesktop(t *testing.T) {
	selection := matrixSelection{root: "../..", platforms: "linuxmint-22.3", cells: "cinnamon-lock-confirmation", architecture: "x86_64"}
	_, cells, err := selection.plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || !cells[0].Spec.GetCinnamonLockConfirmation() || !cells[0].Runnable() {
		t.Fatal("Cinnamon cell is not declaratively runnable")
	}
	run := &matrixRun{root: "../.."}
	args, err := run.laneArgs(cells[0], "base")
	if err != nil {
		t.Fatal(err)
	}
	if labhost.FlagValue(args, "desktop") != "cinnamon" || labhost.FlagValue(args, "scenario") != "wipe" || labhost.FlagValue(args, "wipe-phase") != "cinnamon-lock-confirmation" {
		t.Fatalf("wrong Cinnamon native phase arguments: %v", args)
	}
}
