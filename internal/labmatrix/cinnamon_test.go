// SPDX-License-Identifier: Apache-2.0

package labmatrix

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

func cinnamonSpec() *labv1.MatrixCell {
	return &labv1.MatrixCell{Name: "cinnamon-lock-confirmation", Title: "Cinnamon lock confirmation only", Capabilities: []string{"lock"}, Image: labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER, Lane: "device-actions", Args: []string{"-scenario=wipe", "-wipe-phase=cinnamon-lock-confirmation"}, CinnamonLockConfirmation: true}
}

func cinnamonInputs(r *platform.Release) *Inputs {
	return &Inputs{Manifests: []*Manifest{
		{Image: &labv1.ImageManifest{Id: "encrypted", Edition: "encrypted-lab"}, Release: r, Architecture: "x86_64"},
		{Image: &labv1.ImageManifest{Id: "ordinary"}, Release: r, Architecture: "x86_64"},
	}, Ledger: new(labv1.MatrixLedger)}
}

func TestCinnamonConfirmationApplicabilityUsesDesktopNotReleaseKey(t *testing.T) {
	for _, tc := range []struct {
		key        string
		applicable bool
	}{
		{"linuxmint-22.3", true},
		{"ubuntu-24.04", false},
		{"pop-24.04", false},
	} {
		r := *release(t, tc.key)
		// The package/backport cell must remain available for a future row.
		r.Key = "future-" + r.Key
		in := cinnamonInputs(&r)
		c := in.cell(&r, cinnamonSpec(), "x86_64")
		if tc.applicable {
			if c.State != NotRun || !c.Runnable() {
				t.Fatalf("Cinnamon desktop was statically gated: %s %s", c.State, c.Reason)
			}
		} else if c.State != Gated || c.Runnable() || !strings.Contains(c.Reason, "no maintained Cinnamon desktop") {
			t.Fatalf("other desktop became runnable: %s %s", c.State, c.Reason)
		}
	}
}

func TestCinnamonRuntimeGateRemainsRetryableAndNeverPasses(t *testing.T) {
	r := release(t, "linuxmint-22.3")
	in := cinnamonInputs(r)
	spec := cinnamonSpec()
	at := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	gate := entry(r.Key, spec.GetName(), "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_GATED, at)
	gate.Verified, gate.Scope, gate.GateReason = true, CinnamonLockConfirmationScope, "installed 6.6.4 and vendor candidate 6.6.4 are below 6.7.9"
	in.Ledger.Entries = []*labv1.MatrixLedgerEntry{gate}
	path := filepath.Join(t.TempDir(), "ledger.json")
	if err := Append(path, gate); err != nil {
		t.Fatal(err)
	}
	var err error
	if in.Ledger, err = LoadLedger(path); err != nil {
		t.Fatal(err)
	}
	c := in.cell(r, spec, "x86_64")
	if c.State != Gated || !c.Runnable() || c.Reason != gate.GateReason || supportPassed(c) {
		t.Fatalf("runtime gate became a static refusal or pass: %+v", c)
	}
	// The static non-Cinnamon gate wins even over a forged runtime ledger row.
	other := release(t, "ubuntu-24.04")
	in = cinnamonInputs(other)
	forged := proto.CloneOf(gate)
	forged.Platform = other.Key
	in.Ledger.Entries = []*labv1.MatrixLedgerEntry{forged}
	if c := in.cell(other, spec, "x86_64"); c.State != Gated || c.Runnable() {
		t.Fatal("runtime evidence bypassed a static desktop applicability gate")
	}
	in = cinnamonInputs(r)
	pass := proto.CloneOf(gate)
	pass.Verdict, pass.GateReason, pass.Recorded = labv1.MatrixVerdict_MATRIX_VERDICT_PASS, "", gate.Recorded
	in.Ledger.Entries = []*labv1.MatrixLedgerEntry{gate, pass}
	if c := in.cell(r, spec, "x86_64"); c.State != Pass || !c.Runnable() {
		t.Fatal("a later verified fixed-package result could not replace the retryable gate")
	}
}

func TestCinnamonScopedLedgerCannotQualifyFullDeviceActionLane(t *testing.T) {
	r := release(t, "linuxmint-22.3")
	in := cinnamonInputs(r)
	pass := entry(r.Key, "device-actions", "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, time.Now())
	pass.Verified, pass.Scope = true, CinnamonLockConfirmationScope
	in.Ledger.Entries = []*labv1.MatrixLedgerEntry{pass}
	full := &labv1.MatrixCell{Name: "device-actions", Lane: "device-actions", Image: labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER}
	if c := in.cell(r, full, "x86_64"); c.State != NotRun || c.Entry != nil {
		t.Fatal("native-lock-only scope inflated the complete device-action lane")
	}
	pass.Cell = cinnamonSpec().GetName()
	for _, verified := range []bool{false, true} {
		pass.Verified, pass.Scope = verified, "arbitrary scope"
		if c := in.cell(r, cinnamonSpec(), "x86_64"); c.State == Pass {
			t.Fatal("arbitrary scope counted as version-qualified native confirmation")
		}
	}
}

func TestCinnamonMatrixSchemaRequiresPhaseAndRuntimeReason(t *testing.T) {
	spec := cinnamonSpec()
	if err := protovalidate.Validate(spec); err != nil {
		t.Fatal(err)
	}
	spec.Args = []string{"-scenario=wipe", "-wipe-phase=live-actions"}
	if err := protovalidate.Validate(spec); err == nil {
		t.Fatal("Cinnamon confirmation was allowed to exercise another phase")
	}
	gate := entry("linuxmint-22.3", "cinnamon-lock-confirmation", "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_GATED, time.Now())
	if err := protovalidate.Validate(gate); err == nil {
		t.Fatal("runtime gate without a reason was accepted")
	}
	gate.GateReason = "package prerequisite absent"
	if err := protovalidate.Validate(gate); err != nil {
		t.Fatal(err)
	}
	gate.Verdict = labv1.MatrixVerdict_MATRIX_VERDICT_PASS
	if err := protovalidate.Validate(gate); err == nil {
		t.Fatal("gate reason accompanied a pass")
	}
}
