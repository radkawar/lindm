package demolab

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
)

func TestAdmitQualifiedDevices(t *testing.T) {
	spec := demoFixture(t)
	if err := Admit(spec, qualifiedFixture(spec)); err != nil {
		t.Fatal(err)
	}
}

func TestAdmitMaintainedOrganizationDemo(t *testing.T) {
	ledger, err := labmatrix.LoadLedger("../../lab/ledger.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../../lab/demo/org-demo.json", "../../lab/demo/org-desktops-demo.json"} {
		spec, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := Admit(spec, ledger); err != nil {
			t.Fatalf("maintained demo %s is not qualified: %v", path, err)
		}
	}
}

func TestAdmitFullWaylandAssistanceScopes(t *testing.T) {
	for _, scope := range []string{
		"GNOME Wayland assistance; all five scenarios; colocated dgx20; Secure Boot on",
		"GNOME Wayland assistance; all five scenarios; split controller/dgx20; Secure Boot on",
	} {
		t.Run(scope, func(t *testing.T) {
			device := demoFixture(t).Devices[0]
			if !applicableScope(device, scope, "assistance", false) {
				t.Fatal("verified full assistance scope refused")
			}
			device.Config.Firmware.SecureBoot = proto.Bool(false)
			if applicableScope(device, scope, "assistance", false) {
				t.Fatal("Secure Boot qualification conditions ignored")
			}
		})
	}
}

func TestAdmitRefusesUnqualifiedCell(t *testing.T) {
	spec := demoFixture(t)
	ledger := qualifiedFixture(spec)
	ledger.Entries = ledger.Entries[1:]
	err := Admit(spec, ledger)
	want := spec.Devices[0].Release.Key + "/" + spec.Devices[0].Architecture + "/encrypted"
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "not run") {
		t.Fatalf("Admit error = %v, want missing cell %s", err, want)
	}
}

func TestAdmitRejectsInsufficientEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*labv1.MatrixLedgerEntry)
		want   string
	}{
		{"other architecture", func(e *labv1.MatrixLedgerEntry) { e.Architecture = "x86_64" }, "not run"},
		{"other release", func(e *labv1.MatrixLedgerEntry) { e.Platform = "ubuntu-22.04" }, "not run"},
		{"failure", func(e *labv1.MatrixLedgerEntry) { e.Verdict = labv1.MatrixVerdict_MATRIX_VERDICT_FAIL }, "fail"},
		{"unverified", func(e *labv1.MatrixLedgerEntry) { e.Verified = false }, "not verified"},
		{"TPM-only", func(e *labv1.MatrixLedgerEntry) { e.Scope = "TPM scenario" }, "encrypted: not run"},
		{"non-TPM scenarios", func(e *labv1.MatrixLedgerEntry) { e.Scope = "scenarios 1-4" }, "TPM bind: not run"},
		{"golden only", func(e *labv1.MatrixLedgerEntry) { e.Scope = "golden TPM2 prompted unlock" }, "not run"},
		{"security mismatch", func(e *labv1.MatrixLedgerEntry) { e.Scope = "Secure Boot off" }, "not run"},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := demoFixture(t)
			ledger := qualifiedFixture(spec)
			test.change(ledger.Entries[0])
			if err := Admit(spec, ledger); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Admit error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAdmitLatestApplicableOutcomeWins(t *testing.T) {
	spec := demoFixture(t)
	ledger := qualifiedFixture(spec)
	failure := proto.CloneOf(ledger.Entries[0])
	failure.Recorded = timestamppb.New(time.Unix(200, 0))
	failure.Verdict = labv1.MatrixVerdict_MATRIX_VERDICT_FAIL
	// Slice order cannot hide a newer failed qualification behind an old pass.
	ledger.Entries = append([]*labv1.MatrixLedgerEntry{failure}, ledger.Entries...)
	if err := Admit(spec, ledger); err == nil || !strings.Contains(err.Error(), "fail") {
		t.Fatalf("Admit error = %v, want latest failure", err)
	}
	failure.Recorded = timestamppb.New(time.Unix(50, 0))
	if err := Admit(spec, ledger); err != nil {
		t.Fatalf("historical failure overrode newer pass: %v", err)
	}
}

func TestAdmitRegistryGateOverridesLedger(t *testing.T) {
	spec := demoFixture(t)
	ledger := qualifiedFixture(spec)
	release := *spec.Devices[0].Release
	release.Supports = slices.DeleteFunc(slices.Clone(release.Supports), func(c platform.Capability) bool { return c == platform.Assistance })
	spec.Devices[0].Release = &release
	if err := Admit(spec, ledger); err == nil || !strings.Contains(err.Error(), "assistance: gated") {
		t.Fatalf("Admit error = %v, want registry gate", err)
	}
}

func TestAdmitTPMArchitectureGate(t *testing.T) {
	spec := demoFixture(t)
	ledger := qualifiedFixture(spec)
	release := *spec.Devices[0].Release
	release.Lab.TPM.Unobservable = []string{spec.Devices[0].Architecture}
	spec.Devices[0].Release = &release
	if err := Admit(spec, ledger); err == nil || !strings.Contains(err.Error(), "registry gates TPM2 binding") {
		t.Fatalf("Admit error = %v, want TPM architecture gate", err)
	}
}

func TestAdmitScopedCapabilities(t *testing.T) {
	spec := demoFixture(t)
	ledger := qualifiedFixture(spec)
	ledger.Entries[0].Scope = "scenarios 1-4"
	tpm := proto.CloneOf(ledger.Entries[0])
	tpm.Scope = "TPM scenario"
	ledger.Entries = append(ledger.Entries, tpm)
	for _, entry := range ledger.GetEntries() {
		if entry.GetPlatform() == spec.Devices[1].Release.Key {
			entry.Scope = "Secure Boot off"
			if entry.GetCell() == "assistance" {
				entry.Scope = "GNOME, Secure Boot off"
			}
		}
	}
	if err := Admit(spec, ledger); err != nil {
		t.Fatal(err)
	}
}

func TestAdmitRejectsMissingInputs(t *testing.T) {
	if err := Admit(nil, new(labv1.MatrixLedger)); err == nil {
		t.Fatal("nil spec admitted")
	}
	if err := Admit(demoFixture(t), nil); err == nil {
		t.Fatal("nil ledger admitted")
	}
}

func TestAdmitOnlyRequestedCapabilities(t *testing.T) {
	spec := demoFixture(t)
	spec.Devices = spec.Devices[:1]
	spec.Devices[0].Config.Assistance = false
	spec.Devices[0].Config.TpmBind = false
	ledger := qualifiedFixture(spec)
	ledger.Entries[0].Scope = "scenarios 1-4"
	if err := Admit(spec, ledger); err != nil {
		t.Fatalf("unrequested assistance or TPM blocked installation: %v", err)
	}
}

func TestAdmitRejectsUnencryptedManifest(t *testing.T) {
	spec := demoFixture(t)
	ledger := qualifiedFixture(spec)
	spec.Devices[0].Manifest.Edition = "cloud"
	if err := Admit(spec, ledger); err == nil || !strings.Contains(err.Error(), "manifest is not an encrypted installer") {
		t.Fatalf("Admit error = %v, want encrypted installer refusal", err)
	}
}

func TestAdmitSecureBootEnforcedFullEncryptionScope(t *testing.T) {
	spec := demoFixture(t)
	ledger := qualifiedFixture(spec)
	ledger.Entries[0].Scope = "full encryption; product TPM bind; unattended cold boot; Secure Boot enforced"
	if err := Admit(spec, ledger); err != nil {
		t.Fatalf("full encrypted install and TPM binding not admitted with enforced Secure Boot: %v", err)
	}
	spec.Devices[0].Config.Firmware.SecureBoot = proto.Bool(false)
	err := Admit(spec, ledger)
	if err == nil || !strings.Contains(err.Error(), "/encrypted: not run") || !strings.Contains(err.Error(), "/encrypted/TPM bind: not run") {
		t.Fatalf("Admit error = %v, want install and TPM refusal for mismatched Secure Boot", err)
	}
}
