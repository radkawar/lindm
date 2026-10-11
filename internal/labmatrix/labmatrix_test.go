package labmatrix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

func release(t *testing.T, key string) *platform.Release {
	t.Helper()
	r, ok := platform.Lookup(key)
	if !ok {
		t.Fatalf("registry has no %s", key)
	}
	return r
}

func entry(key, cell, arch string, verdict labv1.MatrixVerdict, at time.Time) *labv1.MatrixLedgerEntry {
	return &labv1.MatrixLedgerEntry{Platform: key, Cell: cell, Architecture: arch, Verdict: verdict, Evidence: "/e", Sha256: strings.Repeat("a", 64), Recorded: timestamppb.New(at), Revision: "r", Source: labv1.MatrixSource_MATRIX_SOURCE_IMPORT}
}

// A gated, laneless, imageless or unrecorded cell is never a pass, and the
// latest ledger entry decides a recorded cell.
func TestPlanStates(t *testing.T) {
	ubuntu, omarchy := release(t, "ubuntu-24.04"), release(t, "omarchy-4.0.4")
	cloud := labv1.MatrixImage_MATRIX_IMAGE_CLOUD
	lifecycle := &labv1.MatrixCell{Name: "lifecycle", Title: "Lifecycle", Capabilities: []string{"lifecycle"}, Image: cloud, Lane: "lifecycle"}
	upgrade := &labv1.MatrixCell{Name: "release-upgrade", Title: "Upgrade", Capabilities: []string{"release-upgrade"}, Image: cloud, NoLane: "none"}
	advisories := &labv1.MatrixCell{Name: "advisories", Title: "Advisories", Capabilities: []string{"advisories"}, Image: cloud, NoLane: "server-side"}
	base := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	in := &Inputs{
		Manifests: []*Manifest{{Path: "lab/images/x.json", Image: &labv1.ImageManifest{Id: "x", Edition: "server-cloudimg"}, Release: ubuntu, Architecture: "x86_64"}},
		Ledger: &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{
			entry("ubuntu-24.04", "lifecycle", "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, base.Add(time.Hour)),
			entry("ubuntu-24.04", "lifecycle", "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, base),
		}},
	}
	got := map[string]State{}
	for _, c := range in.Plan([]*platform.Release{ubuntu, omarchy}, []*labv1.MatrixCell{lifecycle, upgrade, advisories}) {
		got[c.Release.Key+" "+c.Spec.GetName()+" "+c.Architecture] = c.State
	}
	for key, want := range map[string]State{
		"ubuntu-24.04 lifecycle x86_64":        Pass,
		"ubuntu-24.04 lifecycle aarch64":       NoImage,
		"ubuntu-24.04 release-upgrade x86_64":  NoLane,
		"ubuntu-24.04 advisories x86_64":       NoLane,
		"omarchy-4.0.4 advisories x86_64":      Gated,
		"omarchy-4.0.4 lifecycle x86_64":       NoImage,
		"ubuntu-24.04 release-upgrade aarch64": NoLane,
		"omarchy-4.0.4 release-upgrade x86_64": Gated,
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	in.Ledger.Entries = append(in.Ledger.Entries, entry("ubuntu-24.04", "lifecycle", "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_FAIL, base.Add(2*time.Hour)))
	cells := in.Plan([]*platform.Release{ubuntu}, []*labv1.MatrixCell{lifecycle})
	if cells[0].State != Fail {
		t.Fatalf("latest failing entry gives %q, want fail", cells[0].State)
	}
	table, err := Render([]*labv1.MatrixCell{lifecycle}, cells)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table, "| x86_64 fail; aarch64 no image |") {
		t.Fatalf("table does not separate disagreeing architectures:\n%s", table)
	}
}

// A lane the registry restricts to other architectures is "no lane" there, even
// with a pinned image, so the matrix never offers an unqualified run.
func TestPlanHonoursLaneArchitectures(t *testing.T) {
	debian := release(t, "debian-12")
	cloud := labv1.MatrixImage_MATRIX_IMAGE_CLOUD
	updates := &labv1.MatrixCell{Name: "self-update", Title: "Self-update", Capabilities: []string{"self-update"}, Image: cloud, Lane: "updates"}
	in := &Inputs{
		Manifests: []*Manifest{
			{Path: "lab/images/a.json", Image: &labv1.ImageManifest{Id: "a", Edition: "server-cloudimg"}, Release: debian, Architecture: "x86_64"},
			{Path: "lab/images/b.json", Image: &labv1.ImageManifest{Id: "b", Edition: "server-cloudimg"}, Release: debian, Architecture: "aarch64"},
		},
		Ledger: &labv1.MatrixLedger{},
	}
	got := map[string]State{}
	for _, c := range in.Plan([]*platform.Release{debian}, []*labv1.MatrixCell{updates}) {
		got[c.Architecture] = c.State
	}
	if got["x86_64"] != NoLane || got["aarch64"] != NotRun {
		t.Fatalf("debian-12 self-update states = %v, want x86_64 no lane, aarch64 not run", got)
	}
}

// Appends accumulate and the ledger stays strict protobuf JSON.
func TestAppendKeepsEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	for _, verdict := range []labv1.MatrixVerdict{labv1.MatrixVerdict_MATRIX_VERDICT_PASS, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL} {
		if err := Append(path, entry("arch", "inventory", "x86_64", verdict, at)); err != nil {
			t.Fatal(err)
		}
	}
	ledger, err := LoadLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.GetEntries()) != 2 {
		t.Fatalf("ledger has %d entries, want 2", len(ledger.GetEntries()))
	}
	if err := Append(path, entry("arch", "inventory", "riscv64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, at)); err == nil {
		t.Fatal("invalid entry was appended")
	}
	if names, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".ledger-*")); err != nil || len(names) != 0 {
		t.Fatalf("temporary ledger files left behind: %v %v", names, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
