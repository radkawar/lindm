package labmatrix

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
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

func TestRollingManifestPrefersNewestSnapshotButHonorsOwnerChoice(t *testing.T) {
	r := release(t, "opensuse-tumbleweed")
	old := &Manifest{Image: &labv1.ImageManifest{Id: "old", RepositorySnapshotDate: proto.String("2026-10-07")}, Release: r, Architecture: "x86_64"}
	current := &Manifest{Image: &labv1.ImageManifest{Id: "current", RepositorySnapshotDate: proto.String("2026-10-09")}, Release: r, Architecture: "x86_64"}
	in := &Inputs{Manifests: []*Manifest{old, current}}
	if got := in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_CLOUD, "x86_64"); got != current {
		t.Fatal("historical path ordering hid the current rolling snapshot")
	}
	in.PreferredManifest = old.Image.GetId()
	if got := in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_CLOUD, "x86_64"); got != old {
		t.Fatal("newer snapshot silently replaced an explicit owner choice")
	}
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

// A Debian netinst ISO boots both the plain installed golden and the
// guided-LUKS encrypted golden, so encrypted cells are not "no image".
func TestDebianNetinstServesEncryptedCells(t *testing.T) {
	debian, ubuntu := release(t, "debian-13"), release(t, "ubuntu-24.04")
	encrypted := &labv1.MatrixCell{Name: "encrypted", Title: "Encryption", Capabilities: []string{"encryption"}, Image: labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER, Lane: "encrypted"}
	lifecycle := &labv1.MatrixCell{Name: "lifecycle", Title: "Lifecycle", Capabilities: []string{"lifecycle"}, Image: labv1.MatrixImage_MATRIX_IMAGE_CLOUD, Lane: "lifecycle"}
	in := &Inputs{
		Manifests: []*Manifest{
			{Path: "lab/images/debian.json", Image: &labv1.ImageManifest{Id: "d", Edition: "netinst"}, Release: debian, Architecture: "x86_64"},
			{Path: "lab/images/ubuntu.json", Image: &labv1.ImageManifest{Id: "u", Edition: "server-cloudimg"}, Release: ubuntu, Architecture: "x86_64"},
		},
		Ledger: &labv1.MatrixLedger{},
	}
	got := map[string]*Cell{}
	for _, c := range in.Plan([]*platform.Release{debian, ubuntu}, []*labv1.MatrixCell{encrypted, lifecycle}) {
		got[c.Release.Key+" "+c.Spec.GetName()+" "+c.Architecture] = c
	}
	if c := got["debian-13 encrypted x86_64"]; c.State != NotRun || c.Manifest == nil || c.Recovery == nil || c.Manifest != c.Recovery {
		t.Fatalf("debian netinst must drive the encrypted cell and its recovery image: %+v", c)
	}
	if got["debian-13 lifecycle x86_64"].State != NotRun {
		t.Fatal("debian netinst must still drive cloud cells")
	}
	if got["ubuntu-24.04 encrypted x86_64"].State != NoImage {
		t.Fatal("a cloud image must not serve an encrypted-installer cell")
	}
}

// A registry lane gate makes the cell gated with its reason on exactly the
// gated architecture, even though the lane and an image exist there.
func TestPlanHonoursLaneGates(t *testing.T) {
	debian := *release(t, "debian-12")
	debian.Lab.LaneGates = map[platform.LabLane]platform.LaneGate{platform.LaneUpdates: {Reason: "vendor cannot boot it", Architectures: []string{"aarch64"}}}
	cloud := labv1.MatrixImage_MATRIX_IMAGE_CLOUD
	updates := &labv1.MatrixCell{Name: "self-update", Title: "Self-update", Capabilities: []string{"self-update"}, Image: cloud, Lane: "updates"}
	in := &Inputs{
		Manifests: []*Manifest{{Path: "lab/images/b.json", Image: &labv1.ImageManifest{Id: "b", Edition: "server-cloudimg"}, Release: &debian, Architecture: "aarch64"}},
		Ledger:    &labv1.MatrixLedger{},
	}
	cells := in.Plan([]*platform.Release{&debian}, []*labv1.MatrixCell{updates})
	for _, c := range cells {
		if c.Architecture == "aarch64" && (c.State != Gated || c.Reason != "vendor cannot boot it" || c.Runnable()) {
			t.Fatalf("gated lane cell = %q %q runnable=%t", c.State, c.Reason, c.Runnable())
		}
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

func TestConsoleEnrollmentRequiresItsOwnNativeRecord(t *testing.T) {
	cell := &labv1.MatrixCell{Name: "enroll-from-console", Title: "Enroll from console", Capabilities: []string{"lifecycle"}, Image: labv1.MatrixImage_MATRIX_IMAGE_CLOUD, Lane: string(platform.LaneEnrollFromConsole)}
	in := &Inputs{Ledger: &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{
		entry("ubuntu-24.04", "lifecycle", "aarch64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, time.Now()),
	}}}
	for _, key := range []string{"ubuntu-24.04", "fedora-44"} {
		r := release(t, key)
		in.Manifests = append(in.Manifests, &Manifest{Image: &labv1.ImageManifest{Id: key, Edition: "server-cloudimg"}, Release: r, Architecture: "aarch64"})
		if got := in.cell(r, cell, "aarch64"); got.State != NotRun {
			t.Fatalf("%s console enrollment inherited another lane's qualification: %s", key, got.State)
		}
	}
	unsupported := *release(t, "rhel-9")
	unsupported.Lab.Lanes = slices.DeleteFunc(slices.Clone(unsupported.Lab.Lanes), func(l platform.LabLane) bool { return l == platform.LaneEnrollFromConsole })
	if got := in.cell(&unsupported, cell, "aarch64"); got.State != NoLane {
		t.Fatalf("unsupported console enrollment recipe became runnable: %s", got.State)
	}
}

// Snapshot promotion must not carry a rolling platform's old pass forward, even
// if an operator keeps the manifest ID while changing its repository date.
func TestRollingSnapshotEvidenceIdentity(t *testing.T) {
	arch := release(t, "arch")
	spec := &labv1.MatrixCell{Name: "inventory", Capabilities: []string{"inventory"}, Image: labv1.MatrixImage_MATRIX_IMAGE_CLOUD, Lane: "inspect"}
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	manifest := &Manifest{Release: arch, Architecture: "x86_64", SHA256: strings.Repeat("b", 64), Image: &labv1.ImageManifest{Id: "arch-snapshot", RepositorySnapshotDate: proto.String("2026-10-02")}}
	record := entry("arch", "inventory", "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, at)
	record.Manifest = manifest.Image.GetId()
	record.ManifestSha256 = manifest.SHA256
	record.RepositorySnapshotDate = manifest.Image.GetRepositorySnapshotDate()
	in := &Inputs{Manifests: []*Manifest{manifest}, Ledger: &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{record}}}
	if c := in.cell(arch, spec, "x86_64"); c.State != Pass || c.RequalificationDue(at) {
		t.Fatalf("matching snapshot is not a current pass: %s", c.State)
	}
	for _, field := range []*string{&record.Manifest, &record.ManifestSha256, &record.RepositorySnapshotDate} {
		saved := *field
		*field = ""
		c := in.cell(arch, spec, "x86_64")
		if c.State != NotRun || !c.RequalificationDue(at) {
			t.Fatalf("incomplete snapshot binding reused result: %s", c.State)
		}
		*field = saved
	}
	c := in.cell(arch, spec, "x86_64")
	if c.RequalificationDue(at.Add(14*24*time.Hour-time.Nanosecond)) || !c.RequalificationDue(at.Add(14*24*time.Hour)) {
		t.Fatal("rolling requalification window is not exactly registry cadence")
	}
	if !c.RequalificationDue(at.Add(-time.Second)) {
		t.Fatal("future-dated evidence suppressed requalification")
	}
	record.Scope = "files-only"
	if !c.RequalificationDue(at) {
		t.Fatal("partial evidence suppressed complete requalification")
	}
	fixed := &Cell{Release: release(t, "ubuntu-24.04"), State: NotRun}
	if fixed.RequalificationDue(at) {
		t.Fatal("fixed release entered rolling requalification lane")
	}
}
