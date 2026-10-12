package labmatrix

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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
	if got := in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_CLOUD, "x86_64", "", ""); got != current {
		t.Fatal("historical path ordering hid the current rolling snapshot")
	}
	in.PreferredManifest = old.Image.GetId()
	if got := in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_CLOUD, "x86_64", "", ""); got != old {
		t.Fatal("newer snapshot silently replaced an explicit owner choice")
	}
}

func TestRecoveryManifestDoesNotReplaceOwnerBootTopology(t *testing.T) {
	r := release(t, "arch")
	ordinary := &Manifest{Image: &labv1.ImageManifest{Id: "cloud", RepositorySnapshotDate: proto.String("2026-10-02")}, Release: r, Architecture: "x86_64"}
	recovery := &Manifest{Image: &labv1.ImageManifest{Id: "owner-uki", Edition: r.Lab.RecoveryEdition, RepositorySnapshotDate: proto.String("2026-10-03")}, Release: r, Architecture: "x86_64"}
	grub := &Manifest{Image: &labv1.ImageManifest{Id: "owner-grub", Edition: "grub-encrypted-lab"}, Release: r, Architecture: "x86_64"}
	uki := &Manifest{Image: &labv1.ImageManifest{Id: "encrypted-uki", Edition: r.Lab.RecoveryInstallerEdition}, Release: r, Architecture: "x86_64"}
	in := &Inputs{Manifests: []*Manifest{recovery, ordinary, grub, uki}}
	if got := in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_CLOUD, "x86_64", "", ""); got != ordinary {
		t.Fatal("dedicated recovery baseline silently replaced the ordinary rolling image")
	}
	if got := in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_CLOUD, "x86_64", r.Lab.RecoveryEdition, ""); got != recovery {
		t.Fatal("explicit owner-UKI recovery baseline was not selected")
	}
	in.PreferredManifest = grub.Image.Id
	if got := in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER, "x86_64", r.Lab.RecoveryInstallerEdition, ""); got != nil {
		t.Fatal("owner-selected GRUB was silently remapped to systemd-boot recovery")
	}
	if got := in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_CLOUD, "aarch64", r.Lab.RecoveryEdition, ""); got != nil {
		t.Fatal("recovery baseline crossed architecture")
	}
}

func TestInstallerProvisioningNeverBootsDesktopMedia(t *testing.T) {
	r := release(t, "ubuntu-26.04")
	desktop := &Manifest{Image: &labv1.ImageManifest{Id: "desktop", Edition: platform.DesktopInstallerEdition}, Release: r, Architecture: "x86_64"}
	server := &Manifest{Image: &labv1.ImageManifest{Id: "server", Edition: "live-server-encrypted-lab"}, Release: r, Architecture: "x86_64"}
	in := &Inputs{Manifests: []*Manifest{desktop, server}}
	cell := func(name, lane string) *Cell {
		return in.cell(r, &labv1.MatrixCell{Name: name, Lane: lane, Image: labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER}, "x86_64")
	}
	if got := cell("encrypted", "device-actions").Manifest; got != desktop {
		t.Fatal("desktop media lost its place as the release's encrypted installer")
	}
	if got := cell("provision-autoinstall", string(platform.LaneProvisionAutoinstall)).Manifest; got != server {
		t.Fatal("autoinstall provisioning booted desktop media")
	}
	in.PreferredManifest = desktop.Image.Id
	if got := cell("provision-autoinstall", string(platform.LaneProvisionAutoinstall)).Manifest; got != nil {
		t.Fatal("an owner-preferred desktop image was used for installer provisioning")
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
	debian := *release(t, "debian-12")
	debian.Lab.LaneArchitectures = map[platform.LabLane][]string{platform.LaneUpdates: {"aarch64"}}
	cloud := labv1.MatrixImage_MATRIX_IMAGE_CLOUD
	updates := &labv1.MatrixCell{Name: "self-update", Title: "Self-update", Capabilities: []string{"self-update"}, Image: cloud, Lane: "updates"}
	in := &Inputs{
		Manifests: []*Manifest{
			{Path: "lab/images/a.json", Image: &labv1.ImageManifest{Id: "a", Edition: "server-cloudimg"}, Release: &debian, Architecture: "x86_64"},
			{Path: "lab/images/b.json", Image: &labv1.ImageManifest{Id: "b", Edition: "server-cloudimg"}, Release: &debian, Architecture: "aarch64"},
		},
		Ledger: &labv1.MatrixLedger{},
	}
	got := map[string]State{}
	for _, c := range in.Plan([]*platform.Release{&debian}, []*labv1.MatrixCell{updates}) {
		got[c.Architecture] = c.State
	}
	if got["x86_64"] != NoLane || got["aarch64"] != NotRun {
		t.Fatalf("debian-12 self-update states = %v, want x86_64 no lane, aarch64 not run", got)
	}
}

// A cell that needs a TPM is gated (lab-only) where the release's installed
// kernel cannot bind the lab's TPM (Debian arm64), and runs elsewhere.
func TestPlanGatesTPMCellsWhereTPMIsUnobservable(t *testing.T) {
	debian := release(t, "debian-13")
	encrypted := labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER
	boots := &labv1.MatrixCell{Name: "tpm-unattended-boots", Title: "TPM unattended boots", Capabilities: []string{"encryption"}, Image: encrypted, Lane: "device-actions", Tpm: true}
	in := &Inputs{
		Manifests: []*Manifest{
			{Path: "lab/images/a.json", Image: &labv1.ImageManifest{Id: "a", Edition: "netinst"}, Release: debian, Architecture: "x86_64"},
			{Path: "lab/images/b.json", Image: &labv1.ImageManifest{Id: "b", Edition: "netinst"}, Release: debian, Architecture: "aarch64"},
		},
		Ledger: &labv1.MatrixLedger{},
	}
	got := map[string]*Cell{}
	for _, c := range in.Plan([]*platform.Release{debian}, []*labv1.MatrixCell{boots}) {
		got[c.Architecture] = c
	}
	if got["x86_64"].State != NotRun || got["aarch64"].State != Gated || !strings.Contains(got["aarch64"].Reason, "Lab.TPM.Unobservable") {
		t.Fatalf("debian-13 TPM cell: x86_64 %v, aarch64 %v %q", got["x86_64"].State, got["aarch64"].State, got["aarch64"].Reason)
	}
}

// Pop!_OS installs an unsigned systemd-boot, so a cell that requires Secure
// Boot is gated with the registry's measured reason instead of failing; the
// same lane without Secure Boot stays schedulable.
func TestPlanGatesSecureBootCellsWhereSecureBootIsUnavailable(t *testing.T) {
	pop := release(t, "pop-24.04")
	if pop.Lab.SecureBootUnavailable == "" {
		t.Fatal("pop-24.04 lost its measured Secure Boot reason")
	}
	encrypted := labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER
	secure := &labv1.MatrixCell{Name: "tpm-unattended-boots", Capabilities: []string{"encryption"}, Image: encrypted, Lane: "device-actions", Tpm: true, SecureBoot: true}
	plain := &labv1.MatrixCell{Name: "device-actions", Capabilities: []string{"encryption"}, Image: encrypted, Lane: "device-actions"}
	in := &Inputs{
		Manifests: []*Manifest{
			{Path: "lab/images/a.json", Image: &labv1.ImageManifest{Id: "a", Edition: "cosmic-encrypted-lab"}, Release: pop, Architecture: "x86_64"},
			{Path: "lab/images/b.json", Image: &labv1.ImageManifest{Id: "b", Edition: "cosmic"}, Release: pop, Architecture: "x86_64"},
		},
		Ledger: &labv1.MatrixLedger{},
	}
	got := map[string]*Cell{}
	for _, c := range in.Plan([]*platform.Release{pop}, []*labv1.MatrixCell{secure, plain}) {
		got[c.Spec.GetName()] = c
	}
	if c := got["tpm-unattended-boots"]; c.State != Gated || !strings.Contains(c.Reason, "Lab.SecureBootUnavailable") || !strings.Contains(c.Reason, pop.Lab.SecureBootUnavailable) {
		t.Fatalf("pop Secure Boot cell: %v %q", c.State, c.Reason)
	}
	if c := got["device-actions"]; c.State == Gated {
		t.Fatalf("pop cell without Secure Boot gated: %q", c.Reason)
	}
}

// Fedora signs its x86_64 kernel for shim but not its aarch64 one, so only the
// aarch64 Secure Boot cell is gated.
func TestPlanGatesSecureBootCellsPerArchitecture(t *testing.T) {
	fedora := release(t, "fedora-44")
	encrypted := labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER
	secure := &labv1.MatrixCell{Name: "tpm-unattended-boots", Capabilities: []string{"encryption"}, Image: encrypted, Lane: "device-actions", Tpm: true, SecureBoot: true}
	in := &Inputs{Ledger: &labv1.MatrixLedger{}}
	for _, arch := range []string{"x86_64", "aarch64"} {
		in.Manifests = append(in.Manifests,
			&Manifest{Path: "lab/images/" + arch + "-i.json", Image: &labv1.ImageManifest{Id: arch + "-i", Edition: "Server-dvd-encrypted-lab"}, Release: fedora, Architecture: arch},
			&Manifest{Path: "lab/images/" + arch + "-c.json", Image: &labv1.ImageManifest{Id: arch + "-c", Edition: "Cloud-Base-Generic"}, Release: fedora, Architecture: arch})
	}
	got := map[string]*Cell{}
	for _, c := range in.Plan([]*platform.Release{fedora}, []*labv1.MatrixCell{secure}) {
		got[c.Architecture] = c
	}
	if c := got["aarch64"]; c.State != Gated || !strings.Contains(c.Reason, fedora.Lab.SecureBootUnavailableFor("arm64")) {
		t.Fatalf("fedora-44 aarch64 Secure Boot cell: %v %q", c.State, c.Reason)
	}
	if c := got["x86_64"]; c.State != NotRun {
		t.Fatalf("fedora-44 x86_64 Secure Boot cell: %v %q", c.State, c.Reason)
	}
}

// A Debian netinst ISO boots both the plain installed golden and the
// guided-LUKS encrypted golden, so encrypted cells are not "no image".
func TestDebianNetinstServesEncryptedCells(t *testing.T) {
	debian, ubuntu := release(t, "debian-13"), release(t, "ubuntu-24.04")
	encrypted := &labv1.MatrixCell{Name: "encrypted", Title: "Encryption", Capabilities: []string{"encryption"}, Image: labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER, Lane: "device-actions"}
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

// Each provisioning cell is admitted only where the registry maintains its
// installer format, boots its own image kind, and never inherits the console
// enrollment or lifecycle record of the same release. A format the vendor does
// not install through is not applicable (gated with the derived reason); an
// offered format without a maintained recipe stays a visible missing lane.
func TestProvisioningCellsRequireTheirOwnFormatAndRecord(t *testing.T) {
	cloud, installer := labv1.MatrixImage_MATRIX_IMAGE_CLOUD, labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER
	in := &Inputs{Ledger: &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{
		entry("ubuntu-24.04", "enroll-from-console", "aarch64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, time.Now()),
		entry("fedora-44", "lifecycle", "aarch64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, time.Now()),
	}}}
	for _, key := range []string{"ubuntu-24.04", "fedora-43", "fedora-44", "rhel-9", "opensuse-tumbleweed"} {
		r := release(t, key)
		in.Manifests = append(in.Manifests,
			&Manifest{Image: &labv1.ImageManifest{Id: key + "-cloud", Edition: "cloud"}, Release: r, Architecture: "aarch64"},
			&Manifest{Image: &labv1.ImageManifest{Id: key + "-installer", Edition: "server-encrypted-lab"}, Release: r, Architecture: "aarch64"})
	}
	for _, tc := range []struct {
		lane       platform.LabLane
		image      labv1.MatrixImage
		admit      []string
		noRecipe   []string
		notOffered []string
	}{
		{platform.LaneProvisionCloudInit, cloud, []string{"ubuntu-24.04", "fedora-43", "fedora-44", "rhel-9"}, []string{"opensuse-tumbleweed"}, nil},
		{platform.LaneProvisionAutoinstall, installer, []string{"ubuntu-24.04"}, nil, []string{"fedora-43", "fedora-44", "rhel-9", "opensuse-tumbleweed"}},
		{platform.LaneProvisionKickstart, installer, []string{"fedora-43", "fedora-44", "rhel-9"}, nil, []string{"ubuntu-24.04", "opensuse-tumbleweed"}},
		{platform.LaneProvisionAutoYaST, installer, []string{"opensuse-tumbleweed"}, nil, []string{"ubuntu-24.04", "fedora-43", "fedora-44", "rhel-9"}},
	} {
		cell := &labv1.MatrixCell{Name: string(tc.lane), Title: string(tc.lane), Capabilities: []string{"lifecycle"}, Image: tc.image, Lane: string(tc.lane)}
		for _, key := range tc.admit {
			got := in.cell(release(t, key), cell, "aarch64")
			if got.State != NotRun {
				t.Fatalf("%s %s: state %s (%s), want an unrecorded runnable cell", key, tc.lane, got.State, got.Reason)
			}
			want := key + "-cloud"
			if tc.image == installer {
				want = key + "-installer"
			}
			if got.Manifest.Image.GetId() != want {
				t.Fatalf("%s %s boots %s, want %s", key, tc.lane, got.Manifest.Image.GetId(), want)
			}
			// The provision lanes do not define -recovery-manifest.
			if got.Recovery != nil {
				t.Fatalf("%s %s selects recovery image %s, which its lane rejects", key, tc.lane, got.Recovery.Image.GetId())
			}
		}
		for _, key := range tc.noRecipe {
			if got := in.cell(release(t, key), cell, "aarch64"); got.State != NoLane {
				t.Fatalf("%s %s: offered format without a recipe is %s (%s), want no lane", key, tc.lane, got.State, got.Reason)
			}
		}
		for _, key := range tc.notOffered {
			r := release(t, key)
			format, _ := platform.LaneProvisioning(tc.lane)
			want := r.Name + " does not provision via " + string(format)
			if got := in.cell(r, cell, "aarch64"); got.State != Gated || got.Reason != want {
				t.Fatalf("%s %s: %s (%s), want gated %q", key, tc.lane, got.State, got.Reason, want)
			}
		}
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

func TestRollingRecoveryEvidenceBindsSecondaryManifest(t *testing.T) {
	r := release(t, "arch")
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	primary := &Manifest{SHA256: strings.Repeat("a", 64), Image: &labv1.ImageManifest{Id: "encrypted", RepositorySnapshotDate: proto.String("2026-10-02")}}
	recovery := &Manifest{SHA256: strings.Repeat("b", 64), Image: &labv1.ImageManifest{Id: "owner-uki", RepositorySnapshotDate: proto.String("2026-10-02"), RepositorySnapshotManifestSha256: proto.String(strings.Repeat("c", 64)), RepositorySnapshotRepomdSha256: proto.String(strings.Repeat("d", 64))}}
	c := &Cell{Release: r, Architecture: "x86_64", Spec: &labv1.MatrixCell{Name: "recovery-sanitize"}, Manifest: primary, Recovery: recovery}
	e := entry(r.Key, c.Spec.Name, c.Architecture, labv1.MatrixVerdict_MATRIX_VERDICT_PASS, at)
	e.Manifest, e.ManifestSha256, e.RepositorySnapshotDate = primary.Image.GetId(), primary.SHA256, primary.Image.GetRepositorySnapshotDate()
	e.RecoveryManifest, e.RecoveryManifestSha256 = recovery.Image.Id, recovery.SHA256
	e.RecoveryRepositorySnapshotDate = recovery.Image.GetRepositorySnapshotDate()
	e.RecoveryRepositoryClosureSha256 = recovery.Image.GetRepositorySnapshotManifestSha256()
	e.RecoveryRepositoryMetadataSha256 = recovery.Image.GetRepositorySnapshotRepomdSha256()
	in := &Inputs{Ledger: &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{e}}}
	if got, _ := in.latest(c); got != e {
		t.Fatal("exact recovery qualification was lost")
	}
	for _, field := range []*string{&e.RecoveryManifest, &e.RecoveryManifestSha256, &e.RecoveryRepositorySnapshotDate, &e.RecoveryRepositoryClosureSha256, &e.RecoveryRepositoryMetadataSha256} {
		value := *field
		*field = ""
		if got, _ := in.latest(c); got != nil {
			t.Fatal("changed or unbound recovery input reused a rolling pass")
		}
		*field = value
	}
}

// gitCommits creates a linear repository and returns its commit SHAs, oldest
// first, so floors are decided by real git ancestry.
func gitCommits(t *testing.T, n int) (string, []string) {
	t.Helper()
	root := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", root, "-c", "user.name=lab", "-c", "user.email=lab@example.invalid", "-c", "commit.gpgsign=false"}, args...)...).Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	shas := make([]string, n)
	for i := range shas {
		git("commit", "-q", "--allow-empty", "-m", strconv.Itoa(i))
		shas[i] = git("rev-parse", "HEAD")
	}
	return root, shas
}

// A requalification floor keeps earlier entries as history but never counts
// them: the newest counted entry decides, a cell with only superseded entries
// is "not run" with the floor named, and a mainline revision recorded beside
// an unpublished worktree commit is the ancestry that counts.
func TestRequalificationFloorSupersedesEarlierEntries(t *testing.T) {
	root, shas := gitCommits(t, 3)
	before, floor, after := shas[0], shas[1], shas[2]
	ubuntu := release(t, "ubuntu-24.04")
	spec := &labv1.MatrixCell{Name: "lifecycle", Title: "Lifecycle", Capabilities: []string{"lifecycle"}, Image: labv1.MatrixImage_MATRIX_IMAGE_CLOUD, Lane: "lifecycle", MinimumRevision: floor}
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	at2 := func(hours int, verdict labv1.MatrixVerdict, revision string) *labv1.MatrixLedgerEntry {
		e := entry("ubuntu-24.04", "lifecycle", "x86_64", verdict, at.Add(time.Duration(hours)*time.Hour))
		e.Revision = revision
		return e
	}
	pass, fail := labv1.MatrixVerdict_MATRIX_VERDICT_PASS, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL
	postFail := at2(0, fail, after+"-dirty")
	ledger := &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{
		postFail,
		at2(1, pass, before),
		at2(2, pass, before+"-dirty"),
		at2(3, pass, strings.Repeat("e", 40)),
		at2(4, pass, "r"),
	}}
	in := &Inputs{
		Matrix:    &labv1.LabMatrix{Cells: []*labv1.MatrixCell{spec}},
		Manifests: []*Manifest{{Image: &labv1.ImageManifest{Id: "x", Edition: "server-cloudimg"}, Release: ubuntu, Architecture: "x86_64"}},
		Ledger:    ledger,
	}
	plan := func() *Cell {
		t.Helper()
		if err := in.applyFloors(gitDescends(root)); err != nil {
			t.Fatal(err)
		}
		return in.Plan([]*platform.Release{ubuntu}, []*labv1.MatrixCell{spec})[0]
	}
	if c := plan(); c.State != Fail || c.Entry != postFail {
		t.Fatalf("newer pre-floor, unknown or malformed passes outranked the post-floor result: %s", c.State)
	}
	ledger.Entries = ledger.Entries[1:]
	c := plan()
	if c.State != NotRun || c.Entry != nil || c.Reason != "superseded by "+floor[:8] || !c.Runnable() {
		t.Fatalf("pre-floor passes counted: %s %q", c.State, c.Reason)
	}
	table, err := Render([]*labv1.MatrixCell{spec}, []*Cell{c})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table, "superseded by "+floor[:8]) {
		t.Fatalf("report hides the superseding floor:\n%s", table)
	}
	worktree := at2(5, pass, strings.Repeat("f", 40))
	worktree.MainlineRevision = floor
	ledger.Entries = append(ledger.Entries, worktree)
	if c := plan(); c.State != Pass || c.Entry != worktree {
		t.Fatalf("unpublished worktree commit on the floor's mainline did not count: %s", c.State)
	}
	worktree.MainlineRevision = before
	worktree.Revision = after
	if c := plan(); c.State != NotRun {
		t.Fatalf("source revision outranked the recorded mainline ancestry: %s", c.State)
	}
	if len(ledger.GetEntries()) != 5 {
		t.Fatal("superseded entries were removed from history")
	}
	spec.MinimumRevision = ""
	if c := plan(); c.State != Pass {
		t.Fatalf("cell without a floor ignored its history: %s", c.State)
	}
}

// A rolling cell whose only pass predates its floor is due for requalification.
func TestRequalificationFloorMakesRollingCellDue(t *testing.T) {
	root, shas := gitCommits(t, 2)
	arch := release(t, "arch")
	spec := &labv1.MatrixCell{Name: "inventory", Capabilities: []string{"inventory"}, Image: labv1.MatrixImage_MATRIX_IMAGE_CLOUD, Lane: "inspect", MinimumRevision: shas[1]}
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	manifest := &Manifest{Release: arch, Architecture: "x86_64", SHA256: strings.Repeat("b", 64), Image: &labv1.ImageManifest{Id: "arch-snapshot", RepositorySnapshotDate: proto.String("2026-10-02")}}
	record := entry("arch", "inventory", "x86_64", labv1.MatrixVerdict_MATRIX_VERDICT_PASS, at)
	record.Manifest, record.ManifestSha256, record.RepositorySnapshotDate = manifest.Image.GetId(), manifest.SHA256, manifest.Image.GetRepositorySnapshotDate()
	record.Revision = shas[0]
	in := &Inputs{Matrix: &labv1.LabMatrix{Cells: []*labv1.MatrixCell{spec}}, Manifests: []*Manifest{manifest}, Ledger: &labv1.MatrixLedger{Entries: []*labv1.MatrixLedgerEntry{record}}}
	if err := in.applyFloors(gitDescends(root)); err != nil {
		t.Fatal(err)
	}
	if c := in.cell(arch, spec, "x86_64"); c.State != NotRun || !c.RequalificationDue(at) {
		t.Fatalf("superseded rolling pass suppressed requalification: %s", c.State)
	}
	record.Revision = shas[1]
	if err := in.applyFloors(gitDescends(root)); err != nil {
		t.Fatal(err)
	}
	if c := in.cell(arch, spec, "x86_64"); c.State != Pass || c.RequalificationDue(at) {
		t.Fatalf("pass at the floor was not current: %s", c.State)
	}
}
