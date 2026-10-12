package platform

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSnapshotRecipeRequiresExactKernelAndSnapshot(t *testing.T) {
	for _, target := range []struct{ version, architecture string }{
		{"20261007", "aarch64"},
		{"20261009", "x86_64"},
		{"20261010", "x86_64"},
	} {
		inputs, err := RepositorySnapshotInputs("opensuse-tumbleweed", target.version, target.architecture)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(inputs, "kernel-default=7.2.9-1.1") || slices.Contains(inputs, "kernel-default") {
			t.Fatalf("%s/%s does not require the exact signed snapshot kernel: %v", target.version, target.architecture, inputs)
		}
	}
	for _, target := range []struct{ version, architecture string }{
		{"20261007", "x86_64"},
		{"20261009", "aarch64"},
		{"20261010", "aarch64"},
		{"20261011", "x86_64"},
		{"", "aarch64"},
	} {
		if _, err := RepositorySnapshotInputs("opensuse-tumbleweed", target.version, target.architecture); err == nil {
			t.Fatalf("unrecorded snapshot %s/%s admitted without an exact kernel", target.version, target.architecture)
		}
	}
}

func TestIdentify(t *testing.T) {
	for _, test := range []struct {
		os  OSRelease
		key string
	}{
		{OSRelease{ID: "ubuntu", VersionID: "24.04"}, "ubuntu-24.04"},
		{OSRelease{ID: "ubuntu", VersionID: "24.10"}, ""},
		{OSRelease{ID: "rhel", VersionID: "9.8"}, "rhel-9"},
		{OSRelease{ID: "rhel", VersionID: "9"}, "rhel-9"},
		{OSRelease{ID: "rhel", VersionID: "90.1"}, ""},
		{OSRelease{ID: "rhel", VersionID: "9.8.1"}, ""},
		{OSRelease{ID: "arch"}, "arch"},
		{OSRelease{ID: "arch", VersionID: "20261001"}, ""},
		{OSRelease{ID: "opensuse-tumbleweed", VersionID: "20261007"}, "opensuse-tumbleweed"},
		{OSRelease{ID: "opensuse-tumbleweed", VersionID: "2026"}, ""},
		{OSRelease{ID: "fedora", VersionID: "44", VariantID: "cloud"}, "fedora-44"},
		{OSRelease{ID: "fedora", VersionID: "44", VariantID: "silverblue"}, "fedora-atomic"},
		{OSRelease{ID: "fedora", VersionID: "44", VariantID: "coreos"}, ""},
		{OSRelease{ID: "linuxmint", VersionID: "22.3"}, "linuxmint-22.3"},
		// ID_LIKE never selects: an unlisted derivative is unknown.
		{OSRelease{ID: "zorin", VersionID: "17"}, ""},
	} {
		if got := Identify(test.os); got.Key != test.key {
			t.Errorf("Identify(%+v) = %q, want %q", test.os, got.Key, test.key)
		}
	}
}

func TestUnknownReleaseIsGated(t *testing.T) {
	r := Identify(OSRelease{ID: "ubuntu", VersionID: "20.04"})
	for _, c := range Capabilities {
		var gate *GateError
		if err := r.Gate(c); !errors.As(err, &gate) || gate.Reason == "" {
			t.Errorf("%s on unregistered release: %v", c, err)
		}
	}
}

func TestDerivativeUsesBaseTooling(t *testing.T) {
	mint := Identify(OSRelease{ID: "linuxmint", VersionID: "22.3"})
	if mint.Native().Key != "ubuntu-24.04" || mint.Native().Packages.Backend != BackendAPT {
		t.Fatalf("Mint native base = %q", mint.Native().Key)
	}
	if _, ok := mint.PasswordPins("22.3"); !ok {
		t.Fatal("Mint lost its base's measured password pins")
	}
	// Measured recovery readiness identifies the os-release row itself; with
	// no chain, Mint reported recovery_readiness_measured_grub_unsupported
	// although it boots its base's stock shim+GRUB.
	if mint.Quirks.RecoveryGRUB != mint.Native().Quirks.RecoveryGRUB || mint.Quirks.RecoveryGRUB.Entries == "" {
		t.Fatalf("Mint recovery GRUB chain = %+v", mint.Quirks.RecoveryGRUB)
	}
	// A derivative never names a feed itself: its advisories are the base's
	// feed restricted to verified base-archive packages, always partial.
	if len(mint.Advisory.Feeds) != 0 || mint.Advisory.Partial == "" || mint.BaseCoverage() != mint.Native() {
		t.Fatalf("Mint advisory coverage = %+v", mint.Advisory)
	}
	if base := mint.Native(); base.BaseCoverage() != nil {
		t.Fatal("a base release reported derivative coverage")
	}
	omarchy := Identify(OSRelease{ID: "omarchy", VersionID: "4.0.4"})
	if omarchy.BaseCoverage() != nil || omarchy.Gate(Advisories) == nil {
		t.Fatal("a derivative without vendor origins inherited its base's advisory feed")
	}
	if other := Identify(OSRelease{ID: "linuxmint", VersionID: "22.2"}); other.BaseCoverage() != nil {
		t.Fatal("an unlisted derivative release gained base coverage")
	}
}

func TestPasswordPinsAreMinorExact(t *testing.T) {
	el9 := Identify(OSRelease{ID: "almalinux", VersionID: "9.6"})
	if _, ok := el9.PasswordPins("9.6"); ok {
		t.Fatal("EL 9.8 pins applied to 9.6")
	}
	if pins, ok := el9.PasswordPins("9.8"); !ok || pins.Manager != "1.2.6" {
		t.Fatalf("EL 9.8 pins = %+v, %t", pins, ok)
	}
}

func TestForFeedReleaseConventions(t *testing.T) {
	for _, test := range []struct {
		distro, release, key string
	}{
		{"ubuntu", "24.04", "ubuntu-24.04"},
		{"ubuntu", "noble", "ubuntu-24.04"},
		{"ubuntu", "jammy", ""},
		{"rhel", "9", "rhel-9"},
		{"rhel", "9.4", "rhel-9"},
		{"rhel", "9.4.1", ""},
		{"sles", "15.6", "sles-15"},
		{"arch", "rolling", "arch"},
		{"arch", "", ""},
		{"opensuse-tumbleweed", "rolling", "opensuse-tumbleweed"},
		{"opensuse-tumbleweed", "20240615", ""},
	} {
		if got := ForFeed(test.distro, test.release); got.Key != test.key {
			t.Errorf("ForFeed(%q, %q) = %q, want %q", test.distro, test.release, got.Key, test.key)
		}
	}
	arch, tumbleweed, noble := ForFeed("arch", "rolling"), ForFeed("opensuse-tumbleweed", "rolling"), ForFeed("ubuntu", "24.04")
	if arch.FeedRelease("") != "rolling" || tumbleweed.FeedRelease("20261007") != "rolling" || noble.FeedRelease("noble") != "24.04" || noble.FeedRelease("24.04") != "24.04" {
		t.Fatal("observed releases lost their feed spelling")
	}
}

func TestAssistanceCapturePackagesKeepCompositorABIReleaseSpecific(t *testing.T) {
	noble := ForManifest("ubuntu", "24.04").Lab.Session.Capture
	resolute := ForManifest("ubuntu", "26.04").Lab.Session.Capture
	if !slices.Contains(noble, "libmutter-14-0") || !slices.Contains(noble, "mutter-common") {
		t.Fatal("Ubuntu 24.04 compositor provenance is incomplete")
	}
	if !slices.Contains(resolute, "libmutter-18-0") || slices.Contains(resolute, "libmutter-14-0") || slices.Contains(noble, "libmutter-18-0") {
		t.Fatal("Ubuntu compositor ABI provenance crossed release boundaries")
	}
	if !slices.Contains(ForManifest("fedora", "44").Lab.Session.Capture, "mutter") {
		t.Fatal("Fedora compositor provenance is incomplete")
	}
}

func TestAssistanceTerminalMatchesInstalledDesktop(t *testing.T) {
	for _, test := range []struct {
		version string
		argv    []string
	}{
		{"24.04", []string{"gnome-terminal", "--"}},
		{"26.04", []string{"ptyxis", "--new-window", "--"}},
	} {
		release := ForManifest("ubuntu", test.version)
		if !release.Supported(Assistance) || !slices.Equal(release.Lab.Session.Terminal, test.argv) {
			t.Errorf("%s assistance terminal = %v, want %v", release.Name, release.Lab.Session.Terminal, test.argv)
		}
	}
}

func TestDesktopFirstLoginMarkersMatchUpgradeUnitConditions(t *testing.T) {
	// The new upgrade-login unit runs only when the original setup marker
	// exists and this release-specific marker does not.
	resolute := ForManifest("ubuntu", "26.04").Lab.Session.FirstLoginMarkers
	if !slices.Equal(resolute, []string{"gnome-initial-setup/upgrade-26.04-done"}) {
		t.Fatalf("upgrade welcome would cover assistance controls: markers = %v", resolute)
	}
	if noble := ForManifest("ubuntu", "24.04").Lab.Session.FirstLoginMarkers; len(noble) != 0 {
		t.Fatalf("GNOME 46 inherited a different release's upgrade markers: %v", noble)
	}
}

// TestRegistryConsistent catches registry rows that providers cannot act on.
func TestRegistryConsistent(t *testing.T) {
	var keys []string
	for _, r := range registry {
		if r.Key == "" || slices.Contains(keys, r.Key) {
			t.Errorf("%q: empty or duplicate key", r.Key)
		}
		keys = append(keys, r.Key)
		n := r.Native()
		if r.Supported(Definitions) && n.Quirks.SystemdFloor == 0 {
			t.Errorf("%s: definitions without a systemd floor", r.Key)
		}
		if r.Supported(Password) && (n.Quirks.PAMManager == PAMManagerNone || len(n.Quirks.Password) == 0) {
			t.Errorf("%s: password without PAM manager or pins", r.Key)
		}
		if (r.Supported(Packages) || r.Supported(Inventory) || r.Supported(Lifecycle)) && n.Packages.Backend == BackendNone {
			t.Errorf("%s: package capability without a backend", r.Key)
		}
		if r.Supported(Advisories) && r.BaseCoverage() == nil && (len(r.Advisory.Feeds) == 0 || r.Advisory.Ecosystem == "") {
			t.Errorf("%s: advisories without a feed", r.Key)
		}
		if r.Supported(ReleaseUpgrade) && r.UpgradeTo == "" {
			t.Errorf("%s: release upgrade without an upgrade target", r.Key)
		}
		if r.UpgradeTo != "" {
			if target, ok := Lookup(r.UpgradeTo); !ok || target.ID != r.ID || len(target.Advisory.Feeds) == 0 || !slices.Equal(target.Advisory.Feeds, r.Advisory.Feeds) || target.Codename == "" {
				t.Errorf("%s: upgrade target %q is not a same-distribution row with the same advisory feed and a codename", r.Key, r.UpgradeTo)
			}
		}
		if len(r.Advisory.VendorOrigins) != 0 && (r.BaseCoverage() == nil || len(r.Advisory.Feeds) != 0 || r.Advisory.Partial == "") {
			t.Errorf("%s: vendor origins without a covering base, with own feeds, or not partial", r.Key)
		}
		for c := range r.Gates {
			if !slices.Contains(Capabilities, c) || r.Supported(c) {
				t.Errorf("%s: gate %q is unknown or contradicts Supports", r.Key, c)
			}
		}
		for arch, gated := range r.ArchitectureGates {
			for c, reason := range gated {
				if !slices.Contains(r.Architectures, arch) || !r.Supported(c) || reason == "" {
					t.Errorf("%s: %s gate %q is not a reasoned gate of a supported capability on a release architecture", r.Key, arch, c)
				}
			}
		}
		for _, other := range registry {
			if other != r && other.ID == r.ID && overlaps(r, other) {
				t.Errorf("%s and %s match the same os-release identity", r.Key, other.Key)
			}
		}
	}
}

func overlaps(a, b *Release) bool {
	variants := func(r *Release) []string {
		if r.Variants == nil {
			return []string{"", "workstation", "silverblue"}
		}
		return r.Variants
	}
	for _, v := range []string{a.Version.Value, b.Version.Value, a.Version.Value + ".1", b.Version.Value + ".1", "", "20261007"} {
		for _, variant := range variants(a) {
			if slices.Contains(variants(b), variant) && a.Version.matches(v) && b.Version.matches(v) {
				return true
			}
		}
	}
	return false
}

// Natively qualified host providers on the arm64 resource lane: Debian 12
// (systemd 252 floor) and 13, Ubuntu 22.04 without definitions (systemd 249),
// Rocky Linux 9.8 and 10.2 with the EL chroot account root.
func TestNativelyQualifiedHostResourceReleases(t *testing.T) {
	for _, tc := range []struct {
		id, version string
		floor       int
		pins        PasswordPins
		chroot      bool
		definitions bool
	}{
		{"debian", "12", 252, PasswordPins{Version: "12", Quality: "1.4.5", PAM: "1.5.2", Manager: "1.5.2"}, false, true},
		{"debian", "13", 255, PasswordPins{Version: "13", Quality: "1.4.5", PAM: "1.7.0", Manager: "1.7.0"}, false, true},
		{"ubuntu", "22.04", 255, PasswordPins{Version: "22.04", Quality: "1.4.4", PAM: "1.4.0", Manager: "1.4.0"}, false, false},
		{"rocky", "9.8", 252, PasswordPins{Version: "9.8", Quality: "1.4.4", PAM: "1.5.1", Manager: "1.2.6"}, true, true},
		{"rocky", "10.2", 255, PasswordPins{Version: "10.2", Quality: "1.4.5", PAM: "1.6.1", Manager: "1.5.2"}, true, true},
	} {
		r := Identify(OSRelease{ID: tc.id, VersionID: tc.version})
		for _, c := range []Capability{Packages, Accounts, Sysctl, Firewall, Password} {
			if err := r.Gate(c); err != nil {
				t.Errorf("%s %s %s gated: %v", tc.id, tc.version, c, err)
			}
		}
		if (r.Gate(Definitions) == nil) != tc.definitions {
			t.Errorf("%s %s definitions supported=%t", tc.id, tc.version, !tc.definitions)
		}
		q := r.Native().Quirks
		if q.SystemdFloor != tc.floor || q.AccountChroot != tc.chroot {
			t.Errorf("%s %s quirks %+v", tc.id, tc.version, q)
		}
		if pins, ok := r.PasswordPins(tc.version); !ok || pins != tc.pins {
			t.Errorf("%s %s pins %+v %t", tc.id, tc.version, pins, ok)
		}
	}
	if err := Identify(OSRelease{ID: "rocky", VersionID: "8.10"}).Gate(Sysctl); err == nil {
		t.Error("Rocky Linux 8 host providers admitted")
	}
}

// Ubuntu 22.04 ships systemd 249, whose systemd-cryptenroll has no
// --unlock-key-file; binding there ended OUTCOME_UNKNOWN after authorization.
func TestTPM2BindFollowsShippedSystemd(t *testing.T) {
	for key, want := range map[string]bool{"ubuntu-22.04": false, "ubuntu-24.04": true, "debian-12": true, "debian-13": true, "rhel-9": true, "rhel-8": false} {
		release, ok := Lookup(key)
		if !ok {
			t.Fatalf("registry lacks %s", key)
		}
		if got := release.TPM2BindSupported(); got != want {
			t.Errorf("%s (systemd %d) TPM2BindSupported = %t, want %t", key, release.Systemd, got, want)
		}
	}
	if !Identify(OSRelease{ID: "unknown-os", VersionID: "1"}).TPM2BindSupported() {
		t.Fatal("a release without a recorded systemd must defer to the native probe")
	}
}

// The native self-update lane is admitted per guest architecture exactly where
// a native record passed; both architecture spellings resolve identically.
func TestUpdateLaneArchitectures(t *testing.T) {
	for _, tc := range []struct {
		id, version, architecture string
		admitted                  bool
	}{
		{"ubuntu", "24.04", "amd64", true},
		{"ubuntu", "26.04", "x86_64", true},
		{"ubuntu", "24.04", "arm64", true},
		{"ubuntu", "26.04", "aarch64", true},
		{"fedora", "44", "x86_64", true},
		{"fedora", "44", "aarch64", true},
		{"fedora", "43", "amd64", true},
		{"fedora", "43", "arm64", true},
		{"rhel", "9.8", "x86_64", true},
		{"rhel", "10.2", "x86_64", true},
		{"rhel", "9.8", "aarch64", true},
		{"rhel", "10.2", "arm64", true},
		{"ubuntu", "22.04", "arm64", true},
		{"debian", "12", "arm64", true},
		{"debian", "13", "aarch64", true},
		{"rocky", "9.8", "aarch64", true},
		{"rocky", "10.2", "aarch64", true},
		{"almalinux", "9.8", "aarch64", true},
		{"almalinux", "10.2", "arm64", true},
		// Unqualified architectures and releases stay refused.
		{"ubuntu", "22.04", "amd64", false},
		{"debian", "12", "amd64", false},
		{"almalinux", "9.8", "x86_64", false},
		{"rocky", "8.10", "aarch64", false},
		{"opensuse-leap", "16.0", "x86_64", false},
		{"ubuntu", "24.04", "riscv64", false},
	} {
		r := Identify(OSRelease{ID: tc.id, VersionID: tc.version})
		if err := r.LabLaneOn(LaneUpdates, tc.architecture); (err == nil) != tc.admitted {
			t.Errorf("%s %s %s: admitted=%t, err=%v", tc.id, tc.version, tc.architecture, tc.admitted, err)
		}
	}
	// A lane without an architecture restriction follows Release.Architectures.
	r := Identify(OSRelease{ID: "ubuntu", VersionID: "24.04"})
	for _, architecture := range []string{"amd64", "arm64"} {
		if err := r.LabLaneOn(LaneResources, architecture); err != nil {
			t.Errorf("unrestricted resources lane on %s: %v", architecture, err)
		}
	}
}

// A gated lane states a concrete reason, names only the release's own
// architectures, and is refused exactly where it applies; a lane gated on every
// architecture is never also a maintained recipe.
func TestLaneGates(t *testing.T) {
	for _, r := range Releases() {
		for lane, gate := range r.Lab.LaneGates {
			if strings.TrimSpace(gate.Reason) == "" {
				t.Errorf("%s %s lane gate has no reason", r.Key, lane)
			}
			for _, architecture := range gate.Architectures {
				if !slices.Contains(r.Architectures, architecture) {
					t.Errorf("%s %s lane gate names foreign architecture %q", r.Key, lane, architecture)
				}
			}
			if len(gate.Architectures) == 0 && slices.Contains(r.Lab.Lanes, lane) {
				t.Errorf("%s %s lane is both maintained and gated on every architecture", r.Key, lane)
			}
		}
	}
	r := &Release{Name: "Example", Architectures: []string{"x86_64", "aarch64"}, Lab: Lab{
		Lanes:     []LabLane{LaneUpdates},
		LaneGates: map[LabLane]LaneGate{LaneUpdates: {Reason: "vendor kernel unsigned", Architectures: []string{"aarch64"}}, "inspect": {Reason: "no observer"}},
	}}
	if err := r.LabLaneOn(LaneUpdates, "amd64"); err != nil {
		t.Fatalf("ungated architecture refused: %v", err)
	}
	if err := r.LabLaneOn(LaneUpdates, "arm64"); err == nil || !strings.Contains(err.Error(), "vendor kernel unsigned") {
		t.Fatalf("gated architecture admitted or reason lost: %v", err)
	}
	if got := r.LaneGateOn("inspect", "x86_64"); got != "no observer" {
		t.Fatalf("all-architecture gate = %q", got)
	}
	if got := r.LaneGateOn(LaneUpdates, "x86_64"); got != "" {
		t.Fatalf("gate leaked to ungated architecture: %q", got)
	}
}

// RHEL's aarch64 DVDs carry no Workstation environment; the encrypted golden
// installs Server with GUI there and keeps Workstation on x86_64.
func TestRHELDesktopPackagesFollowArchitectureMedia(t *testing.T) {
	for _, key := range []string{"rhel-9", "rhel-10"} {
		r, ok := Lookup(key)
		if !ok {
			t.Fatalf("%s missing", key)
		}
		for architecture, want := range map[string]string{"x86_64": "@^workstation-product-environment", "amd64": "@^workstation-product-environment", "aarch64": "@^graphical-server-environment", "arm64": "@^graphical-server-environment"} {
			if got := r.Lab.Session.DesktopPackages("gnome", architecture); !slices.Equal(got, []string{want}) {
				t.Errorf("%s %s gnome packages = %v, want %s", key, architecture, got, want)
			}
		}
	}
}

// A provision lane qualifies a release's own vendor format; the console must
// never offer a format the release's installation media lack.
func TestProvisionLanesMatchOfferedFormats(t *testing.T) {
	for _, r := range Releases() {
		for _, p := range r.Provisioning {
			if _, ok := ProvisionLane(p); !ok && p != ProvisionNixOS {
				t.Fatalf("%s offers unknown provisioning format %q", r.Key, p)
			}
		}
		for _, p := range []Provisioning{ProvisionCloudInit, ProvisionAutoinstall, ProvisionKickstart, ProvisionAutoYaST} {
			lane, _ := ProvisionLane(p)
			if back, ok := LaneProvisioning(lane); !ok || back != p {
				t.Fatalf("lane %s does not map back to %s", lane, p)
			}
			if slices.Contains(r.Lab.Lanes, lane) && !slices.Contains(r.Provisioning, p) {
				t.Fatalf("%s has a %s lane but does not offer %s", r.Key, lane, p)
			}
			if gate := r.ProvisionGate(lane); (gate == "") != slices.Contains(r.Provisioning, p) {
				t.Fatalf("%s %s: provision gate %q disagrees with offered formats", r.Key, p, gate)
			}
		}
		if r.ProvisionGate(LaneEnrollFromConsole) != "" {
			t.Fatalf("%s: a non-provision lane was gated as a provisioning format", r.Key)
		}
	}
	if _, ok := LaneProvisioning("provision-nixos"); ok {
		t.Fatal("a provisioning format without a lab lane mapped to a lane")
	}
	nixos, ok := Lookup("nixos")
	if !ok || nixos.Supported(Lifecycle) || !strings.Contains(nixos.GateReason(Lifecycle), "lindmd serves no NixOS installation artifact") {
		t.Fatal("NixOS installation must stay gated with its self-hosting reason")
	}
}

func TestDisplayName(t *testing.T) {
	for _, tc := range []struct{ id, version, want string }{
		{"ubuntu", "24.04", "Ubuntu 24.04 LTS"},
		{"rhel", "9.4", "RHEL 9.4"},
		{"fedora", "44", "Fedora 44"},
		{"debian", "12", "Debian 12"},
		{"plan9", "4", ""},
	} {
		if got := Identify(OSRelease{ID: tc.id, VersionID: tc.version}).DisplayName(tc.version); got != tc.want {
			t.Errorf("%s %s: got %q, want %q", tc.id, tc.version, got, tc.want)
		}
	}
}
