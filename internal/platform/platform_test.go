package platform

import (
	"errors"
	"slices"
	"testing"
)

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
	if err := mint.Gate(Advisories); err == nil {
		t.Fatal("derivative inherited its base's advisory feed")
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
	if slices.Contains(resolute, "libmutter-14-0") {
		t.Fatal("Ubuntu 26.04 inherited an unavailable compositor ABI")
	}
	if !slices.Contains(ForManifest("fedora", "44").Lab.Session.Capture, "mutter") {
		t.Fatal("Fedora compositor provenance is incomplete")
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
		if r.Supported(Advisories) && (len(r.Advisory.Feeds) == 0 || r.Advisory.Ecosystem == "") {
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
		for c := range r.Gates {
			if !slices.Contains(Capabilities, c) || r.Supported(c) {
				t.Errorf("%s: gate %q is unknown or contradicts Supports", r.Key, c)
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
