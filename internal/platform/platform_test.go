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
		if r.Supported(Advisories) && r.Advisory.Feed == "" {
			t.Errorf("%s: advisories without a feed", r.Key)
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
