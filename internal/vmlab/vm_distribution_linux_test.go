//go:build linux

package vmlab

import (
	"testing"

	"lindm/internal/packaging"
	"lindm/internal/platform"
)

func TestNativeDistributionRouting(t *testing.T) {
	for _, tc := range []struct {
		id, version string
		backend     platform.Backend
		format      packaging.Format
	}{
		{"arch", "rolling", platform.BackendPacman, packaging.FormatArch},
		{"omarchy", "4.0.4", platform.BackendPacman, packaging.FormatArch},
		{"ubuntu", "24.04", platform.BackendAPT, packaging.FormatDEB},
		{"linuxmint", "22.3", platform.BackendAPT, packaging.FormatDEB},
		{"debian", "13", platform.BackendAPT, packaging.FormatDEB},
		{"fedora", "44", platform.BackendDNF5, packaging.FormatRPM},
		{"rhel", "9.6", platform.BackendDNF4, packaging.FormatRPM},
		{"rocky", "10.0", platform.BackendDNF4, packaging.FormatRPM},
		{"almalinux", "8.10", platform.BackendDNF4, packaging.FormatRPM},
		{"opensuse-leap", "16.0", platform.BackendZypper, packaging.FormatRPM},
		{"opensuse-tumbleweed", "20260901", platform.BackendZypper, packaging.FormatRPM},
	} {
		t.Run(tc.id, func(t *testing.T) {
			release := platform.ForManifest(tc.id, tc.version)
			backend, err := nativeBackend(release)
			if err != nil || backend != tc.backend {
				t.Fatalf("native backend = %v, %v; want %v", backend, err, tc.backend)
			}
			format, err := NativePackageFormat(release)
			if err != nil || format != tc.format {
				t.Fatalf("native artifact format = %q, %v; want %q", format, err, tc.format)
			}
		})
	}
}

func TestNativeDistributionRejectsAliasesAndImmutableDerivatives(t *testing.T) {
	for _, id := range []string{"", "unknown", "Debian", "alma", "opensuse", "suse", "opensuse-microos", "opensuse-aeon", "fedora-coreos", "nixos"} {
		t.Run(id, func(t *testing.T) {
			release := platform.ForManifest(id, "1")
			if backend, err := nativeBackend(release); err == nil || backend != platform.BackendNone {
				t.Fatalf("unsupported distribution selected mutable backend: %v, %v", backend, err)
			}
			if format, err := NativePackageFormat(release); err == nil || format != "" {
				t.Fatalf("unsupported distribution selected native artifact: %q, %v", format, err)
			}
		})
	}
	if _, err := nativeBackend(platform.Identify(platform.OSRelease{ID: "fedora", VersionID: "44", VariantID: "silverblue"})); err == nil {
		t.Fatal("image-based Fedora Atomic selected a mutable backend")
	}
}

func TestSUSEOracleKeepsRPMIdentity(t *testing.T) {
	for _, id := range []string{"opensuse-leap", "opensuse-tumbleweed"} {
		t.Run(id, func(t *testing.T) {
			truth, actual := vmTestObservation()
			truth.host[0] = id
			actual.Host.OsId.Value = id
			if err := compareVMObservation(truth, actual); err != nil {
				t.Fatalf("RPM package identity rejected for SUSE: %v", err)
			}
			actual.Packages.Backend = "zypper"
			actual.Packages.Packages[0].Manager = "zypper"
			if err := compareVMObservation(truth, actual); err == nil {
				t.Fatal("frontend zypper accepted as canonical RPM package identity")
			}
		})
	}
	before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
	before.Backends.Rpm.Value, before.Backends.Zypper.Value = true, true
	after.Backends.Rpm.Value, after.Backends.Zypper.Value = true, true
	actual.Backends.Rpm.Value, actual.Backends.Zypper.Value = true, true
	if err := compareVMDetails(platform.ForManifest("opensuse-leap", "16.0"), "x86_64", before, after, actual); err != nil {
		t.Fatalf("independent RPM and zypper presence rejected: %v", err)
	}
	actual.Backends.Zypper.Value = false
	if err := compareVMDetails(platform.ForManifest("opensuse-leap", "16.0"), "x86_64", before, after, actual); err == nil {
		t.Fatal("missing zypper backend accepted when RPM was present")
	}
}
