//go:build linux

package vmlab

import (
	"testing"

	"lindm/internal/packaging"
)

func TestNativeDistributionRouting(t *testing.T) {
	for _, tc := range []struct {
		id     string
		family nativeFamily
		format packaging.Format
	}{
		{"arch", familyPacman, packaging.FormatArch},
		{"ubuntu", familyAPT, packaging.FormatDEB},
		{"debian", familyAPT, packaging.FormatDEB},
		{"fedora", familyDNF, packaging.FormatRPM},
		{"rhel", familyDNF, packaging.FormatRPM},
		{"rocky", familyDNF, packaging.FormatRPM},
		{"almalinux", familyDNF, packaging.FormatRPM},
		{"opensuse-leap", familyZypper, packaging.FormatRPM},
		{"opensuse-tumbleweed", familyZypper, packaging.FormatRPM},
	} {
		t.Run(tc.id, func(t *testing.T) {
			family, err := nativeDistributionFamily(tc.id)
			if err != nil || family != tc.family {
				t.Fatalf("native family = %v, %v; want %v", family, err, tc.family)
			}
			format, err := NativePackageFormat(tc.id)
			if err != nil || format != tc.format {
				t.Fatalf("native artifact format = %q, %v; want %q", format, err, tc.format)
			}
		})
	}
}

func TestNativeDistributionRejectsAliasesAndImmutableDerivatives(t *testing.T) {
	for _, id := range []string{"", "unknown", "Debian", "alma", "opensuse", "suse", "opensuse-microos", "opensuse-aeon", "fedora-coreos", "nixos"} {
		t.Run(id, func(t *testing.T) {
			if family, err := nativeDistributionFamily(id); err == nil || family != 0 {
				t.Fatalf("unsupported distribution selected mutable family: %v, %v", family, err)
			}
			if format, err := NativePackageFormat(id); err == nil || format != "" {
				t.Fatalf("unsupported distribution selected native artifact: %q, %v", format, err)
			}
		})
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
	if err := compareVMDetails(before, after, actual); err != nil {
		t.Fatalf("independent RPM and zypper presence rejected: %v", err)
	}
	actual.Backends.Zypper.Value = false
	if err := compareVMDetails(before, after, actual); err == nil {
		t.Fatal("missing zypper backend accepted when RPM was present")
	}
}
