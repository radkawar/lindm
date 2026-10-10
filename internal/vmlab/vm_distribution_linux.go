//go:build linux

package vmlab

import (
	"fmt"

	"lindm/internal/packaging"
)

type nativeFamily uint8

const (
	familyAPT nativeFamily = iota + 1
	familyDNF
	familyZypper
	familyPacman
)

// nativeDistributionFamily uses the actual os-release ID, never ID_LIKE. In
// particular, immutable derivatives must not inherit a mutable transaction path.
func nativeDistributionFamily(distribution string) (nativeFamily, error) {
	switch distribution {
	case "arch":
		return familyPacman, nil
	case "ubuntu", "debian":
		return familyAPT, nil
	case "fedora", "rhel", "rocky", "almalinux":
		return familyDNF, nil
	case "opensuse-leap", "opensuse-tumbleweed":
		return familyZypper, nil
	default:
		return 0, fmt.Errorf("unsupported native distribution %q", distribution)
	}
}

// NativePackageFormat selects the native artifact format for a supported mutable
// distribution. Unknown and immutable distributions are rejected explicitly.
func NativePackageFormat(distribution string) (packaging.Format, error) {
	family, err := nativeDistributionFamily(distribution)
	if err != nil {
		return "", err
	}
	if family == familyAPT {
		return packaging.FormatDEB, nil
	}
	if family == familyPacman {
		return packaging.FormatArch, nil
	}
	return packaging.FormatRPM, nil
}
