//go:build linux

package osupdateprovider

import (
	"fmt"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// PrerequisiteError identifies the native automatic-update package that must
// be installed by a separately authorized package resource. The update policy
// never installs, removes or upgrades its own native tools.
type PrerequisiteError struct {
	Package *resourcev1.PackageIdentity
	Cause   error
}

func (e *PrerequisiteError) Error() string {
	return fmt.Sprintf("%v: %s: %v", ErrMissingPrerequisite, e.Package.GetNativeName(), e.Cause)
}
func (e *PrerequisiteError) Unwrap() []error { return []error{ErrMissingPrerequisite, e.Cause} }

func missingPackage(platform *resourcev1.PlatformProduct, name string, cause error) *PrerequisiteError {
	ecosystem := resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM
	arch := "noarch"
	switch {
	case aptProduct(platform):
		// unattended-upgrades and needrestart are Architecture: all.
		ecosystem, arch = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, "all"
	case name == "dnf5-plugin-automatic" || name == "dnf5-plugins":
		arch = rpmArchitecture()
	}
	return &PrerequisiteError{Package: &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: name, Architecture: arch}, Cause: cause}
}
