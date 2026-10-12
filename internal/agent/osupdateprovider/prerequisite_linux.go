//go:build linux

package osupdateprovider

import (
	"fmt"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
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

// missingPackage returns the typed prerequisite with the native_tool_missing
// refusal detail; errors.As still finds the PrerequisiteError.
func missingPackage(platform *resourcev1.PlatformProduct, name string, cause error) error {
	ecosystem := resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM
	arch := "noarch"
	switch {
	case aptProduct(platform):
		// unattended-upgrades, needrestart and Ubuntu's reboot-signal package
		// update-notifier-common are Architecture: all.
		ecosystem, arch = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, "all"
	case name == "pacman":
		ecosystem, arch = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM, rpmArchitecture()
	case name == "dnf5" || name == "dnf5-plugin-automatic" || name == "dnf5-plugins" || name == "zypper":
		arch = rpmArchitecture()
	}
	return admissiondetail.Wrap(&PrerequisiteError{Package: &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: name, Architecture: arch}, Cause: cause}, "native_tool_missing")
}
