//go:build linux

package passwordprovider

import (
	"fmt"
	"runtime"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// PrerequisiteError identifies the native package that must be installed by a
// separately authorized package resource. Password policy never installs it.
type PrerequisiteError struct {
	Package *resourcev1.PackageIdentity
	Module  string
	Cause   error
}

func (e *PrerequisiteError) Error() string {
	return fmt.Sprintf("%v: %s (%s): %v", ErrMissingModule, e.Module, e.Package.GetNativeName(), e.Cause)
}
func (e *PrerequisiteError) Unwrap() []error { return []error{ErrMissingModule, e.Cause} }
func missingModule(platform *resourcev1.PlatformProduct, feature agentv1.PasswordNativeFeature, cause error) *PrerequisiteError {
	name := modulePackageName(platform, feature)
	ecosystem := resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB
	arch := nativePackageArchitecture(platform)
	if authselectProduct(platform) {
		ecosystem = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM
	}
	return &PrerequisiteError{Package: &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: name, Architecture: arch}, Module: moduleName(feature), Cause: cause}
}
func nativePackageArchitecture(platform *resourcev1.PlatformProduct) string {
	arch := runtime.GOARCH
	if authselectProduct(platform) {
		switch arch {
		case "amd64":
			return "x86_64"
		case "arm64":
			return "aarch64"
		}
	}
	return arch
}
