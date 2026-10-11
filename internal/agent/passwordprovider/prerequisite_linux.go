//go:build linux

package passwordprovider

import (
	"fmt"
	"runtime"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
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
func missingModule(product *resourcev1.PlatformProduct, feature agentv1.PasswordNativeFeature, cause error) *PrerequisiteError {
	name := modulePackageName(product, feature)
	ecosystem := resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB
	arch := nativePackageArchitecture(product)
	switch platform.Of(product).Native().Packages.Backend.PackageDB() {
	case platform.PackageDBRPM:
		ecosystem = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM
	case platform.PackageDBPacman:
		ecosystem = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM
	}
	return &PrerequisiteError{Package: &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: name, Architecture: arch}, Module: moduleName(feature), Cause: cause}
}
func nativePackageArchitecture(product *resourcev1.PlatformProduct) string {
	arch := runtime.GOARCH
	if platform.Of(product).Native().Packages.Backend.PackageDB() != platform.PackageDBDpkg {
		switch arch {
		case "amd64":
			return "x86_64"
		case "arm64":
			return "aarch64"
		}
	}
	return arch
}
