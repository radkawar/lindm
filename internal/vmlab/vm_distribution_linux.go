//go:build linux

package vmlab

import (
	"fmt"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// manifestRelease is the registry row a lab image manifest boots.
func manifestRelease(manifest *labv1.ImageManifest) *platform.Release {
	return platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
}

// nativeBackend is the release's native package backend (its base's for a
// derivative). Unknown and image-based releases have none and are rejected, so
// immutable derivatives never inherit a mutable transaction path.
func nativeBackend(release *platform.Release) (platform.Backend, error) {
	backend := release.Native().Packages.Backend
	if backend == platform.BackendNone {
		return backend, fmt.Errorf("unsupported native distribution %s", release.Name)
	}
	return backend, nil
}

// NativePackageFormat selects the native artifact format for a supported
// mutable release.
func NativePackageFormat(release *platform.Release) (packaging.Format, error) {
	backend, err := nativeBackend(release)
	if err != nil {
		return "", err
	}
	return packaging.Format(backend.PackageFormat()), nil
}
