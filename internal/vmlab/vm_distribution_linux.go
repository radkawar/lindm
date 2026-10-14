// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"errors"
	"fmt"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// manifestRelease is the registry row a lab image manifest boots.
func manifestRelease(manifest *labv1.ImageManifest) *platform.Release {
	return platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
}

// nativeScript prefixes a lab guest script with the registry's native base
// identity, so a derivative (its own os-release ID) runs the base release's
// branch of the script's os-release switch. Scripts read the identity right
// after sourcing os-release; a release without a base keeps its own.
func (v *guestVM) nativeScript(script string) (string, error) {
	identity, err := nativeScriptIdentity(v.release)
	if err != nil {
		return "", err
	}
	return identity + script, nil
}

// nativeScriptIdentity is the shell assignment of the base identity for a
// derivative and empty for a release without a base. A rolling base without
// VERSION_ID (Arch for Omarchy) assigns an empty, never invented, version.
// Lab scripts never select behavior from ID_LIKE.
func nativeScriptIdentity(release *platform.Release) (string, error) {
	if release == nil || !release.Known() {
		return "", errors.New("lab guest scripts require a registry release")
	}
	native := release.Native()
	if native == release {
		return "", nil
	}
	version := ""
	switch native.Version.Rule {
	case platform.VersionExact:
		version = native.Version.Value
	case platform.VersionAbsent:
	default:
		return "", fmt.Errorf("%s base %s has no exact version identity", release.Name, native.Name)
	}
	return "LINDM_NATIVE_ID=" + nativeQuote(native.ID) + "\nLINDM_NATIVE_VERSION=" + nativeQuote(version) + "\n", nil
}

// nativeOSRelease sources os-release and applies the lab's native identity.
// A set but empty LINDM_NATIVE_VERSION is the base's absent VERSION_ID.
const nativeOSRelease = `. /etc/os-release
ID=${LINDM_NATIVE_ID:-$ID} VERSION_ID=${LINDM_NATIVE_VERSION-${VERSION_ID-}}`

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
