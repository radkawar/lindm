//go:build linux

package passwordprovider

import (
	"context"
	"fmt"
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

// pinnedVersions returns the libpwquality, PAM modules and PAM manager
// releases qualified for the observed product.
func pinnedVersions(p *resourcev1.PlatformProduct) (platform.PasswordPins, bool) {
	release := platform.Of(p)
	if release.Gate(platform.Password) != nil {
		return platform.PasswordPins{}, false
	}
	return release.PasswordPins(p.GetVersion())
}

// authselectProduct reports products whose PAM stacks authselect owns.
func authselectProduct(p *resourcev1.PlatformProduct) bool {
	return platform.Of(p).Native().Quirks.PAMManager == platform.PAMManagerAuthselect
}
func nativePAMProduct(p *resourcev1.PlatformProduct) bool {
	return platform.Of(p).Native().Quirks.PAMManager == platform.PAMManagerNative
}
func pamConfigProduct(p *resourcev1.PlatformProduct) bool {
	return platform.Of(p).Native().Quirks.PAMManager == platform.PAMManagerPamConfig
}
func passwordBackend(p *resourcev1.PlatformProduct) resourcev1.Backend {
	switch platform.Of(p).Native().Quirks.PAMManager {
	case platform.PAMManagerAuthselect:
		return resourcev1.Backend_BACKEND_AUTHSELECT
	case platform.PAMManagerPamAuthUpdate:
		return resourcev1.Backend_BACKEND_PAM_AUTH_UPDATE
	case platform.PAMManagerPamConfig:
		return resourcev1.Backend_BACKEND_PAM_CONFIG
	case platform.PAMManagerNative:
		return resourcev1.Backend_BACKEND_NATIVE_PAM
	default:
		return resourcev1.Backend_BACKEND_UNSPECIFIED
	}
}

func modulePackageName(platform *resourcev1.PlatformProduct, feature agentv1.PasswordNativeFeature) string {
	if pamConfigProduct(platform) {
		if feature == 1 {
			return "pam_pwquality"
		}
		return "pam"
	}
	if authselectProduct(platform) || nativePAMProduct(platform) {
		if feature == 1 {
			return "libpwquality"
		}
		return "pam"
	}
	if feature == 1 {
		return "libpam-pwquality"
	}
	return "libpam-modules"
}
func packageVersion(ctx context.Context, product *resourcev1.PlatformProduct, name string, run commandRunner) (string, error) {
	switch name {
	case "authselect", "pam", "libpwquality", "libpwquality1", "libpam-runtime", "libpam-modules", "libpam-pwquality", "pam-config", "pam_pwquality", "pambase":
	default:
		return "", ErrUnsupported
	}
	var output []byte
	var err error
	db := platform.Of(product).Native().Packages.Backend.PackageDB()
	switch db {
	case platform.PackageDBRPM:
		output, err = run(ctx, "/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", name+"."+nativePackageArchitecture(product))
	case platform.PackageDBPacman:
		output, err = run(ctx, "/usr/bin/pacman", "-Q", name)
	case platform.PackageDBDpkg:
		query := name
		if name != "libpam-runtime" {
			query += ":" + nativePackageArchitecture(product)
		}
		output, err = run(ctx, "/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}\n", query)
	default:
		return "", ErrUnsupported
	}
	if err != nil {
		return "", err
	}
	version := strings.TrimSuffix(string(output), "\n")
	if db == platform.PackageDBDpkg {
		status, value, ok := strings.Cut(version, "\t")
		if !ok || (status != "ii " && status != "hi ") {
			return "", ErrUnsupported
		}
		version = value
	}
	if db == platform.PackageDBPacman {
		packageName, value, ok := strings.Cut(version, " ")
		if !ok || packageName != name {
			return "", ErrUnsupported
		}
		version = value
	}
	if version == "" || len(version) > 128 {
		return "", ErrUnsupported
	}
	for _, c := range version {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune(".+:~_-", c) {
			return "", ErrUnsupported
		}
	}
	return version, nil
}
func upstreamVersion(version string) string {
	if _, rest, ok := strings.Cut(version, ":"); ok {
		version = rest
	}
	before, _, _ := strings.Cut(version, "-")
	return before
}
func moduleVersionSupported(platform *resourcev1.PlatformProduct, feature agentv1.PasswordNativeFeature, version string) bool {
	pinned, ok := pinnedVersions(platform)
	if !ok || feature < 1 || feature > 3 {
		return false
	}
	// Rolling snapshots pin the complete native package release, not just
	// an upstream version shared by differently patched distribution builds.
	if nativePAMProduct(platform) || pamConfigProduct(platform) {
		if feature == 1 {
			return version == pinned.Quality
		}
		return version == pinned.PAM
	}
	if feature == 1 {
		return upstreamVersion(version) == pinned.Quality
	}
	return upstreamVersion(version) == pinned.PAM
}
func managerVersion(ctx context.Context, platform *resourcev1.PlatformProduct, run commandRunner) (string, error) {
	pinned, ok := pinnedVersions(platform)
	if !ok {
		return "", ErrUnsupported
	}
	name := "libpam-runtime"
	switch passwordBackend(platform) {
	case resourcev1.Backend_BACKEND_AUTHSELECT:
		name = "authselect"
	case resourcev1.Backend_BACKEND_NATIVE_PAM:
		name = "pambase"
	case resourcev1.Backend_BACKEND_PAM_CONFIG:
		name = "pam-config"
	}
	version, err := packageVersion(ctx, platform, name, run)
	if err != nil {
		return "", err
	}
	matches := upstreamVersion(version) == pinned.Manager
	if nativePAMProduct(platform) || pamConfigProduct(platform) {
		matches = version == pinned.Manager
	}
	if !matches {
		return "", fmt.Errorf("%w: unsupported PAM manager %s version", ErrUnsupported, name)
	}
	return version, nil
}
