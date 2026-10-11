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

// authselectProduct reports products whose PAM stacks authselect owns; the
// other qualified products use Debian's pam-auth-update.
func authselectProduct(p *resourcev1.PlatformProduct) bool {
	return platform.Of(p).Native().Quirks.PAMManager == platform.PAMManagerAuthselect
}

func modulePackageName(platform *resourcev1.PlatformProduct, feature agentv1.PasswordNativeFeature) string {
	if authselectProduct(platform) {
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
func packageVersion(ctx context.Context, platform *resourcev1.PlatformProduct, name string, run commandRunner) (string, error) {
	switch name {
	case "authselect", "pam", "libpwquality", "libpam-runtime", "libpam-modules", "libpam-pwquality":
	default:
		return "", ErrUnsupported
	}
	var output []byte
	var err error
	if authselectProduct(platform) {
		output, err = run(ctx, "/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", name+"."+nativePackageArchitecture(platform))
	} else {
		query := name
		if name != "libpam-runtime" {
			query += ":" + nativePackageArchitecture(platform)
		}
		output, err = run(ctx, "/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}\n", query)
	}
	if err != nil {
		return "", err
	}
	version := strings.TrimSuffix(string(output), "\n")
	if !authselectProduct(platform) {
		status, value, ok := strings.Cut(version, "\t")
		if !ok || (status != "ii " && status != "hi ") {
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
	name := "authselect"
	if !authselectProduct(platform) {
		name = "libpam-runtime"
	}
	version, err := packageVersion(ctx, platform, name, run)
	if err != nil {
		return "", err
	}
	if upstreamVersion(version) != pinned.Manager {
		return "", fmt.Errorf("%w: unsupported PAM manager %s version", ErrUnsupported, name)
	}
	return version, nil
}
