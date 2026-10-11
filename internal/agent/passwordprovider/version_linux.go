//go:build linux

package passwordprovider

import (
	"context"
	"fmt"
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// nativeVersions are the exact upstream releases qualified for one product:
// libpwquality, the PAM modules package and the PAM manager.
type nativeVersions struct{ quality, pam, manager string }

func pinnedVersions(p *resourcev1.PlatformProduct) (nativeVersions, bool) {
	switch {
	case p.GetOsId() == "ubuntu" && p.GetVersion() == "24.04":
		return nativeVersions{quality: "1.4.5", pam: "1.5.3", manager: "1.5.3"}, true
	case p.GetOsId() == "fedora" && p.GetVersion() == "44":
		return nativeVersions{quality: "1.4.5", pam: "1.7.2", manager: "1.7.1"}, true
	case (p.GetOsId() == "rhel" || p.GetOsId() == "almalinux") && p.GetVersion() == "9.8":
		return nativeVersions{quality: "1.4.4", pam: "1.5.1", manager: "1.2.6"}, true
	case (p.GetOsId() == "rhel" || p.GetOsId() == "almalinux") && p.GetVersion() == "10.2":
		return nativeVersions{quality: "1.4.5", pam: "1.6.1", manager: "1.5.2"}, true
	default:
		return nativeVersions{}, false
	}
}

// authselectProduct reports RPM products whose PAM stacks authselect owns;
// the other qualified products use Debian's pam-auth-update.
func authselectProduct(p *resourcev1.PlatformProduct) bool {
	switch p.GetOsId() {
	case "fedora", "rhel", "almalinux":
		return true
	default:
		return false
	}
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
	if platform.GetOsId() == "ubuntu" {
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
		return upstreamVersion(version) == pinned.quality
	}
	return upstreamVersion(version) == pinned.pam
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
	if upstreamVersion(version) != pinned.manager {
		return "", fmt.Errorf("%w: unsupported PAM manager %s version", ErrUnsupported, name)
	}
	return version, nil
}
