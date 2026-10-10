//go:build linux

package passwordprovider

import (
	"context"
	"fmt"
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func modulePackageName(platform *resourcev1.PlatformProduct, feature agentv1.PasswordNativeFeature) string {
	if platform.GetOsId() == "fedora" {
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
	if platform.GetOsId() == "fedora" {
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
	if !productSupported(platform) || feature < 1 || feature > 3 {
		return false
	}
	upstream := upstreamVersion(version)
	if feature == 1 {
		return upstream == "1.4.5"
	}
	if platform.GetOsId() == "ubuntu" {
		return upstream == "1.5.3"
	}
	return platform.GetOsId() == "fedora" && upstream == "1.7.2"
}
func managerVersion(ctx context.Context, platform *resourcev1.PlatformProduct, run commandRunner) (string, error) {
	name := "authselect"
	if platform.GetOsId() == "ubuntu" {
		name = "libpam-runtime"
	}
	version, err := packageVersion(ctx, platform, name, run)
	if err != nil {
		return "", err
	}
	if platform.GetOsId() == "ubuntu" && upstreamVersion(version) != "1.5.3" {
		return "", fmt.Errorf("%w: unsupported PAM manager version", ErrUnsupported)
	}
	if platform.GetOsId() == "fedora" && upstreamVersion(version) != "1.7.1" {
		return "", fmt.Errorf("%w: unsupported authselect manager version", ErrUnsupported)
	}
	return version, nil
}
