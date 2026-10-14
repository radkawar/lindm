// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"fmt"
	"syscall"

	"buf.build/go/protovalidate"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

// HostRelease reads the os-release identity (ID, VERSION_ID, VARIANT_ID) with
// the strict inventory parser, for callers that must identify the registry
// row including image-based variants.
func HostRelease(ctx context.Context) (platform.OSRelease, error) {
	release, err := loadOSRelease(ctx, readHostFile)
	if err != nil {
		return platform.OSRelease{}, fmt.Errorf("read os-release: %w", err)
	}
	return platform.OSRelease{ID: release["ID"], VersionID: release["VERSION_ID"], VariantID: release["VARIANT_ID"]}, nil
}

// HostPlatform reports the native product identity used in resource evidence.
// It does not certify any backend or requested operation. A missing VERSION_ID
// remains empty, as on rolling distributions; it is never replaced by ID_LIKE,
// a build identifier, the kernel version, or a guessed release.
func HostPlatform(ctx context.Context) (*resourcev1.PlatformProduct, error) {
	return hostPlatform(ctx, readHostFile, func() (string, error) {
		var uts syscall.Utsname
		if err := syscall.Uname(&uts); err != nil {
			return "", err
		}
		return utsString(uts.Machine[:]), nil
	})
}

func hostPlatform(ctx context.Context, readFile func(string) ([]byte, error), architecture func() (string, error)) (*resourcev1.PlatformProduct, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release, err := loadOSRelease(ctx, readFile)
	if err != nil {
		return nil, fmt.Errorf("observe resource platform: %w", err)
	}
	machine, err := architecture()
	if err != nil {
		return nil, fmt.Errorf("observe resource architecture: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	platform := &resourcev1.PlatformProduct{
		OsId: release["ID"], Product: release["NAME"],
		Version: release["VERSION_ID"], Architecture: machine,
	}
	if err := protovalidate.Validate(platform); err != nil {
		return nil, fmt.Errorf("validate resource platform observation: %w", err)
	}
	return platform, nil
}
