// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/inventory"
	"lindm/internal/platform"
)

// resolvePackageProvider uses the same custody boundary as executor configuration.
// The provider must recheck the exact key digest when staging an isolated native
// repository; this startup observation never authorizes a later replacement key.
func resolvePackageProvider(base string, cfg *agentv1.NativePackageProviderConfig, rootOwner bool) error {
	var release *platform.Release
	for _, source := range cfg.GetSources() {
		if rpm := source.GetRepository().GetRpm(); rpm != nil && (!rpm.GetRequireMetadataSignature() || HasEntitledLocation(rpm)) {
			if release == nil {
				identity, err := inventory.HostRelease(context.Background())
				if err != nil {
					return err
				}
				release = platform.Identify(identity)
			}
			if !RPMMetadataTrusted(release, rpm) {
				return fmt.Errorf("%w: approved package repository %s is outside the release's pinned HTTPS metalinks", ErrUnsignedMetadata, source.GetRepository().GetRepositoryId())
			}
		}
		if HasEntitledLocation(source.GetRepository().GetRpm()) {
			if err := CheckEntitledSource(release, source); err != nil {
				return err
			}
		}
		path := resolve(base, source.GetSigningKeyFile())
		key, err := readConfig(path, rootOwner)
		if err != nil {
			return fmt.Errorf("read approved package signing key: %w", err)
		}
		digest := sha256.Sum256(key)
		if !bytes.Equal(digest[:], source.GetSigningKeySha256()) {
			return fmt.Errorf("approved package signing key digest mismatch for repository %s", source.GetRepository().GetRepositoryId())
		}
		source.SigningKeyFile = path
	}
	return nil
}

// ErrUnsignedMetadata reports a source outside the running release's pinned
// metadata trust contract (HTTPS metalinks or device-local entitled CDN TLS).
var ErrUnsignedMetadata = errors.New("unsigned_repository_metadata")

// RPMMetadataTrusted admits signed metadata, pinned HTTPS metalinks, or exact
// registry-approved RHSM IDs. RHSM definitions and credentials are additionally
// checked locally before staging; this marker alone never authorizes an endpoint.
// Package signatures remain mandatory.
func RPMMetadataTrusted(release *platform.Release, rpm *resourcev1.RpmRepository) bool {
	if HasEntitledLocation(rpm) {
		_, _, ok := EntitledVendor(release, rpm)
		return ok
	}
	if rpm.GetRequireMetadataSignature() {
		return true
	}
	metalinks := []string{rpm.GetMetalink()}
	for _, additional := range rpm.GetAdditionalRepositories() {
		metalinks = append(metalinks, additional.GetMetalink())
	}
	for _, metalink := range metalinks {
		if metalink == "" {
			return false
		}
	}
	return release.UnsignedMetadataAllowed(metalinks)
}

// HasEntitledLocation detects even a mixed source, so a signed-metadata flag
// cannot bypass the device-local source checks.
func HasEntitledLocation(rpm *resourcev1.RpmRepository) bool {
	if rpm.GetRhsmManaged() {
		return true
	}
	for _, repository := range rpm.GetAdditionalRepositories() {
		if repository.GetRhsmManaged() {
			return true
		}
	}
	return false
}

// EntitledVendor admits only the release registry's exact architecture IDs.
func EntitledVendor(release *platform.Release, rpm *resourcev1.RpmRepository) (platform.VendorRepository, string, bool) {
	if !rpm.GetRhsmManaged() || rpm.GetRequireMetadataSignature() || !rpm.GetRequirePackageSignature() {
		return platform.VendorRepository{}, "", false
	}
	ids := []string{rpm.GetNativeId()}
	for _, repository := range rpm.GetAdditionalRepositories() {
		if !repository.GetRhsmManaged() {
			return platform.VendorRepository{}, "", false
		}
		ids = append(ids, repository.GetNativeId())
	}
	return release.EntitledRepository(ids)
}

// CheckEntitledSource prevents local configuration from substituting a key,
// signer or repository identity for a registry-derived entitled source.
func CheckEntitledSource(release *platform.Release, source *agentv1.NativePackageSource) error {
	vendor, architecture, ok := EntitledVendor(release, source.GetRepository().GetRpm())
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return err
	}
	if !ok || architecture != unix.ByteSliceToString(uts.Machine[:]) || source.GetRepository().GetRepositoryId() != vendor.RepositoryID || source.GetSigningKeyFile() != vendor.KeyFile || source.GetRpmSigningKeyFingerprint() != vendor.RPMFingerprint {
		return ErrUnsignedMetadata
	}
	return nil
}
