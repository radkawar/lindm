// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

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
		if rpm := source.GetRepository().GetRpm(); rpm != nil && !rpm.GetRequireMetadataSignature() {
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

// ErrUnsignedMetadata reports an RPM source whose unsigned metadata is not
// authenticated by a metalink the running release pins.
var ErrUnsignedMetadata = errors.New("unsigned_repository_metadata")

// RPMMetadataTrusted reports whether an RPM source's metadata is
// authenticated: signed metadata, or (registry decision for vendors that sign
// no metadata) every repository located by an HTTPS metalink on a host the
// release pins. A plain base URL without signed metadata is never trusted.
// Package signatures are required either way.
func RPMMetadataTrusted(release *platform.Release, rpm *resourcev1.RpmRepository) bool {
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
