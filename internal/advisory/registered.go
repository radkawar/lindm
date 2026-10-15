// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"crypto/sha256"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/platform"
)

// RegisteredSources constructs complete maintained exports for this exact product.
// Derivatives never borrow a base feed here; explicit origin-aware coverage stays
// in the normal matcher. All vendor locations and limits belong to the registry.
func RegisteredSources(key, architecture, prefix string) ([]*advisoryv1.FeedSource, error) {
	release, ok := platform.Lookup(key)
	if !ok || release.Native() != release || !release.Supported(platform.Advisories) || release.Advisory.Partial != "" || release.Advisory.Ecosystem == "" || len(release.Advisory.Feeds) == 0 {
		return nil, fmt.Errorf("advisory: no complete maintained export for %s", key)
	}
	native := architecture
	switch architecture {
	case "amd64", "x86_64":
		native, architecture = "x86_64", "amd64"
	case "arm64", "aarch64":
		native, architecture = "aarch64", "arm64"
	}
	if !slices.Contains(release.Architectures, native) {
		return nil, fmt.Errorf("advisory: unsupported architecture %q for %s", architecture, key)
	}
	if release.Packages.Backend != platform.BackendAPT {
		architecture = native
	}
	sources := make([]*advisoryv1.FeedSource, 0, len(release.Advisory.Feeds))
	for _, kind := range release.Advisory.Feeds {
		export, ok := release.Advisory.Exports[kind]
		if !ok {
			continue
		}
		url := export.URL
		if len(export.ArchitectureURLs) != 0 {
			url = export.ArchitectureURLs[native]
		}
		if url == "" || export.MaxAgeSeconds == 0 {
			return nil, fmt.Errorf("advisory: no maintained %s export for %s", kind, key)
		}
		var format advisoryv1.FeedFormat
		switch export.Format {
		case "osv-zip":
			format = advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP
		case "rpm-repomd":
			format = advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD
		case "redhat-csaf-archives":
			format = advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES
		default:
			return nil, fmt.Errorf("advisory: unsupported maintained format %q", export.Format)
		}
		source := &advisoryv1.FeedSource{
			Id:     prefix + "-" + key + "-" + architecture + "-" + string(kind),
			Distro: release.ID, Release: release.FeedRelease(release.Version.Value),
			Architecture: architecture, Url: url, Format: format,
			MaxAgeSeconds: export.MaxAgeSeconds, PlatformStream: export.PlatformStream,
		}
		if export.MaxArchiveBytes != 0 {
			source.MaxArchiveBytes = proto.Uint64(export.MaxArchiveBytes)
		}
		sources = append(sources, source)
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("advisory: no maintained exports for %s", key)
	}
	return sources, nil
}

// automaticProjectionRegistryRevision invalidates only derived observation work
// when maintained export facts change. It is not feed authority. The policy
// discriminator must change when native eligibility/stream semantics change.
func automaticProjectionRegistryRevision() ([]byte, []string, error) {
	config := new(configv1.AdvisoryConfig)
	var streamIDs []string
	for _, release := range platform.Releases() {
		for _, architecture := range release.Architectures {
			sources, err := RegisteredSources(release.Key, architecture, "auto")
			if err != nil {
				continue
			}
			config.Feeds = append(config.Feeds, sources...)
			if release.Advisory.PlatformStreams && !slices.Contains(streamIDs, release.ID) {
				streamIDs = append(streamIDs, release.ID)
			}
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.MarshalAppend([]byte("automatic-native-identity-v3\x00"), config)
	if err != nil {
		return nil, nil, err
	}
	revision := sha256.Sum256(encoded)
	return revision[:], streamIDs, nil
}
