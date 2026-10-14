// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"errors"
	"fmt"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/platform"
)

// FeedBenchmarkSources returns maintained source configurations, not recorded
// data. SUSE is a real signed individual CSAF document: the current importer does
// not support a full SUSE ecosystem export. Debian and Arch use complete vendor
// JSON exports. Ubuntu, Fedora and RHEL reuse the acceptance source registry.
func FeedBenchmarkSources(families []string) (*configv1.AdvisoryConfig, error) {
	acceptance, err := acceptanceAdvisories()
	if err != nil {
		return nil, err
	}
	debian, ok := platform.Lookup("debian-12")
	if !ok {
		return nil, errors.New("benchmark Debian release is not registered")
	}
	sles, ok := platform.Lookup("sles-15")
	if !ok {
		return nil, errors.New("benchmark SLES release is not registered")
	}
	var arch *platform.Release
	for _, release := range platform.Releases() {
		if release.Family == platform.FamilyArch && release.Base == "" {
			arch = release
			break
		}
	}
	if arch == nil {
		return nil, errors.New("benchmark Arch release is not registered")
	}
	available := make(map[string]*advisoryv1.FeedSource, 6)
	for _, source := range acceptance.Feeds {
		available[source.Distro] = source
	}
	available[debian.ID] = &advisoryv1.FeedSource{Id: "benchmark-debian", Distro: debian.ID, Release: debian.Version.Value, Architecture: "amd64", Format: advisoryv1.FeedFormat_FEED_FORMAT_DEBIAN_TRACKER_JSON, Url: "https://security-tracker.debian.org/tracker/data/json", MaxAgeSeconds: 86400}
	available[string(platform.FamilySUSE)] = &advisoryv1.FeedSource{Id: "benchmark-suse", Distro: sles.ID, Release: "15.6", Architecture: "x86_64", Format: advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF, Url: "https://ftp.suse.com/pub/projects/security/csaf/suse-su-2024_2275-1.json", MaxAgeSeconds: 86400}
	available[arch.ID] = &advisoryv1.FeedSource{Id: "benchmark-arch", Distro: arch.ID, Release: "rolling", Architecture: "x86_64", Format: advisoryv1.FeedFormat_FEED_FORMAT_ARCH_JSON, Url: "https://security.archlinux.org/issues/all.json", MaxAgeSeconds: 86400}
	cfg := new(configv1.AdvisoryConfig)
	seen := make(map[string]bool)
	for _, family := range families {
		source, ok := available[family]
		if !ok || seen[family] {
			return nil, fmt.Errorf("unknown or duplicate feed family %q", family)
		}
		seen[family] = true
		cfg.Feeds = append(cfg.Feeds, source)
	}
	if len(cfg.Feeds) == 0 {
		return nil, errors.New("at least one feed family required")
	}
	return cfg, protovalidate.Validate(cfg)
}

// LoadFeedSources reads a strict protobuf JSON AdvisoryConfig with bounded size.
func LoadFeedSources(path string) (*configv1.AdvisoryConfig, error) {
	raw, err := readFeedReplayFile(path)
	if err != nil {
		return nil, err
	}
	cfg := new(configv1.AdvisoryConfig)
	if err := protojson.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(cfg); err != nil {
		return nil, err
	}
	if len(cfg.GetFeeds()) == 0 {
		return nil, errors.New("at least one feed source required")
	}
	return cfg, nil
}
