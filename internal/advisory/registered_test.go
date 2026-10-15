// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"testing"

	"buf.build/go/protovalidate"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/feed"
	"lindm/internal/platform"
)

func TestRegisteredSourcesPreserveExactProductAndExport(t *testing.T) {
	for _, test := range []struct {
		key, os, version, architecture, feedArchitecture, stream string
		format                                                   advisoryv1.FeedFormat
	}{
		{"ubuntu-24.04", "ubuntu", "24.04", "x86_64", "amd64", "", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP},
		{"rhel-9", "rhel", "9.8", "x86_64", "x86_64", "standard", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES},
	} {
		t.Run(test.key, func(t *testing.T) {
			sources, err := RegisteredSources(test.key, test.architecture, "auto")
			if err != nil || len(sources) != 1 {
				t.Fatalf("registered sources: %v %v", sources, err)
			}
			release, _ := platform.Lookup(test.key)
			export := release.Advisory.Exports[release.Advisory.Feeds[0]]
			source := sources[0]
			if source.GetDistro() != test.os || source.GetRelease() != release.FeedRelease(release.Version.Value) || source.GetArchitecture() != test.feedArchitecture || source.GetPlatformStream() != test.stream || source.GetUrl() != export.URL || source.GetFormat() != test.format || source.GetMaxAgeSeconds() != export.MaxAgeSeconds || source.GetMaxArchiveBytes() != export.MaxArchiveBytes {
				t.Fatalf("source broadened or changed maintained identity: %v", source)
			}
			if !feed.Applies(source, test.os, test.version, test.architecture) || feed.Applies(source, "rocky", test.version, test.architecture) || feed.Applies(source, test.os, test.version, "s390x") {
				t.Fatal("source applicability lost product/architecture boundary")
			}
			if err := protovalidate.Validate(source); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRegisteredSourcesRefuseUnknownDerivativePartialAndArchitecture(t *testing.T) {
	for _, key := range []string{"", "unregistered", "linuxmint-22.3", "popos-24.04", "rocky-9", "debian-13", "arch"} {
		if sources, err := RegisteredSources(key, "amd64", "auto"); err == nil || len(sources) != 0 {
			t.Fatalf("%s gained automatic complete coverage: %v", key, sources)
		}
	}
	if _, err := RegisteredSources("ubuntu-24.04", "riscv64", "auto"); err == nil {
		t.Fatal("unknown architecture acquired a vendor export")
	}
}
