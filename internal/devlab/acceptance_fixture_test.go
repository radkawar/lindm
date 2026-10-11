package devlab

import (
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func TestAcceptanceAdvisoriesPreservesSourceContract(t *testing.T) {
	cfg, err := acceptanceAdvisories()
	if err != nil {
		t.Fatal(err)
	}
	if err := protovalidate.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	// Stable IDs retain published generations, and neither scheduled refresh
	// nor larger archive allowances may be enabled by the registry refactor.
	want := &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{
		{Id: "acceptance-ubuntu", Distro: "ubuntu", Release: "24.04", Architecture: "amd64", Url: "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip", Format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP, MaxAgeSeconds: 86400},
		{Id: "acceptance-fedora", Distro: "fedora", Release: "44", Architecture: "x86_64", Url: "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/repomd.xml", Format: advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD, MaxAgeSeconds: 86400},
		{Id: "acceptance-rhel", Distro: "rhel", Release: "9", Architecture: "x86_64", PlatformStream: "standard", Url: "https://security.access.redhat.com/data/csaf/v2/", Format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES, MaxAgeSeconds: 604800},
	}}
	if !proto.Equal(cfg, want) {
		t.Fatalf("acceptance feed behavior changed: got %v; want %v", cfg, want)
	}
}
