//go:build linux

package vmlab

import (
	"strings"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// The lane takes source/target identity and both vendor feeds from the
// registry; a release without a modelled path is refused with its gate.
func TestReleaseUpgradePathAndFeedsComeFromTheRegistry(t *testing.T) {
	for _, row := range platform.Releases() {
		if row.UpgradeTo == "" {
			continue
		}
		source, target, err := releaseUpgradePath(&labv1.ImageManifest{Distribution: row.ID, Version: row.Version.Value})
		if err != nil || source != row || target.Key != row.UpgradeTo {
			t.Fatalf("%s: path %v -> %v: %v", row.Key, source, target, err)
		}
		before, after := releaseUpgradeFeed(source, "arm64"), releaseUpgradeFeed(target, "arm64")
		if before.GetId() == after.GetId() || before.GetUrl() != after.GetUrl() || before.GetRelease() != source.Version.Value || after.GetRelease() != target.Version.Value || before.GetDistro() != source.ID || !strings.HasSuffix(before.GetUrl(), "/all.zip") {
			t.Fatalf("%s: feeds %v %v", row.Key, before, after)
		}
		// The target itself has no further modelled path unless the registry says so.
		if target.UpgradeTo == "" {
			if _, _, err := releaseUpgradePath(&labv1.ImageManifest{Distribution: target.ID, Version: target.Version.Value}); err == nil {
				t.Fatalf("%s: release without an upgrade path was admitted", target.Key)
			}
		}
	}
	if _, _, err := releaseUpgradePath(&labv1.ImageManifest{Distribution: "unregistered", Version: "1"}); err == nil {
		t.Fatal("unregistered release admitted")
	}
}

func TestReleaseUpgradeHostFacts(t *testing.T) {
	facts := "id=ubuntu\nversion_id=26.04\ncodename=resolute\nkernel=7.0.0-15-generic\ninstalled=812\n" +
		"package lindm-agent=0.1.0 installed\npackage sudo-rs=0.2.10-1ubuntu1 installed\ntool ls=ls (uutils coreutils) 0.2.2\n" +
		"unit lindm-executor.service=ActiveState=active ProtectSystem=strict \nunit lindm-executor.service.fragment=ab\n" +
		"unit lindm-agent.service=ActiveState=active \nunit lindm-agent.service.fragment=cd\n"
	host, err := parseReleaseUpgradeHost([]byte(facts))
	if err != nil {
		t.Fatal(err)
	}
	if host.VersionID != "26.04" || host.Codename != "resolute" || host.Packages["lindm-agent"] != "0.1.0 installed" || host.Tools["ls"] != "ls (uutils coreutils) 0.2.2" || host.Units["lindm-executor.service"] != "ActiveState=active ProtectSystem=strict " {
		t.Fatalf("parsed host facts: %+v", host)
	}
	for _, bad := range []string{facts + "stray line\n", facts + "unknown=1\n", strings.Replace(facts, "kernel=7.0.0-15-generic\n", "", 1)} {
		if _, err := parseReleaseUpgradeHost([]byte(bad)); err == nil {
			t.Fatalf("accepted malformed host facts %q", bad)
		}
	}
}
