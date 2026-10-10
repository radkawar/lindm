//go:build linux

package inventory

import (
	"context"
	"io"
	"strings"
	"testing"
	"testing/fstest"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestMutableDistributionPackageManagerIdentity(t *testing.T) {
	for _, tc := range []struct {
		id, version, database, manager, input string
	}{
		{"debian", "13", "var/lib/dpkg/status", "dpkg", "ii \tlindm-agent\t0.1.0\tamd64\tlindm-agent\t0.1.0\n"},
		{"rocky", "9.6", "var/lib/rpm/rpmdb.sqlite", "rpm", "lindm-agent\t0\t0.1.0\t1\tx86_64\t(none)\n"},
		{"almalinux", "9.6", "var/lib/rpm/rpmdb.sqlite", "rpm", "lindm-agent\t0\t0.1.0\t1\tx86_64\t(none)\n"},
		{"opensuse-leap", "15.6", "var/lib/rpm/Packages", "rpm", "lindm-agent\t0\t0.1.0\t1\tx86_64\t(none)\n"},
		// Leap 16.0 Build18.75 images ship only the ndb Index.db/Packages.db pair.
		{"opensuse-leap", "16.0", "usr/lib/sysimage/rpm/Packages.db", "rpm", "lindm-agent\t0\t0.1.0\t1\taarch64\t(none)\n"},
		{"opensuse-tumbleweed", "20261001", "usr/lib/sysimage/rpm/rpmdb.sqlite", "rpm", "lindm-agent\t0\t0.1.0\t1\tx86_64\t(none)\n"},
	} {
		t.Run(tc.id+"-"+tc.version, func(t *testing.T) {
			stat := fixtureStat(fstest.MapFS{tc.database: {Data: []byte("database fixture")}})
			run := func(ctx context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
				if selected.name != tc.manager {
					t.Fatalf("selected %q, want canonical manager %q", selected.name, tc.manager)
				}
				return consume(strings.NewReader(tc.input))
			}
			got := collectPackages(t.Context(), map[string]string{"ID": tc.id, "VERSION_ID": tc.version}, stat, run)
			if got.Status != success || got.Backend != tc.manager || len(got.Packages) != 1 || got.Packages[0].Manager != tc.manager {
				t.Fatalf("lost native manager identity: %v", got)
			}
		})
	}
}

func TestSUSEReportsZypperAndRPMIndependently(t *testing.T) {
	for _, withZypper := range []bool{false, true} {
		files := fstest.MapFS{"usr/bin/rpm": {Mode: 0755}}
		if withZypper {
			files["usr/bin/zypper"] = &fstest.MapFile{Mode: 0755}
		}
		got := collectBackends(t.Context(), detailSources{stat: fixtureStat(files)})
		if got.Rpm.Status != success || !got.Rpm.Value || got.Zypper.Status != success || got.Zypper.Value != withZypper {
			t.Fatalf("backend tools conflated (zypper=%t): %v", withZypper, got)
		}
	}
}
