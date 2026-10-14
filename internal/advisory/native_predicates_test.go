// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/advisorydb"
)

func TestNativeProductPredicateRequiresInstalledRelease(t *testing.T) {
	for _, test := range []struct {
		version, manager string
		want             bool
	}{
		{"0:20261007-1.1", "rpm", true},
		{"0:20210101-0", "rpm", true},
		{"0:20201231-1.1", "rpm", false},
		{"0:20261007-1.1", "pacman", false},
		{"invalid epoch:1", "rpm", false},
	} {
		got := nativeProductPredicate([]advisorydb.AdvisoryNativeInstancesRow{{Manager: test.manager, Version: test.version, Architecture: "x86_64"}}, "0:20210101-0")
		if got.applies != test.want {
			t.Errorf("%+v: %+v", test, got)
		}
	}
	if got := nativeProductPredicate(nil, "0:20210101-0"); got.applies || got.reason == "" {
		t.Fatalf("missing release package became applicable: %+v", got)
	}
}

func TestOVALAllInstancesDoesNotBecomeAnyInstance(t *testing.T) {
	record := &advisoryv1.Advisory{FixedVersion: "0:7.0.11-1.1", InstanceArchitectures: []string{"aarch64", "x86_64"}}
	old := advisorydb.AdvisoryNativeInstancesRow{Manager: "rpm", Version: "0:7.0.10-1.1", Architecture: "x86_64"}
	for _, test := range []struct {
		name string
		rows []advisorydb.AdvisoryNativeInstancesRow
		want bool
	}{
		{"old-only", []advisorydb.AdvisoryNativeInstancesRow{old}, true},
		{"old-and-fixed", []advisorydb.AdvisoryNativeInstancesRow{old, {Manager: "rpm", Version: record.FixedVersion, Architecture: "x86_64"}}, false},
		{"other-architecture-fixed", []advisorydb.AdvisoryNativeInstancesRow{old, {Manager: "rpm", Version: record.FixedVersion, Architecture: "aarch64"}}, false},
		{"outside-architecture-predicate", []advisorydb.AdvisoryNativeInstancesRow{old, {Manager: "rpm", Version: old.Version, Architecture: "i586"}}, false},
		{"missing", nil, false},
		{"bounded", make([]advisorydb.AdvisoryNativeInstancesRow, 1025), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := nativeAllPredicate(test.rows, record); got.applies != test.want {
				t.Fatalf("all-instance result=%+v want=%v", got, test.want)
			}
		})
	}
}
