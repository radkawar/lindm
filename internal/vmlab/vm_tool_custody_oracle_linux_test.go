// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import "testing"

func TestTruthToolCustodyNamesTheFirstUnprotectedAncestor(t *testing.T) {
	for _, tc := range []struct {
		name, stat, path string
		uid, mode        uint32
		fails            bool
	}{
		{name: "protected", stat: "/ 0 555\n/usr 0 755\n/usr/bin 0 755\n/usr/sbin 0 755\n"},
		// Fedora Cloud Base 43-1.6 as coreutils stat %a prints it.
		{name: "fedora 43 cloud root", stat: "/ 0 775\n/usr 0 755\n/usr/bin 0 755\n", path: "/", mode: 0o775},
		{name: "foreign owner", stat: "/ 0 555\n/usr 0 755\n/usr/bin 1000 755\n", path: "/usr/bin", uid: 1000, mode: 0o755},
		{name: "sticky other-writable", stat: "/ 0 555\n/usr 0 755\n/usr/sbin 0 1777\n", path: "/usr/sbin", mode: 0o1777},
		{name: "missing /usr", stat: "/ 0 555\n", fails: true},
		{name: "non-octal mode", stat: "/ 0 555\n/usr 0 7a5\n", fails: true},
		{name: "truncated", stat: "/ 0 555\n/usr 0 755", fails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTruthToolCustody([]byte(tc.stat))
			if tc.fails {
				if err == nil {
					t.Fatalf("accepted %q: %v", tc.stat, got)
				}
				return
			}
			if err != nil || got.GetStatus() != truthSuccess || got.GetUnprotectedPath() != tc.path || got.GetOwnerUid() != tc.uid || got.GetMode() != tc.mode {
				t.Fatalf("custody = %v, %v", got, err)
			}
		})
	}
}
