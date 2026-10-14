// SPDX-License-Identifier: Apache-2.0

package custody

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestTrustedDirectory(t *testing.T) {
	for _, test := range []struct {
		name string
		mode uint32
		uid  uint32
		gid  uint32
		want bool
	}{
		{"root-private", unix.S_IFDIR | 0700, 0, 0, true},
		{"root-readable", unix.S_IFDIR | 0755, 0, 1000, true},
		{"vendor-root-group-writable", unix.S_IFDIR | 0775, 0, 0, true},
		{"untrusted-group-writable", unix.S_IFDIR | 0775, 0, 1000, false},
		{"world-writable", unix.S_IFDIR | 0777, 0, 0, false},
		{"sticky-world-writable", unix.S_IFDIR | unix.S_ISVTX | 0777, 0, 0, false},
		{"non-root-owner", unix.S_IFDIR | 0755, 1000, 0, false},
		{"symlink", unix.S_IFLNK | 0777, 0, 0, false},
		{"symlink-protected-mode", unix.S_IFLNK | 0755, 0, 0, false},
		{"regular-file", unix.S_IFREG | 0755, 0, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stat := unix.Stat_t{Mode: test.mode, Uid: test.uid, Gid: test.gid}
			if got := TrustedDirectory(&stat); got != test.want {
				t.Fatalf("TrustedDirectory(mode=%#o uid=%d gid=%d) = %t, want %t", test.mode, test.uid, test.gid, got, test.want)
			}
		})
	}
}
