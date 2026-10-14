// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import "testing"

// Tumbleweed Snapshot20261007 dispatch recorded SELinux "not applicable" while
// its guest booted with /sys/fs/selinux/enforce = 1 and no getenforce binary.
func TestSELinuxModeFromKernelEnforceState(t *testing.T) {
	for _, test := range []struct{ value, want string }{
		{"1\n", "Enforcing"},
		{"0", "Permissive"},
		{"absent", "Disabled"},
	} {
		got, err := selinuxModeFromEnforce(test.value)
		if err != nil || got != test.want {
			t.Fatalf("selinuxModeFromEnforce(%q) = %q, %v; want %q", test.value, got, err, test.want)
		}
	}
	for _, invalid := range []string{"", "2", "Enforcing", "1\n0\n"} {
		if _, err := selinuxModeFromEnforce(invalid); err == nil {
			t.Fatalf("accepted SELinux enforce state %q", invalid)
		}
	}
}
