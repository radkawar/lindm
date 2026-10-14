// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestConfigRejectsReplaceableParentAndHardlink(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	if err := os.Mkdir(parent, 0777); err != nil {
		t.Fatal(err)
	}
	// Mkdir applies the caller's umask; this fixture must remain replaceable.
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(parent, "agent.json")
	if err := os.WriteFile(file, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(file, false); err == nil {
		t.Fatal("accepted a group-writable configuration ancestor")
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(file, true); err == nil {
		t.Fatal("production loader accepted a non-root ancestor")
	}
	linked := filepath.Join(parent, "linked.json")
	if err := os.Link(file, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(file, false); err == nil {
		t.Fatal("accepted a hardlinked configuration file")
	}
}

func TestNetworkUserRejectsRootAndNumericNames(t *testing.T) {
	if _, _, _, err := resolveNetworkUser("root"); err == nil {
		t.Fatal("accepted root as the network account")
	}
	if _, _, _, err := resolveNetworkUser("0"); err == nil {
		t.Fatal("accepted a numeric uid as a username")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if current.Username == "root" || current.Username == "" {
		t.Fatal("test account cannot prove canonical lookup")
	}
	uid, _, name, err := resolveNetworkUser(current.Username)
	if err != nil {
		t.Fatal(err)
	}
	if name != current.Username || uid == 0 {
		t.Fatalf("lookup changed the account: %s %d", name, uid)
	}
}

func TestDistinctDirectoriesRejectNesting(t *testing.T) {
	if err := distinctDirectories("/var/lib/lindm/executor", "/run/lindm", "/var/lib/lindm/agent"); err != nil {
		t.Fatal(err)
	}
	if err := distinctDirectories("/var/lib/lindm/executor", "/run/lindm", "/var/lib/lindm/executor/spool"); err == nil {
		t.Fatal("accepted a spool nested in executor state")
	}
}

func TestRootConfigDirectoryCustody(t *testing.T) {
	for _, test := range []struct {
		name string
		mode uint32
		uid  uint32
		gid  uint32
		want bool
	}{
		{"vendor-root", unix.S_IFDIR | 0775, 0, 0, true},
		{"untrusted-group", unix.S_IFDIR | 0775, 0, 1000, false},
		{"world-writable", unix.S_IFDIR | 0777, 0, 0, false},
		{"untrusted-owner", unix.S_IFDIR | 0755, 1000, 0, false},
		{"symlink", unix.S_IFLNK | 0755, 0, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := trustedConfigAncestor(unix.Stat_t{Mode: test.mode, Uid: test.uid, Gid: test.gid}, true)
			if (err == nil) != test.want {
				t.Fatalf("root configuration custody: got %v, want trusted=%t", err, test.want)
			}
		})
	}
}

func TestNetworkGroupsRejectRootMembership(t *testing.T) {
	for _, test := range []struct {
		name    string
		primary string
		groups  []string
		want    bool
	}{
		{"ordinary", "1000", []string{"1000", "1001"}, true},
		{"no-supplemental", "1000", nil, true},
		{"primary-root", "0", []string{"1000"}, false},
		{"supplemental-root", "1000", []string{"1000", "0"}, false},
		{"noncanonical-primary", "01000", nil, false},
		{"invalid-supplemental", "1000", []string{"invalid"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			gid, err := networkGroups(test.primary, test.groups)
			if (err == nil) != test.want || (test.want && gid != 1000) {
				t.Fatalf("network groups = %d, %v; want accepted=%t", gid, err, test.want)
			}
		})
	}
}
