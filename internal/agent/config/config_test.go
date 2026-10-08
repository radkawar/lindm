//go:build linux

package config

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestConfigRejectsReplaceableParentAndHardlink(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	if err := os.Mkdir(parent, 0777); err != nil {
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
