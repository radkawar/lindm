// SPDX-License-Identifier: Apache-2.0

//go:build linux

package accountprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Tumbleweed's shadow keeps no /etc/gshadow (groupadd never creates one), so
// every local group and user resource failed with "no such file or
// directory". An absent group shadow is admitted and bound into the revision;
// a present one is still required to agree with /etc/group.
func TestLocalDatabaseAdmitsAbsentGroupShadow(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned account database fixtures require root")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "etc", name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("passwd", "root:x:0:0:root:/root:/bin/sh\n")
	write("group", "root:x:0:\nengineers:x:2000:root\n")
	write("shadow", "root:!:20000:0:99999:7:::\n")
	digest := func(_ string, data []byte) ([]byte, error) { sum := sha256.Sum256(data); return sum[:], nil }
	if _, err := rootRead(filepath.Join(root, "etc", "passwd")); errors.Is(err, ErrUnsafe) {
		t.Skip("custody needs a root-protected TMPDIR ancestry (not a sticky /tmp)")
	}
	absent, err := readDatabaseAt(root, digest)
	if err != nil || absent.shadowGroups || absent.groups["engineers"] == nil {
		t.Fatalf("absent gshadow: %+v %v", absent, err)
	}
	write("gshadow", "root:*::\nengineers:!::root\n")
	present, err := readDatabaseAt(root, digest)
	if err != nil || !present.shadowGroups || bytes.Equal(present.revision, absent.revision) {
		t.Fatalf("present gshadow: %v", err)
	}
	write("gshadow", "root:*::\nengineers:!:admin:root\n")
	if _, err := readDatabaseAt(root, digest); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("group administrator admitted: %v", err)
	}
}
