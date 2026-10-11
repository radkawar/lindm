//go:build linux

package packageprovider

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func rootPackageFixtureDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("native custody requires root")
	}
	// /tmp is deliberately not root-protected ancestry.
	root, err := os.MkdirTemp("/run", "lindm-packageprovider-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	return root
}

func TestALPMIncludeInputsInvalidatePreparedPolicy(t *testing.T) {
	directory := rootPackageFixtureDirectory(t)
	path := filepath.Join(directory, "options")
	if err := os.WriteFile(path, []byte("IgnorePkg = unrelated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := []byte("[options]\nInclude = " + path + "\n")
	prepared, err := alpmPolicyInputs(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{"IgnorePkg = proof\n", "IgnoreGroup = protected\n", "HoldPkg = proof\n"} {
		if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
			t.Fatal(err)
		}
		current, err := alpmPolicyInputs(config)
		if err != nil || prepared == current {
			t.Fatalf("included hold change not bound: %v", err)
		}
	}
	if err := os.WriteFile(path, []byte("Include = "+path+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := alpmPolicyInputs(config); err == nil {
		t.Fatal("cyclic native includes accepted")
	}
}

func TestALPMRetainedLockIdentityExcludesCompetingLockAndReplacement(t *testing.T) {
	directory := rootPackageFixtureDirectory(t)
	path := filepath.Join(directory, "db.lck")
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(int(lock.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	guard := (alpmAdapterReply{State: "ready", Device: stat.Dev, Inode: stat.Ino}).lockGuard(directory)
	if err := guard(); err != nil {
		t.Fatal(err)
	}
	// This is libalpm's O_EXCL lock primitive, not a lindm-only flock. A native
	// pacman barrier acceptance is still required in the disposable VM lane.
	competing, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if competing != nil {
		_ = competing.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("competing native lock admitted: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := guard(); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement lock inherited permit: %v", err)
	}
}

func TestALPMAuthorityProtocolRejectsTruncationAndUnknownFields(t *testing.T) {
	var valid bytes.Buffer
	if err := sendALPMRequest(&valid, alpmAdapterReply{State: "ready", Device: 1, Inode: 2}); err != nil {
		t.Fatal(err)
	}
	data := valid.Bytes()
	if _, err := readALPMReply(bytes.NewReader(data), "ready"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{data[:3], data[:len(data)-1], {0, 0, 0, 0}, {0, 0x20, 0, 0}} {
		if _, err := readALPMReply(bytes.NewReader(bad), "ready"); err == nil {
			t.Fatal("invalid native protocol frame accepted")
		}
	}
	if _, err := readALPMReply(bytes.NewReader(data), "committed"); err == nil {
		t.Fatal("readiness reused as commit receipt")
	}
	payload := []byte(`{"state":"ready","device":1,"inode":2,"extra":true}`)
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed, uint32(len(payload)))
	copy(framed[4:], payload)
	if _, err := readALPMReply(bytes.NewReader(framed), "ready"); err == nil {
		t.Fatal("unknown native protocol field accepted")
	}
}
