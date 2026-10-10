//go:build linux

package nativefile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func nativeFixture(t *testing.T) (string, *resourcev1.ResourceObservation) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root filesystem custody and leases")
	}
	dir, err := os.MkdirTemp("/var/lib", "lindm-nativefile-test-")
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skip("requires writable isolated root fixture directory")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "public-data")
	return path, &resourcev1.ResourceObservation{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: path}, Metadata: &resourcev1.ObservationMetadata{}}
}
func captureFixture(t *testing.T, path string, template *resourcev1.ResourceObservation) *agentv1.ResourceOwnershipSnapshot {
	t.Helper()
	snapshot, err := Capture(path, template)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
func targetFixture(t *testing.T, before *agentv1.ResourceOwnershipSnapshot, content string) *agentv1.ResourceOwnershipSnapshot {
	t.Helper()
	target := proto.CloneOf(before)
	o := target.Observation.GetManagedFile()
	o.Exists = true
	target.ManagedFileContent = []byte(content)
	if o.File == nil {
		o.File = &resourcev1.FileIdentity{Path: o.GetPath(), Mode: 0600}
	}
	digest := sha256.Sum256(target.ManagedFileContent)
	o.File.Sha256 = digest[:]
	if !before.GetObservation().GetManagedFile().GetExists() {
		if err := CreationMetadata(t.Context(), target); err != nil {
			t.Fatal(err)
		}
	}
	return target
}
func TestNativeAtomicReplacementPreservesXattrs(t *testing.T) {
	path, template := nativeFixture(t)
	if err := os.WriteFile(path, []byte("before"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(path, "user.lindm-test", []byte("must survive"), 0); errors.Is(err, unix.ENOTSUP) {
		t.Skip("filesystem has no user xattr support")
	} else if err != nil {
		t.Fatal(err)
	}
	before := captureFixture(t, path, template)
	target := targetFixture(t, before, "after")
	tx, err := Prepare(before, target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	calls := 0
	after, err := tx.Commit(t.Context(), func(context.Context) error {
		calls++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(data) != "before" {
			t.Error("effect preceded authority")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(after.GetManagedFileContent()) != "after" || after.GetObservation().GetManagedFile().GetFile().GetMode() != 0640 || bytes.Equal(after.GetObservation().GetManagedFile().GetNativeIdentitySha256(), before.GetObservation().GetManagedFile().GetNativeIdentitySha256()) || !bytes.Equal(after.GetObservation().GetManagedFile().GetSecurityMetadataSha256(), before.GetObservation().GetManagedFile().GetSecurityMetadataSha256()) {
		t.Fatal("atomic replacement lost identity or preserved metadata")
	}
	if _, err := tx.Commit(t.Context(), func(context.Context) error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatal("transaction committed twice")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("temporary sibling survived successful replacement")
	}
}
func TestNativeRejectsLinksAndUnsafeAncestry(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "parent-symlink", "writable-parent", "nonroot-parent", "directory", "fifo", "oversize", "special-mode"} {
		t.Run(kind, func(t *testing.T) {
			path, template := nativeFixture(t)
			parent := filepath.Dir(path)
			other := filepath.Join(parent, "original")
			if err := os.WriteFile(other, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(other, path); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				actual := filepath.Join(parent, "actual")
				if err := os.Mkdir(actual, 0700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(parent, "link")
				if err := os.Symlink(actual, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "child")
			case "writable-parent":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "nonroot-parent":
				if err := os.Chown(parent, 12345, 0); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxContent+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "special-mode":
				if err := os.WriteFile(path, []byte("code"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chmod(path, 04755); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Capture(path, template); err == nil {
				t.Fatal("unsafe file custody accepted")
			}
			data, err := os.ReadFile(other)
			if err != nil || string(data) != "untouched" {
				t.Fatal("unsafe observation changed another file")
			}
		})
	}
}
func TestNativeFinalGateCannotBypassSymlinkRace(t *testing.T) {
	path, template := nativeFixture(t)
	before := captureFixture(t, path, template)
	target := targetFixture(t, before, "managed")
	other := filepath.Join(filepath.Dir(path), "foreign")
	if err := os.WriteFile(other, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	tx, err := Prepare(before, target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	_, err = tx.Commit(t.Context(), func(context.Context) error { return os.Symlink(other, path) })
	if err == nil {
		t.Fatal("symlink introduced during permit exchange was followed")
	}
	data, err := os.ReadFile(other)
	if err != nil || string(data) != "foreign" {
		t.Fatal("foreign file overwritten")
	}
}
func TestNativeRetainsEntireAncestorCustody(t *testing.T) {
	path, template := nativeFixture(t)
	root := filepath.Dir(path)
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(parent, "data")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	before := captureFixture(t, path, template)
	target := targetFixture(t, before, "after")
	tx, err := Prepare(before, target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	_, err = tx.Commit(t.Context(), func(context.Context) error {
		if err := os.Rename(parent, parent+"-old"); err != nil {
			return err
		}
		return os.Mkdir(parent, 0700)
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("replaced ancestor accepted: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(parent+"-old", "data"))
	if err != nil || string(data) != "before" {
		t.Fatal("detached inode mutated")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement ancestry received a write")
	}
}
func TestNativeLeaseRejectsAlreadyOpenWriter(t *testing.T) {
	path, template := nativeFixture(t)
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	before := captureFixture(t, path, template)
	target := targetFixture(t, before, "after")
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	if tx, err := Prepare(before, target); !errors.Is(err, ErrConflict) {
		if tx != nil {
			_ = tx.Close()
		}
		t.Fatalf("active writer bypassed custody: %v", err)
	}
}
func TestNativeRejectsUnknownSecurityMetadataAndPathOverrides(t *testing.T) {
	path, template := nativeFixture(t)
	before := captureFixture(t, path, template)
	target := targetFixture(t, before, "after")
	for _, name := range []string{"security.capability", "security.ima", "system.posix_acl_access", "trusted.overlay.opaque"} {
		candidate := proto.CloneOf(target)
		candidate.ManagedFileXattrs = []*agentv1.NativeFileXattr{{Name: name, Value: []byte("untrusted")}}
		candidate.Observation.GetManagedFile().SecurityMetadataSha256 = XattrDigest(candidate.GetManagedFileXattrs())
		if tx, err := Prepare(before, candidate); err == nil {
			_ = tx.Close()
			t.Fatalf("unpreservable security metadata accepted: %s", name)
		}
	}
	candidate := proto.CloneOf(target)
	candidate.Observation.GetManagedFile().Path = path + "-override"
	candidate.Observation.GetManagedFile().File.Path = path + "-override"
	if tx, err := Prepare(before, candidate); err == nil {
		_ = tx.Close()
		t.Fatal("independent target path override accepted")
	}
}
func TestNativeRefusesInheritedACLBeforeEffect(t *testing.T) {
	path, template := nativeFixture(t)
	before := captureFixture(t, path, template)
	target := targetFixture(t, before, "after")
	// Linux POSIX ACL xattr v2: owner/group/other default entries. Even this
	// simple ACL must not silently disappear when replacing a public file.
	acl := make([]byte, 4+3*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, tag := range []uint16{1, 4, 32} {
		entry := acl[4+i*8:]
		binary.LittleEndian.PutUint16(entry, tag)
		binary.LittleEndian.PutUint16(entry[2:], 7)
		binary.LittleEndian.PutUint32(entry[4:], ^uint32(0))
	}
	if err := unix.Setxattr(filepath.Dir(path), "system.posix_acl_default", acl, 0); errors.Is(err, unix.ENOTSUP) {
		t.Skip("filesystem has no POSIX ACL support")
	} else if err != nil {
		t.Fatal(err)
	}
	if tx, err := Prepare(before, target); !errors.Is(err, ErrUnsupported) {
		if tx != nil {
			_ = tx.Close()
		}
		t.Fatalf("inherited ACL discarded: %v", err)
	}
}
func TestNativeCreateNeedsExistingParentAndCancellationPreservesData(t *testing.T) {
	path, template := nativeFixture(t)
	if _, err := Capture(filepath.Join(filepath.Dir(path), "missing", "data"), template); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent parent synthesized: %v", err)
	}
	before := captureFixture(t, path, template)
	target := targetFixture(t, before, "new")
	tx, err := Prepare(before, target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	if _, err := tx.Commit(ctx, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled transaction consumed authority")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled transaction changed path")
	}
}
