//go:build linux

package nativefile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Capture never mutates the target or creates an absent parent. The caller's
// template supplies resource/boot/incarnation metadata, not filesystem authority.
func Capture(path string, template *resourcev1.ResourceObservation) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	if template == nil || template.GetMetadata() == nil {
		return nil, ErrUnsupported
	}
	c, err := openCustody(path, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, c.close()) }()
	return c.snapshot(template)
}

// CaptureReadOnly inspects a root-protected configuration dependency, not a
// replaceable managed file. Hardlinks are allowed only on this observation path;
// Capture, CaptureWithContinuity and Prepare continue to reject them.
func CaptureReadOnly(path string, template *resourcev1.ResourceObservation) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	if template == nil || template.GetMetadata() == nil {
		return nil, ErrUnsupported
	}
	c, err := openCustody(path, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, c.close()) }()
	return c.snapshot(template)
}

type Transaction struct {
	mu      sync.Mutex
	custody *custody
	before  *agentv1.ResourceOwnershipSnapshot
	target  *agentv1.ResourceOwnershipSnapshot
	used    bool
}

// Prepare retains inode and directory custody and a read lease. The path is
// derived from the typed before-state and cannot be overridden at commit time.
// Every write, including the temporary sibling, happens after Commit's gate.
func Prepare(before, target *agentv1.ResourceOwnershipSnapshot) (tx *Transaction, err error) {
	if err := validateImage(before); err != nil {
		return nil, err
	}
	if err := validateImage(target); err != nil {
		return nil, err
	}
	path := before.GetObservation().GetManagedFile().GetPath()
	if path != target.GetObservation().GetManagedFile().GetPath() {
		return nil, ErrConflict
	}
	c, err := openCustody(path, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.close())
		}
	}()
	if err := c.lease(); err != nil {
		return nil, err
	}
	fresh, err := c.snapshot(before.GetObservation())
	if err != nil {
		return nil, err
	}
	if !sameSnapshot(fresh, before) {
		return nil, ErrConflict
	}
	if target.GetObservation().GetManagedFile().GetExists() {
		if err := noDefaultACL(c.parent()); err != nil {
			return nil, err
		}
	}
	return &Transaction{custody: c, before: proto.CloneOf(before), target: proto.CloneOf(target)}, nil
}
func (t *Transaction) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.custody == nil {
		return nil
	}
	err := t.custody.close()
	t.custody = nil
	return err
}
func (t *Transaction) Commit(ctx context.Context, beforeEffect func(context.Context) error) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.custody == nil || t.used || beforeEffect == nil {
		return nil, ErrConflict
	}
	t.used = true
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := t.custody.unchanged(); err != nil {
		return nil, err
	}
	if err := beforeEffect(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The permit exchange is deliberately not a stale-check bypass.
	if err := t.custody.unchanged(); err != nil {
		return nil, err
	}
	if !sameImage(t.before, t.target) {
		if t.target.GetObservation().GetManagedFile().GetExists() {
			if err := t.replace(ctx); err != nil {
				return nil, err
			}
		} else if t.before.GetObservation().GetManagedFile().GetExists() {
			if err := unix.Unlinkat(t.custody.parent(), t.custody.name, 0); err != nil {
				return nil, err
			}
			if err := unix.Fsync(t.custody.parent()); err != nil {
				return nil, err
			}
		}
	}
	template := proto.CloneOf(t.before.GetObservation())
	template.Metadata.ObservedAt = timestamppb.Now()
	after, err := Capture(t.custody.path, template)
	if err != nil {
		return nil, err
	}
	if !sameImage(after, t.target) {
		return nil, ErrConflict
	}
	return after, nil
}
func (t *Transaction) replace(ctx context.Context) (err error) {
	c := t.custody
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	name := ".lindm-file-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(c.parent(), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	linked := true
	defer func() {
		err = errors.Join(err, file.Close())
		if linked {
			err = errors.Join(err, unix.Unlinkat(c.parent(), name, 0), unix.Fsync(c.parent()))
		}
	}()
	if _, err := file.Write(t.target.GetManagedFileContent()); err != nil {
		return err
	}
	identity := t.target.GetObservation().GetManagedFile().GetFile()
	if err := unix.Fchown(fd, int(identity.GetUid()), int(identity.GetGid())); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, identity.GetMode()); err != nil {
		return err
	}
	inherited, err := readXattrs(fd)
	if err != nil {
		return err
	}
	for _, attr := range inherited {
		found := false
		for _, desired := range t.target.GetManagedFileXattrs() {
			if desired.GetName() == attr.GetName() {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: unexpected inherited xattr", ErrUnsupported)
		}
	}
	for _, attr := range t.target.GetManagedFileXattrs() {
		if err := unix.Fsetxattr(fd, attr.GetName(), attr.GetValue(), 0); err != nil {
			return err
		}
	}
	attrs, err := readXattrs(fd)
	if err != nil {
		return err
	}
	if !bytes.Equal(XattrDigest(attrs), t.target.GetObservation().GetManagedFile().GetSecurityMetadataSha256()) {
		return ErrConflict
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.unchanged(); err != nil {
		return err
	}
	flags := uint(0)
	if c.file == nil {
		flags = unix.RENAME_NOREPLACE
	}
	if err := unix.Renameat2(c.parent(), name, c.parent(), c.name, flags); err != nil {
		return err
	}
	linked = false
	return unix.Fsync(c.parent())
}
func validateImage(s *agentv1.ResourceOwnershipSnapshot) error {
	o := s.GetObservation().GetManagedFile()
	if o == nil || s.GetObservation().GetMetadata() == nil || len(o.GetAncestrySha256()) != 32 || len(o.GetSecurityMetadataSha256()) != 32 || len(o.GetNativeIdentitySha256()) != 32 || o.GetExists() != (s.ManagedFileContent != nil) || o.GetExists() != (o.GetFile() != nil) || len(s.GetManagedFileContent()) > maxContent || len(s.GetManagedFileXattrs()) > 64 {
		return ErrUnsupported
	}
	if o.GetExists() {
		if o.GetFile().GetPath() != o.GetPath() || o.GetFile().GetMode()&^uint32(0777) != 0 || o.GetFile().GetUid() == ^uint32(0) || o.GetFile().GetGid() == ^uint32(0) {
			return ErrUnsafePath
		}
		digest := sha256.Sum256(s.GetManagedFileContent())
		if !bytes.Equal(digest[:], o.GetFile().GetSha256()) {
			return ErrConflict
		}
	} else if len(s.GetManagedFileXattrs()) != 0 {
		return ErrConflict
	}
	last := ""
	total := 0
	for _, attr := range s.GetManagedFileXattrs() {
		if attr.GetName() <= last || (!bytes.HasPrefix([]byte(attr.GetName()), []byte("user.")) && attr.GetName() != "security.selinux") {
			return ErrUnsupported
		}
		total += len(attr.GetName()) + len(attr.GetValue())
		if total > maxXattrs {
			return ErrUnsupported
		}
		last = attr.GetName()
	}
	if !bytes.Equal(XattrDigest(s.GetManagedFileXattrs()), o.GetSecurityMetadataSha256()) {
		return ErrConflict
	}
	return nil
}
func sameSnapshot(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	return proto.Equal(a.GetObservation().GetManagedFile(), b.GetObservation().GetManagedFile()) && bytes.Equal(a.GetObservation().GetMetadata().GetNativeRevision(), b.GetObservation().GetMetadata().GetNativeRevision()) && sameImage(a, b)
}
func sameImage(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	x, y := a.GetObservation().GetManagedFile(), b.GetObservation().GetManagedFile()
	return x.GetPath() == y.GetPath() && x.GetExists() == y.GetExists() && x.GetFile().GetMode() == y.GetFile().GetMode() && x.GetFile().GetUid() == y.GetFile().GetUid() && x.GetFile().GetGid() == y.GetFile().GetGid() && bytes.Equal(a.GetManagedFileContent(), b.GetManagedFileContent()) && bytes.Equal(x.GetSecurityMetadataSha256(), y.GetSecurityMetadataSha256())
}
func noDefaultACL(fd int) error {
	_, err := unix.Fgetxattr(fd, "system.posix_acl_default", nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: parent has inherited ACL", ErrUnsupported)
}
