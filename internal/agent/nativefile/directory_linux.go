//go:build linux

package nativefile

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// CreatedDirectoryMode is the only metadata a provider-created file root has.
const CreatedDirectoryMode = 0755

// absentDirectoryAncestry binds the protected chain above an absent directory
// and its name. It is domain-separated from every present-chain ancestry, so a
// file observed under an absent directory never matches one observed in it.
func absentDirectoryAncestry(c *custody) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.file.absent-directory.v1\x00"))
	_, _ = h.Write(c.ancestry)
	_, _ = h.Write([]byte(c.name))
	return h.Sum(nil)
}

// openAbsentDirectory retains custody above directory and proves it absent.
// Any existing object at directory, including a symlink, is ErrConflict; an
// absent ancestor above it stays the ordinary ErrConflict precondition.
func openAbsentDirectory(directory string) (_ *custody, err error) {
	c, err := openAncestors(directory, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.close())
		}
	}()
	var st unix.Stat_t
	err = unix.Fstatat(c.parent(), c.name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: %s exists", ErrConflict, directory)
}

// DirectoryAbsent reports whether directory is absent beneath a root-protected
// parent chain, returning the ancestry a file directly inside it is observed
// with. An existing directory reports false; unsafe ancestry is an error.
func DirectoryAbsent(directory string) (ancestry []byte, absent bool, err error) {
	c, err := openAncestors(directory, false)
	if err != nil {
		return nil, false, err
	}
	defer func() { err = errors.Join(err, c.close()) }()
	var st unix.Stat_t
	err = unix.Fstatat(c.parent(), c.name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return absentDirectoryAncestry(c), true, c.unchanged()
	}
	return nil, false, err
}

// CaptureInAbsentDirectory observes path as absent because its parent
// directory is absent while the directory's own parent chain is protected.
func CaptureInAbsentDirectory(path string, template *resourcev1.ResourceObservation) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	if template == nil || template.GetMetadata() == nil {
		return nil, ErrUnsupported
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == "/" {
		return nil, ErrUnsafePath
	}
	c, err := openAbsentDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, c.close()) }()
	absent := sha256.Sum256([]byte("lindm.file.absent.v1"))
	o := &resourcev1.ManagedFileObservation{Path: path, AncestrySha256: absentDirectoryAncestry(c), NativeIdentitySha256: absent[:], SecurityMetadataSha256: XattrDigest(nil)}
	s := &agentv1.ResourceOwnershipSnapshot{Observation: proto.CloneOf(template)}
	s.Observation.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: o}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(o)
	if err != nil {
		return nil, err
	}
	revision := sha256.Sum256(encoded)
	s.Observation.Metadata.NativeRevision = revision[:]
	if err := c.unchanged(); err != nil {
		return nil, err
	}
	return s, nil
}

// PrepareInAbsentDirectory is Prepare for a file whose parent directory the
// same effect creates as root:root 0755. Custody covers the protected chain
// above the directory; nothing is written before Commit's gate.
func PrepareInAbsentDirectory(before, target *agentv1.ResourceOwnershipSnapshot) (tx *Transaction, err error) {
	if err := validateImage(before); err != nil {
		return nil, err
	}
	if err := validateImage(target); err != nil {
		return nil, err
	}
	path := before.GetObservation().GetManagedFile().GetPath()
	if path != target.GetObservation().GetManagedFile().GetPath() || before.GetObservation().GetManagedFile().GetExists() || !target.GetObservation().GetManagedFile().GetExists() || target.GetCreatedDirectory() != filepath.Dir(path) {
		return nil, ErrConflict
	}
	c, err := openAbsentDirectory(target.GetCreatedDirectory())
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.close())
		}
	}()
	if string(absentDirectoryAncestry(c)) != string(before.GetObservation().GetManagedFile().GetAncestrySha256()) {
		return nil, ErrConflict
	}
	// A default ACL on the parent would be inherited by the new directory.
	if err := noDefaultACL(c.parent()); err != nil {
		return nil, err
	}
	return &Transaction{custody: c, before: proto.CloneOf(before), target: proto.CloneOf(target), createDirectory: true}, nil
}

// createDirectoryAndReplace runs after the gate: it creates the retained
// absent directory root:root 0755, then writes the file inside it.
func (t *Transaction) createDirectoryAndReplace(ctx context.Context) (err error) {
	c := t.custody
	if err := unix.Mkdirat(c.parent(), c.name, CreatedDirectoryMode); err != nil {
		return err
	}
	created := true
	defer func() {
		if err != nil && created {
			// Only an empty directory can be removed; a written file stays.
			_ = unix.Unlinkat(c.parent(), c.name, unix.AT_REMOVEDIR)
		}
	}()
	fd, err := unix.Openat(c.parent(), c.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, CreatedDirectoryMode); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	if err := unix.Fsync(c.parent()); err != nil {
		return err
	}
	inner, err := openCustody(t.target.GetObservation().GetManagedFile().GetPath(), false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, inner.close()) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	parent := inner.stats[len(inner.stats)-1]
	if inner.file != nil || parent.Dev != st.Dev || parent.Ino != st.Ino {
		return ErrConflict
	}
	created = false
	return (&Transaction{custody: inner, before: t.before, target: t.target}).replace(ctx)
}

// RemoveCreatedDirectory removes directory only when it is still an empty
// root:root 0755 directory beneath a protected chain. It reports whether it
// removed it; a non-empty or changed directory is left in place.
func RemoveCreatedDirectory(directory string) (removed bool, err error) {
	c, err := openAncestors(directory, false)
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, c.close()) }()
	fd, err := unix.Openat(c.parent(), c.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	if !createdDirectoryShape(&st) {
		return false, nil
	}
	// unlinkat(AT_REMOVEDIR) refuses a directory that gained any entry.
	if err := unix.Unlinkat(c.parent(), c.name, unix.AT_REMOVEDIR); err != nil {
		if errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, err
	}
	return true, unix.Fsync(c.parent())
}

func createdDirectoryShape(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == CreatedDirectoryMode && st.Uid == 0 && st.Gid == 0
}
