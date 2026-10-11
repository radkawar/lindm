//go:build linux

package nativefile

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// CaptureWithContinuity adds a boot-stable generation proof while holding the
// same descriptors as the ordinary byte/metadata capture. Existing Capture and
// transaction CAS identities remain unchanged. Content and mtime are deliberately
// excluded: an in-place edit can be repaired, but a reused inode cannot be owned.
func CaptureWithContinuity(path string, template *resourcev1.ResourceObservation) (snapshot *agentv1.ResourceOwnershipSnapshot, continuity *agentv1.NativeFileContinuity, err error) {
	if template == nil || template.GetMetadata() == nil {
		return nil, nil, ErrUnsupported
	}
	c, err := openCustody(path, false)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, c.close()) }()
	continuity, err = c.continuity()
	if err != nil {
		return nil, nil, err
	}
	snapshot, err = c.snapshot(template)
	return snapshot, continuity, err
}

func (c *custody) continuity() (*agentv1.NativeFileContinuity, error) {
	ancestry := sha256.New()
	_, _ = ancestry.Write([]byte("lindm.file.ancestry-generation.v1\x00"))
	for i, fd := range c.dirs {
		generation, err := descriptorGeneration(fd)
		if err != nil {
			return nil, err
		}
		_, _ = ancestry.Write(generation)
		st := c.stats[i]
		_, _ = fmt.Fprintf(ancestry, "%d:%d:%d;", st.Uid, st.Gid, st.Mode)
	}
	generation := sha256.Sum256([]byte("lindm.file.absent-generation.v1"))
	inode := generation[:]
	if c.file != nil {
		var err error
		inode, err = descriptorGeneration(int(c.file.Fd()))
		if err != nil {
			return nil, err
		}
	}
	return &agentv1.NativeFileContinuity{InodeGenerationSha256: inode, AncestryGenerationSha256: ancestry.Sum(nil)}, nil
}

func descriptorGeneration(fd int) ([]byte, error) {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return nil, err
	}
	if fs.Fsid.Val[0] == 0 && fs.Fsid.Val[1] == 0 {
		return nil, fmt.Errorf("%w: stable filesystem identity unavailable", ErrUnsupported)
	}
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME|unix.STATX_INO, &st); err != nil {
		return nil, err
	}
	if st.Mask&(unix.STATX_BTIME|unix.STATX_INO) != (unix.STATX_BTIME | unix.STATX_INO) {
		return nil, fmt.Errorf("%w: inode generation unavailable", ErrUnsupported)
	}
	// f_fsid identifies the native filesystem, unlike the volatile st_dev
	// number. Including birth time prevents delete/recreate with inode reuse.
	digest := sha256.Sum256(fmt.Appendf(nil, "lindm.file.inode-generation.v1:%d:%d:%d:%d:%d:%d", fs.Type, fs.Fsid.Val[0], fs.Fsid.Val[1], st.Ino, st.Btime.Sec, st.Btime.Nsec))
	return digest[:], nil
}
