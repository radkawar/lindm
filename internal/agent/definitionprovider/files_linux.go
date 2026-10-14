// SPDX-License-Identifier: Apache-2.0

//go:build linux

package definitionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
)

// directory opens each component without symlinks. Its fingerprint binds inode
// birth time and security metadata, but not child-entry mtime: our own atomic
// file replacement legitimately changes that timestamp.
func directory(path string) (int, []byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, nil, ErrProtected
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	h := sha256.New()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := 0; ; i++ {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return -1, nil, err
		}
		if st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(fd)
			return -1, nil, ErrProtected
		}
		_, _ = fmt.Fprintf(h, "%d:%d:%d:%d:%d;", st.Dev, st.Ino, st.Uid, st.Gid, st.Mode)
		if i == len(parts) || parts[i] == "" {
			break
		}
		// systemd RestrictSUIDSGID= fails openat2 with ENOSYS. A single clean
		// component opened with O_NOFOLLOW cannot escape or follow a link.
		next, err := unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, nil, err
		}
		fd = next
	}
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &stx); err != nil {
		_ = unix.Close(fd)
		return -1, nil, err
	}
	if stx.Mask&unix.STATX_BTIME == 0 {
		_ = unix.Close(fd)
		return -1, nil, ErrUnsupported
	}
	_, _ = fmt.Fprintf(h, "birth:%d:%d;", stx.Btime.Sec, stx.Btime.Nsec)
	attrs, err := directoryXattrs(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, nil, err
	}
	_, _ = h.Write(attrs)
	return fd, h.Sum(nil), nil
}
func directoryXattrs(fd int) ([]byte, error) {
	size, err := unix.Flistxattr(fd, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return emptyDigest(), nil
	}
	if err != nil {
		return nil, err
	}
	if size > 32768 {
		return nil, ErrUnsupported
	}
	if size == 0 {
		return emptyDigest(), nil
	}
	data := make([]byte, size)
	n, err := unix.Flistxattr(fd, data)
	if err != nil || n != size {
		return nil, errors.Join(ErrConflict, err)
	}
	names := strings.Split(string(data[:n-1]), "\x00")
	slices.Sort(names)
	h := sha256.New()
	total := 0
	for _, name := range names {
		if strings.HasPrefix(name, "system.posix_acl_") {
			return nil, fmt.Errorf("%w: inherited ACL", ErrUnsupported)
		}
		size, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return nil, err
		}
		total += size + len(name)
		if total > 32768 {
			return nil, ErrUnsupported
		}
		value := make([]byte, size)
		n, err := unix.Fgetxattr(fd, name, value)
		if err != nil || n != size {
			return nil, errors.Join(ErrConflict, err)
		}
		_, _ = fmt.Fprintf(h, "%d:%s:%d:", len(name), name, n)
		_, _ = h.Write(value)
	}
	return h.Sum(nil), nil
}
func parentEvidence(path string) (bool, []byte, error) {
	parent := filepath.Dir(path)
	fd, digest, err := directory(parent)
	if err == nil {
		return false, digest, unix.Close(fd)
	}
	if !errors.Is(err, unix.ENOENT) || filepath.Dir(parent) != unitRoot || !strings.HasSuffix(parent, ".service.d") {
		return false, nil, err
	}
	fd, digest, err = directory(unitRoot)
	if err != nil {
		return false, nil, err
	}
	if err := unix.Close(fd); err != nil {
		return false, nil, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.definition.parent-absent.v1\x00"))
	_, _ = h.Write(digest)
	_, _ = h.Write([]byte(filepath.Base(parent)))
	return true, h.Sum(nil), nil
}
func captureLink(path, target string) (_ *resourcev1.InstallLink, err error) {
	fd, ancestry, err := directory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	link, err := unix.Openat(fd, filepath.Base(path), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.Close(link)) }()
	var st unix.Stat_t
	if err := unix.Fstat(link, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK || st.Uid != 0 || st.Nlink != 1 {
		return nil, ErrProtected
	}
	var buf [4097]byte
	n, err := unix.Readlinkat(link, "", buf[:])
	if err != nil || n == 0 || n == len(buf) {
		return nil, errors.Join(ErrProtected, err)
	}
	value := string(buf[:n])
	if value != target {
		return nil, ErrConflict
	}
	var current unix.Stat_t
	if err := unix.Fstatat(fd, filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Ino != st.Ino || current.Dev != st.Dev || current.Ctim != st.Ctim {
		return nil, errors.Join(ErrConflict, err)
	}
	var birth unix.Statx_t
	if err := unix.Statx(link, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &birth); err != nil || birth.Mask&unix.STATX_BTIME == 0 {
		return nil, errors.Join(ErrUnsupported, err)
	}
	h := sha256.New()
	_, _ = h.Write(ancestry)
	_, _ = fmt.Fprintf(h, "%d:%d:%d:%d", birth.Btime.Sec, birth.Btime.Nsec, st.Ctim.Sec, st.Ctim.Nsec)
	ancestry = h.Sum(nil)
	return &resourcev1.InstallLink{Path: path, Target: value, Device: st.Dev, Inode: st.Ino, AncestrySha256: ancestry}, nil
}
func captureFile(path string, template *resourcev1.ResourceObservation) (*agentv1.DefinitionFileSnapshot, error) {
	missing, parent, err := parentEvidence(path)
	if err != nil {
		return nil, err
	}
	if missing {
		absent := sha256.Sum256([]byte("lindm.file.absent.v1"))
		return &agentv1.DefinitionFileSnapshot{ParentMissing: true, ParentIdentitySha256: parent, NativeRevisionSha256: bytes.Clone(parent), State: &resourcev1.ManagedFileObservation{Path: path, AncestrySha256: bytes.Clone(parent), SecurityMetadataSha256: nativefile.XattrDigest(nil), NativeIdentitySha256: absent[:]}}, nil
	}
	snapshot, err := nativefile.Capture(path, template)
	if err != nil {
		return nil, err
	}
	return &agentv1.DefinitionFileSnapshot{State: snapshot.GetObservation().GetManagedFile(), Content: snapshot.ManagedFileContent, Xattrs: snapshot.ManagedFileXattrs, ParentIdentitySha256: parent, NativeRevisionSha256: bytes.Clone(snapshot.GetObservation().GetMetadata().GetNativeRevision())}, nil
}
func fileSnapshot(snapshot *agentv1.ResourceOwnershipSnapshot) *agentv1.ResourceOwnershipSnapshot {
	f := snapshot.GetDefinitionFile()
	o := proto.CloneOf(snapshot.GetObservation())
	o.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: proto.CloneOf(f.GetState())}
	o.Metadata.NativeRevision = bytes.Clone(f.GetNativeRevisionSha256())
	return &agentv1.ResourceOwnershipSnapshot{Observation: o, ManagedFileContent: bytes.Clone(f.GetContent()), ManagedFileXattrs: cloneXattrs(f.GetXattrs())}
}
func cloneXattrs(values []*agentv1.NativeFileXattr) []*agentv1.NativeFileXattr {
	out := make([]*agentv1.NativeFileXattr, len(values))
	for i, v := range values {
		out[i] = proto.CloneOf(v)
	}
	return out
}

func createParent(path string, expected *agentv1.DefinitionFileSnapshot) (err error) {
	missing, digest, err := parentEvidence(path)
	if err != nil {
		return err
	}
	if !missing || !expected.GetParentMissing() || !bytes.Equal(digest, expected.GetParentIdentitySha256()) {
		return ErrConflict
	}
	fd, _, err := directory(unitRoot)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	if err := unix.Mkdirat(fd, filepath.Base(filepath.Dir(path)), 0755); err != nil {
		return err
	}
	return unix.Fsync(fd)
}
func removeOwnedParent(path string, last *agentv1.DefinitionFileSnapshot) (err error) {
	missing, digest, err := parentEvidence(path)
	if err != nil {
		return err
	}
	if missing || last.GetParentMissing() || !bytes.Equal(digest, last.GetParentIdentitySha256()) {
		return ErrConflict
	}
	fd, _, err := directory(unitRoot)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	// unlinkat(AT_REMOVEDIR) cannot remove another administrator's children.
	if err := unix.Unlinkat(fd, filepath.Base(filepath.Dir(path)), unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func (p *Provider) snapshot(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := DefinitionPath(desired)
	if err != nil {
		return nil, err
	}
	template := p.observationTemplate(desired.GetRef())
	file, err := captureFile(path, template)
	if err != nil {
		return nil, err
	}
	d := desired.GetSystemdDefinition()
	target, err := settledTarget(ctx, p.manager, targetUnit(d), targetJobSettle)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, fmt.Errorf("%w: target service is absent", ErrUnsupported)
	}
	graph, err := targetFingerprint(ctx, target, path)
	if err != nil {
		return nil, err
	}
	o := &resourcev1.SystemdDefinitionObservation{CanonicalKey: desired.GetRef().GetCanonicalKey(), Exists: file.GetState().GetExists(), OwnedFile: proto.CloneOf(file.GetState().GetFile()), FileState: proto.CloneOf(file.GetState()), TargetDefinitionSha256: graph, TargetServiceExists: true, DaemonReloadPending: target.reload, TimerScheduleSha256: emptyDigest()}
	if timer := d.GetTimer(); timer != nil {
		v, err := p.manager.Unit(ctx, timer.GetUnit(), "Timer")
		if err != nil {
			return nil, err
		}
		o.TimerEnabled = proto.Bool(false)
		o.TimerActive = proto.Bool(false)
		o.TimerUnitFileState = "absent"
		if v != nil {
			if v.fragment != path || len(v.dropIns) != 0 || !file.GetState().GetExists() {
				return nil, fmt.Errorf("%w: unrelated timer definition or drop-ins", ErrConflict)
			}
			if v.fileState != "enabled" && v.fileState != "disabled" {
				return nil, ErrUnsupported
			}
			if v.active != "active" && v.active != "inactive" {
				return nil, ErrUnsupported
			}
			if len(v.invocation) != 0 && len(v.invocation) != 16 {
				return nil, ErrUnsupported
			}
			effective, schedule, err := timerSchedule(v)
			if err != nil {
				return nil, err
			}
			if effective.GetService().GetCanonicalKey() != timer.GetService().GetCanonicalKey() {
				return nil, ErrConflict
			}
			o.Effective = &resourcev1.SystemdDefinitionDesired{Presence: resourcev1.Presence_PRESENCE_PRESENT, Definition: &resourcev1.SystemdDefinitionDesired_Timer{Timer: effective}}
			exact := &resourcev1.ResourceDesiredState{Ref: proto.CloneOf(desired.GetRef()), State: &resourcev1.ResourceDesiredState_SystemdDefinition{SystemdDefinition: o.Effective}}
			content, err := Render(exact)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(content, file.GetContent()) {
				return nil, fmt.Errorf("%w: timer has unmanaged directives", ErrUnsupported)
			}
			o.TimerEnabled = proto.Bool(v.fileState == "enabled")
			o.TimerActive = proto.Bool(v.active == "active")
			// An inactive timer reports an empty InvocationID, which is absence.
			if len(v.invocation) != 0 {
				o.TimerInvocationId = bytes.Clone(v.invocation)
			}
			o.TimerJobPending = v.pending
			o.TimerUnitFileState = v.fileState
			o.TimerScheduleSha256 = schedule
			o.DaemonReloadPending = o.GetDaemonReloadPending() || v.reload
		} else if file.GetState().GetExists() {
			return nil, fmt.Errorf("%w: file not loaded", ErrConflict)
		}
		o.TimerInstallLinks, err = p.manager.Links(ctx, timer.GetUnit())
		if err != nil {
			return nil, err
		}
		o.TimerInstallProjectionComplete = true
		if o.GetTimerEnabled() != (len(o.GetTimerInstallLinks()) == 1) {
			return nil, ErrConflict
		}
	} else {
		o.EffectiveOptions, err = effectiveOptions(target)
		if err != nil {
			return nil, err
		}
		if file.GetState().GetExists() {
			o.Effective, err = parseOwnedDropIn(desired, file.GetContent())
			if err != nil {
				return nil, err
			}
		}
	}
	definition := sha256.New()
	_, _ = definition.Write(graph)
	_, _ = definition.Write(file.GetState().GetFile().GetSha256())
	_, _ = definition.Write(o.GetTimerScheduleSha256())
	options, err := messageDigest(o.GetEffectiveOptions())
	if err != nil {
		return nil, err
	}
	_, _ = definition.Write(options)
	o.DefinitionSha256 = definition.Sum(nil)
	template.Observed = &resourcev1.ResourceObservation_SystemdDefinition{SystemdDefinition: o}
	revision, err := messageDigest(o)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = h.Write(revision)
	_, _ = h.Write(file.GetParentIdentitySha256())
	_, _ = h.Write(file.GetNativeRevisionSha256())
	if file.GetParentMissing() {
		_, _ = h.Write([]byte{1})
	}
	template.Metadata.NativeRevision = h.Sum(nil)
	s := &agentv1.ResourceOwnershipSnapshot{Observation: template, DefinitionFile: file}
	if err := resourceObservationValid(s); err != nil {
		return nil, err
	}
	return s, nil
}

// targetJobSettle bounds the wait for a queued target job, such as the start
// the definition's own timer enqueued when it elapsed during an apply.
const targetJobSettle = 20 * time.Second

// settledTarget observes the target service once no job is queued for it. A
// timer-started run settles within seconds; a job still pending after settle
// is a conflict, since the definition must not change mid-transition.
func settledTarget(ctx context.Context, manager nativeManager, name string, settle time.Duration) (*unitView, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(settle)
	defer deadline.Stop()
	for {
		target, err := manager.Unit(ctx, name, "Service")
		if err != nil || target == nil || !target.pending {
			return target, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("%w: target has a pending job", ErrConflict)
		case <-ticker.C:
		}
	}
}
