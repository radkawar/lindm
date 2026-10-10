//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/custody"
)

// changeAccount runs shadow-utils against a private prefix, then publishes its
// exact result under BOTH native serialization protocols: lckpwdf's POSIX lock
// and shadow-utils' PID hard-link locks. Running usermod directly while holding
// these locks would deadlock; running it without them would allow an admin edit
// between the expected-state comparison and --unlock. No password is in argv.
func (p *Provider) changeAccount(ctx context.Context, actionID string, before, after *agentv1.AccountLockSnapshot, lock bool) (err error) {
	etc := filepath.Join(p.accounts.root, "etc")
	stage := accountStage(etc, actionID, before.GetUsername())
	unlock, err := lockAccountFiles(etc, stage)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	current, err := p.accounts.lookup(ctx, before.GetUsername())
	if err != nil || !proto.Equal(current, before) {
		return ErrConflict
	}
	passwd, err := p.accounts.readLocal(ctx, "passwd")
	if err != nil {
		return err
	}
	defer clear(passwd)
	shadow, err := p.accounts.readLocal(ctx, "shadow")
	if err != nil {
		return err
	}
	defer clear(shadow)
	if err := os.Mkdir(filepath.Join(stage, "etc"), 0700); err != nil {
		return ErrUnsupported
	}
	for name, data := range map[string][]byte{"passwd": passwd, "shadow": shadow} {
		if err := os.WriteFile(filepath.Join(stage, "etc", name), data, 0600); err != nil {
			return ErrUnsupported
		}
	}
	args := []string{"--prefix", stage}
	beforePassword := strings.Split(before.GetShadowEntry(), ":")[1]
	afterPassword := strings.Split(after.GetShadowEntry(), ":")[1]
	if lock {
		args = append(args, "--lock")
	} else if beforePassword != afterPassword {
		if afterPassword == "" {
			// shadow-utils refuses --unlock of a passwordless account. The
			// empty argument is not a credential; no hash ever enters argv.
			args = append(args, "--password", "")
		} else {
			args = append(args, "--unlock")
		}
	}
	expiry := strings.Split(after.GetShadowEntry(), ":")[7]
	args = append(args, "--expiredate", expiry, "--", before.GetUsername())
	if _, err := p.run(ctx, nativeRequest{command: usermod, args: args}); err != nil {
		return ErrOutcomeUnknown
	}
	if !lock && beforePassword != afterPassword && afterPassword == "" {
		// usermod --password resets last-change; restore that attribute through
		// chage's supported private-root mode before any live publish.
		lastChange := strings.Split(after.GetShadowEntry(), ":")[2]
		if lastChange == "" {
			lastChange = "-1"
		}
		if _, err := p.run(ctx, nativeRequest{command: chage, args: []string{"--root", stage, "--lastday", lastChange, "--", before.GetUsername()}}); err != nil {
			return ErrOutcomeUnknown
		}
	}
	staged := &accountLocker{root: stage}
	nextPasswd, err := staged.readLocal(ctx, "passwd")
	if err != nil {
		return err
	}
	defer clear(nextPasswd)
	nextShadow, err := staged.readLocal(ctx, "shadow")
	if err != nil {
		return err
	}
	defer clear(nextShadow)
	// Native output must change exactly the owned row, not normalize or delete
	// unrelated account state. This also refuses unsupported shadow variants.
	oldLine := []byte(before.GetShadowEntry() + "\n")
	newLine := []byte(after.GetShadowEntry() + "\n")
	defer clear(oldLine)
	defer clear(newLine)
	if !bytes.Equal(passwd, nextPasswd) || bytes.Count(shadow, oldLine) != 1 || !bytes.Equal(bytes.Replace(shadow, oldLine, newLine, 1), nextShadow) {
		return ErrOutcomeUnknown
	}
	// Recheck all live bytes immediately before publication. Cooperative native
	// writers cannot change them while locked; even a bypassing edit observed
	// during staging is preserved rather than overwritten.
	livePasswd, err := p.accounts.readLocal(ctx, "passwd")
	if err != nil {
		return err
	}
	defer clear(livePasswd)
	liveShadow, err := p.accounts.readLocal(ctx, "shadow")
	if err != nil {
		return err
	}
	defer clear(liveShadow)
	if !bytes.Equal(passwd, livePasswd) || !bytes.Equal(shadow, liveShadow) || ctx.Err() != nil {
		return ErrConflict
	}
	return publishShadow(etc, filepath.Join(stage, "etc", "shadow"))
}

func accountStage(etc, actionID, username string) string {
	digest := sha256.Sum256([]byte(actionID + "\x00" + username))
	return filepath.Join(etc, ".lindm-account-"+hex.EncodeToString(digest[:]))
}

// The journal identity determines the only stage eligible for reclamation.
// Neither foreign stale PID locks nor arbitrary directory entries are removed.
func (a *accountLocker) cleanTransaction(actionID, username string) (err error) {
	etc := filepath.Join(a.root, "etc")
	stage := accountStage(etc, actionID, username)
	if _, err := os.Lstat(stage); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	unlock, err := accountPasswordLock(etc)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	return reclaimAccountStage(etc, stage)
}

func accountPasswordLock(etc string) (_ func() error, err error) {
	fd, err := unix.Open(etc, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsupported
	}
	directory := os.NewFile(uintptr(fd), "account-directory")
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || !custody.TrustedDirectory(&stat) {
		_ = directory.Close()
		return nil, ErrUnsupported
	}
	passwordFD, err := unix.Openat(fd, ".pwd.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		_ = directory.Close()
		return nil, ErrUnsupported
	}
	passwordLock := os.NewFile(uintptr(passwordFD), "account-password-lock")
	cleanup := func() error { return errors.Join(passwordLock.Close(), directory.Close()) }
	defer func() {
		if err != nil {
			err = errors.Join(err, cleanup())
		}
	}()
	if unix.Fstat(passwordFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Nlink != 1 {
		return nil, ErrUnsupported
	}
	if err := unix.FcntlFlock(uintptr(passwordFD), unix.F_SETLK, &unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(io.SeekStart)}); err != nil {
		return nil, ErrConflict
	}
	return cleanup, nil
}

func lockAccountFiles(etc, stage string) (_ func() error, err error) {
	unlock, err := accountPasswordLock(etc)
	if err != nil {
		return nil, err
	}
	var locks []string
	created := false
	cleanup := func() error {
		var result error
		for i := len(locks) - 1; i >= 0; i-- {
			result = errors.Join(result, os.Remove(locks[i]))
		}
		if created {
			result = errors.Join(result, os.RemoveAll(stage))
		}
		return errors.Join(result, unlock())
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, cleanup())
		}
	}()
	if err := reclaimAccountStage(etc, stage); err != nil {
		return nil, err
	}
	if err := os.Mkdir(stage, 0700); err != nil {
		return nil, ErrUnsupported
	}
	created = true
	pidPath := filepath.Join(stage, "owner.pid")
	pidFile, err := os.OpenFile(pidPath+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, ErrUnsupported
	}
	if _, err := io.WriteString(pidFile, strconv.Itoa(os.Getpid())+"\x00"); err != nil {
		_ = pidFile.Close()
		return nil, ErrUnsupported
	}
	if err := errors.Join(pidFile.Sync(), pidFile.Close()); err != nil {
		return nil, ErrUnsupported
	}
	if err := os.Rename(pidPath+".tmp", pidPath); err != nil {
		return nil, ErrUnsupported
	}
	for _, name := range []string{"passwd.lock", "shadow.lock"} {
		path := filepath.Join(etc, name)
		if err := os.Link(pidPath, path); err != nil {
			return nil, ErrConflict
		}
		locks = append(locks, path)
	}
	return cleanup, nil
}

func reclaimAccountStage(etc, stage string) error {
	var stat unix.Stat_t
	if err := unix.Lstat(stage, &stat); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return ErrUnsupported
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0777 != 0700 || stat.Uid != 0 {
		return ErrUnsupported
	}
	pidPath := filepath.Join(stage, "owner.pid")
	var owner unix.Stat_t
	if err := unix.Lstat(pidPath, &owner); errors.Is(err, unix.ENOENT) {
		// A crash before writing the owner file cannot have acquired PID locks.
		return os.RemoveAll(stage)
	} else if err != nil {
		return ErrUnsupported
	}
	if owner.Mode&unix.S_IFMT != unix.S_IFREG || owner.Uid != 0 || owner.Mode&0777 != 0600 || owner.Size < 2 || owner.Size > 32 {
		return ErrUnsupported
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return ErrUnsupported
	}
	pid, err := strconv.Atoi(strings.TrimSuffix(string(data), "\x00"))
	if err != nil || pid <= 0 {
		return ErrUnsupported
	}
	// PID reuse conservatively holds; never infer death from permission errors.
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		return ErrConflict
	}
	for _, name := range []string{"passwd.lock", "shadow.lock"} {
		path := filepath.Join(etc, name)
		var lock unix.Stat_t
		if err := unix.Lstat(path, &lock); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return ErrUnsupported
		}
		if lock.Dev != owner.Dev || lock.Ino != owner.Ino || lock.Mode&unix.S_IFMT != unix.S_IFREG {
			return ErrConflict
		}
		if err := os.Remove(path); err != nil {
			return ErrUnsupported
		}
	}
	return os.RemoveAll(stage)
}

func publishShadow(etc, stagedPath string) (err error) {
	fd, err := unix.Open(filepath.Join(etc, "shadow"), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrUnsupported
	}
	original := os.NewFile(uintptr(fd), "original-shadow")
	defer func() { err = errors.Join(err, original.Close()) }()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Nlink != 1 {
		return ErrUnsupported
	}
	stagedFD, err := unix.Open(stagedPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsupported
	}
	staged := os.NewFile(uintptr(stagedFD), "native-shadow-result")
	defer func() { err = errors.Join(err, staged.Close()) }()
	if err := staged.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		return ErrUnsupported
	}
	if err := staged.Chmod(os.FileMode(stat.Mode & 0777)); err != nil {
		return ErrUnsupported
	}
	if err := copyAccountXattrs(fd, stagedFD); err != nil {
		return err
	}
	if err := staged.Sync(); err != nil {
		return ErrOutcomeUnknown
	}
	if err := os.Rename(stagedPath, filepath.Join(etc, "shadow")); err != nil {
		return ErrOutcomeUnknown
	}
	dir, err := os.Open(etc)
	if err != nil {
		return ErrOutcomeUnknown
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func copyAccountXattrs(from, to int) error {
	names := make([]byte, 65536)
	n, err := unix.Flistxattr(from, names)
	if errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return ErrUnsupported
	}
	values := make([]byte, 65536)
	defer clear(values)
	for _, name := range strings.Split(string(names[:n]), "\x00") {
		if name == "" {
			continue
		}
		size, err := unix.Fgetxattr(from, name, values)
		if err != nil {
			return ErrUnsupported
		}
		if err := unix.Fsetxattr(to, name, values[:size], 0); err != nil {
			return ErrUnsupported
		}
	}
	return nil
}
