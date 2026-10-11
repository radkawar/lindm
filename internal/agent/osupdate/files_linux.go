//go:build linux

package osupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

var (
	errFileUnsafe = errors.New("os_update_file_unsafe")
	errFileSize   = errors.New("os_update_file_too_large")
	// ErrRunInProgress reports that a window, patch-now or status run, or an
	// os.update.v1 provider effect, holds the run lock.
	ErrRunInProgress = errors.New("os_update_run_in_progress")
)

// readProtected reads a root-owned regular file without following a final
// symlink. Group/other write permission is refused, and so is a file larger
// than limit. A missing file returns fs.ErrNotExist.
func readProtected(path string, limit int64) ([]byte, error) {
	return readOwned(path, limit, 0)
}

// readOwned is readProtected for an explicit owner (tests use their own UID).
func readOwned(path string, limit int64, owner uint32) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != owner || st.Mode&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s", errFileUnsafe, path)
	}
	if st.Size > limit {
		return nil, fmt.Errorf("%w: %s", errFileSize, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s", errFileSize, path)
	}
	return data, nil
}

// checkPrivateDir requires an existing root-owned directory that is not a
// symlink and not group/other writable. The package creates the parents.
func checkPrivateDir(path string) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
		return fmt.Errorf("%w: %s", errFileUnsafe, path)
	}
	return nil
}

// writeAtomic replaces path with data (0600 root): an O_EXCL temporary in the
// same directory, fsync, rename, then fsync of the directory.
func writeAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	temp := filepath.Join(dir, "."+filepath.Base(path)+"."+strconv.Itoa(os.Getpid())+".tmp")
	if err := unix.Unlink(temp); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := unix.Open(temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", temp, err)
	}
	file := os.NewFile(uintptr(fd), temp)
	defer func() {
		if err != nil {
			err = errors.Join(err, unix.Unlink(temp))
		}
	}()
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("write %s: %w", temp, err)
	}
	if err := unix.Rename(temp, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = unix.Close(dirFD) }()
	return unix.Fsync(dirFD)
}

// marshalValidated encodes deterministically after validating the message.
func (r *Runner) marshalValidated(message proto.Message) ([]byte, error) {
	if err := r.validator.Validate(message); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

// unmarshalValidated decodes and validates; unknown fields are rejected.
func (r *Runner) unmarshalValidated(data []byte, message proto.Message) error {
	if err := proto.Unmarshal(data, message); err != nil {
		return err
	}
	if len(message.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("unknown fields")
	}
	return r.validator.Validate(message)
}

// lock holds the flock serializing the run, patch-now and status units and
// the os.update.v1 provider's native effects.
type lock struct{ file *os.File }

// openLock opens the lock file. It lives in a root-only 0700 directory
// (never the world-writable /run/lock), so no unprivileged user can
// pre-create or hold it.
func openLock(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := unix.Mkdir(dir, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	var dirStat unix.Stat_t
	if err := unix.Lstat(dir, &dirStat); err != nil {
		return nil, err
	}
	if dirStat.Mode&unix.S_IFMT != unix.S_IFDIR || dirStat.Uid != 0 || dirStat.Mode&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s", errFileUnsafe, dir)
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 {
		_ = file.Close()
		return nil, errors.Join(errFileUnsafe, err)
	}
	return file, nil
}

// tryFlock makes one non-blocking attempt; contention is ErrRunInProgress.
func tryFlock(file *os.File) error {
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
		case errors.Is(err, unix.EWOULDBLOCK):
			return ErrRunInProgress
		default:
			return fmt.Errorf("flock: %w", err)
		}
	}
}

// acquireLock polls a non-blocking flock until wait elapses. A blocking
// flock could not be cancelled; the poll keeps the wait bounded.
func acquireLock(ctx context.Context, path string, wait time.Duration) (*lock, error) {
	file, err := openLock(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		err := tryFlock(file)
		if err == nil {
			return &lock{file: file}, nil
		}
		if !errors.Is(err, ErrRunInProgress) {
			_ = file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ErrRunInProgress
		case <-ticker.C:
		}
	}
}

func (l *lock) release() error { return l.file.Close() }

// TryRunLock takes the run lock without waiting, for the os.update.v1
// provider's effect: a native effect never overlaps a running package
// transaction, and a run that starts meanwhile waits for the effect. The
// returned function releases it.
func TryRunLock(path string) (func() error, error) {
	file, err := openLock(path)
	if err != nil {
		return nil, err
	}
	if err := tryFlock(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file.Close, nil
}
