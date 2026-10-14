// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// protectedBundle rejects links, special files and writable/non-root ancestry
// before a directly invoked installer authenticates or later consumes assets.
func protectedBundle(path string) error {
	return filepath.WalkDir(path, func(name string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		f, stat, err := custody.OpenRoot(name, unix.O_RDONLY|unix.O_NONBLOCK)
		if err != nil {
			return err
		}
		err = f.Close()
		kind := stat.Mode & unix.S_IFMT
		if kind != unix.S_IFDIR && (kind != unix.S_IFREG || stat.Nlink != 1) {
			return errors.Join(err, errors.New("bundle must contain only root-protected directories and regular files"))
		}
		return err
	})
}

// protected reads a bounded regular file without following replaceable ancestry.
func protected(path string, secret bool) (data []byte, err error) {
	f, stat, err := custody.OpenRoot(path, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size > 1<<20 || (secret && stat.Mode&0077 != 0) {
		return nil, errors.New("input must be bounded root-owned protected regular file")
	}
	data, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("input exceeds 1 MiB")
	}
	return data, nil
}

func account(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, errors.New("service account cannot be root")
	}
	return uid, gid, nil
}

// Database passwords stay in root custody; service identities receive only
// ephemeral systemd credentials, never ownership of the persistent URL.
func newDatabaseURL(path string, content []byte) error {
	return newFile(path, content, 0, 0, 0600)
}

func newFile(path string, content []byte, uid, gid int, mode os.FileMode) (err error) {
	// Publish complete, synced bytes with no replacement. A crash during a write
	// must not strand a truncated credential at its final, immutable pathname.
	f, err := os.CreateTemp(filepath.Dir(path), ".lindm-new-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Chown(uid, gid); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Chmod(mode.Perm()); err != nil {
		return errors.Join(err, f.Close())
	}
	_, writeErr := f.Write(content)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

func copyFileNew(src, dst string, mode os.FileMode) (err error) {
	inFD, err := unix.Open(src, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	in := os.NewFile(uintptr(inFD), src)
	defer func() { err = errors.Join(err, in.Close()) }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<30 {
		return errors.New("invalid native artifact file")
	}
	fd, err := unix.Open(dst, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	out := os.NewFile(uintptr(fd), dst)
	defer func() { err = errors.Join(err, out.Close()) }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// command never includes child output in errors: SQL and setup output may be secret.
func command(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/", "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "UCF_FORCE_CONFFOLD=1"}
	cmd.Stdin = bytes.NewReader(input)
	var output boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed (output withheld; inspect private service journal): %w", filepath.Base(name), err)
	}
	return output.data.Bytes(), nil
}

type boundedOutput struct{ data bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.data.Len()+len(p) > 1<<20 {
		return 0, errors.New("subprocess output limit exceeded")
	}
	return b.data.Write(p)
}

func directory(path string, uid, gid int, mode os.FileMode) error {
	mkdirErr := os.Mkdir(path, mode)
	if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
		return mkdirErr
	}
	if mkdirErr == nil {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return errors.New("unsafe directory")
	}
	if st.Uid != uint32(uid) {
		return errors.New("directory owner mismatch")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
