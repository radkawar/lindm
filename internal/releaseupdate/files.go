// SPDX-License-Identifier: Apache-2.0

// Package releaseupdate publishes TUF repositories and verifies agent updates.
// It has no implicit network transport and never executes native packages.
package releaseupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

const (
	MaxMetadataBytes  int64 = 4 << 20
	MaxCatalogBytes   int64 = 1 << 20
	MaxTargetBytes    int64 = 2 << 30
	MaxSignatureBytes int64 = 64 << 10
	maxStateBytes     int64 = 24 << 20
)

var ErrNotFound = errors.New("releaseupdate: not_found")
var ErrNoUpdate = errors.New("releaseupdate: no_update")

func safePath(name string) bool {
	return name != "" && len(name) <= 1024 && !path.IsAbs(name) && path.Clean(name) == name && name != "." && name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00%?#")
}

var targetPathName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)

func safeTargetPath(name string) bool { return safePath(name) && targetPathName.MatchString(name) }

func openDirectoryNoLinks(directory string) (*os.Root, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			return nil, errors.New("releaseupdate: directory symlink or non-directory refused")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return os.OpenRoot(absolute)
}

// openRegular rejects every symlink, including intermediate components. os.Root
// also confines traversal if an administrator concurrently changes the tree.
func openRegular(root *os.Root, name string) (*os.File, error) {
	if !safePath(name) {
		return nil, errors.New("releaseupdate: invalid file path")
	}
	parts := strings.Split(name, "/")
	for n := range parts {
		st, err := root.Lstat(strings.Join(parts[:n+1], "/"))
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("releaseupdate: symlink refused")
		}
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.Join(errors.New("releaseupdate: regular file required"), err, file.Close())
	}
	return file, nil
}

func readBounded(root *os.Root, name string, limit int64) (data []byte, err error) {
	f, err := openRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, errors.New("releaseupdate: file exceeds bound")
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("releaseupdate: file exceeds bound")
	}
	return data, err
}

func syncDir(directory string) (err error) {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return f.Sync()
}

func atomicWrite(filename string, data []byte, mode os.FileMode) (err error) {
	directory := filepath.Dir(filename)
	f, err := os.CreateTemp(directory, ".publish-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() {
		if removeErr := os.Remove(name); !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	if err = f.Chmod(mode); err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err = f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, filename); err != nil {
		return err
	}
	return syncDir(directory)
}

func mkdirDurable(directory string, mode os.FileMode) error {
	directory = filepath.Clean(directory)
	parent := filepath.Dir(directory)
	if parent != directory {
		if err := mkdirDurable(parent, mode); err != nil {
			return err
		}
	}
	st, err := os.Lstat(directory)
	if err == nil {
		if !st.IsDir() {
			return errors.New("releaseupdate: directory symlink or non-directory refused")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = os.Mkdir(directory, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	st, err = os.Lstat(directory)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("releaseupdate: directory replaced")
	}
	return syncDir(parent)
}

// ownedDirectory durably creates directory, then requires custody.Owned: a
// private leaf owned by the effective user. Publishers, mirrors and tests run
// unprivileged, so the ancestry is the operator's, not root's.
func ownedDirectory(directory string) error {
	if !filepath.IsAbs(directory) {
		return errors.New("releaseupdate: state directory must be absolute")
	}
	if err := mkdirDurable(directory, 0700); err != nil {
		return err
	}
	_, err := custody.Owned(directory, true)
	return err
}

func acquireLock(directory string) (*os.File, error) {
	fd, err := unix.Open(filepath.Join(directory, ".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "releaseupdate lock")
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(errors.New("releaseupdate: repository busy"), err, f.Close())
	}
	return f, nil
}

func digestBytes(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }
func hashPath(name string, hash []byte) string {
	return path.Join(path.Dir(name), hex.EncodeToString(hash)+"."+path.Base(name))
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func copyTarget(ctx context.Context, source io.Reader, destination string, length int64, expected []byte) (err error) {
	if length < 1 || length > MaxTargetBytes || len(expected) != sha256.Size {
		return errors.New("releaseupdate: invalid target descriptor")
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".target-")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer func() {
		if e := os.Remove(temp); !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}()
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(contextReader{ctx, source}, length+1))
	if copyErr != nil || n != length || hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(expected) {
		return errors.Join(fmt.Errorf("releaseupdate: target length/hash mismatch (%d bytes)", n), copyErr, f.Close())
	}
	if err = f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = os.Rename(temp, destination); err != nil {
		return err
	}
	return syncDir(filepath.Dir(destination))
}
