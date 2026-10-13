//go:build linux

package packaging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/statefs"
)

func cleanAbsolute(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, 0) || strings.ContainsAny(path, "\r\n") {
		return "", ErrUnsafePath
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: path is not absolute", ErrUnsafePath)
	}
	cleaned := filepath.Clean(path)
	if cleaned != path || cleaned == "/" {
		return "", fmt.Errorf("%w: path is not canonical", ErrUnsafePath)
	}
	return cleaned, nil
}

func rejectMacroUnsafe(path string) error {
	if strings.ContainsAny(path, "%\"'`\\\n\r") {
		return fmt.Errorf("%w: path is unsafe for package tool input", ErrUnsafePath)
	}
	return nil
}

func openPrivate(path string) (*os.File, error) {
	cleaned, err := cleanAbsolute(path)
	if err != nil {
		return nil, err
	}
	if err := rejectMacroUnsafe(cleaned); err != nil {
		return nil, err
	}
	fd, err := statefs.OpenDirectory(cleaned)
	if err != nil {
		if errors.Is(err, statefs.ErrUnsafe) {
			return nil, fmt.Errorf("%w: %s", ErrUnsafePath, "directory is not a private 0700 directory")
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), cleaned), nil
}

func openRegular(path string) (*os.File, error) {
	return openBoundedRegular(path, maxBinaryBytes)
}

// Native server archives include the complete signed agent repository payload.
const maxPackageBytes = 5 << 30

func openBoundedRegular(path string, limit int64) (*os.File, error) {
	cleaned, err := cleanAbsolute(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(cleaned, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: symlink rejected", ErrUnsafePath)
		}
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: not a regular non-hardlinked file", ErrUnsafePath)
	}
	if stat.Mode&unix.S_ISUID != 0 || stat.Mode&unix.S_ISGID != 0 || stat.Mode&0002 != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: setuid or world-writable input rejected", ErrUnsafePath)
	}
	if stat.Size <= 0 || stat.Size > limit {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: binary size rejected", ErrUnsafePath)
	}
	return os.NewFile(uintptr(fd), cleaned), nil
}

func within(path, prefix string) bool {
	path = filepath.Clean(path)
	prefix = filepath.Clean(prefix)
	return path == prefix || strings.HasPrefix(path, prefix+string(os.PathSeparator))
}

func rejectReservedHome(path string, extra []string) error {
	cleaned, err := cleanAbsolute(path)
	if err != nil {
		return err
	}
	reserved := append([]string{stateParent, configDir, "/usr/libexec/lindm"}, extra...)
	for _, prefix := range reserved {
		if prefix == "" {
			continue
		}
		abs, err := cleanAbsolute(prefix)
		if err != nil {
			if filepath.IsAbs(prefix) && filepath.Clean(prefix) == prefix {
				abs = prefix
			} else {
				return fmt.Errorf("%w: rejected key prefix", ErrSigner)
			}
		}
		if within(cleaned, abs) {
			return fmt.Errorf("%w: key home overlaps protected or forbidden state", ErrSigner)
		}
	}
	return nil
}

func privateWork(parent string) (string, func() error, error) {
	work, err := os.MkdirTemp(parent, ".work-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() error {
		return removeWork(work)
	}
	dir, err := openPrivate(work)
	if err != nil {
		_ = cleanup()
		return "", nil, err
	}
	if err := dir.Close(); err != nil {
		_ = cleanup()
		return "", nil, err
	}
	tmp := filepath.Join(work, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		_ = cleanup()
		return "", nil, err
	}
	return work, cleanup, nil
}

func removeWork(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: work directory was replaced", ErrUnsafePath)
	}
	return os.RemoveAll(path)
}

func writeFile(path string, data []byte, mode os.FileMode, epoch int64) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	stamp := time.Unix(epoch, 0)
	return os.Chtimes(path, stamp, stamp)
}

func mkdir(path string, epoch int64) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return err
	}
	stamp := time.Unix(epoch, 0)
	return os.Chtimes(path, stamp, stamp)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func copyFile(dst string, src *os.File, mode os.FileMode, epoch int64) error {
	if _, err := src.Seek(0, 0); err != nil {
		return err
	}
	file, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, copyErr := file.ReadFrom(src)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Chmod(dst, mode); err != nil {
		return err
	}
	stamp := time.Unix(epoch, 0)
	return os.Chtimes(dst, stamp, stamp)
}
