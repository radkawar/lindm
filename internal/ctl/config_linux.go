// Package ctl implements the browser-authorized administrative client. It owns
// pinned transport and private CLI credentials, not server authorization policy.
package ctl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
)

const maxDocumentBytes = 4 << 20

type configStore struct {
	dir  *os.File
	name string
}

// DefaultConfigPath resolves the XDG per-user configuration location.
func DefaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve configuration directory: %w", err)
	}
	return filepath.Join(dir, "lindm", "config.json"), nil
}

func openStore(path string) (_ *configStore, resultErr error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve configuration path: %w", err)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if err := unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, fmt.Errorf("create configuration directory: %w", err)
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			return nil, fmt.Errorf("open configuration directory without symlinks: %w", openErr)
		}
		if err := unix.Close(fd); err != nil {
			return nil, errors.Join(err, unix.Close(next))
		}
		fd = next
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		uid := uint32(os.Geteuid())
		if st.Uid != uid && st.Uid != 0 {
			return nil, errors.New("configuration ancestor has an untrusted owner")
		}
		if st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			return nil, fmt.Errorf("configuration ancestor %q is writable by other users", part)
		}
		if i == len(parts)-1 && (st.Uid != uid || st.Mode&0777 != 0700) {
			return nil, errors.New("configuration directory must be owned by this user with mode 0700")
		}
	}
	copyFD, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(copyFD)
	return &configStore{dir: os.NewFile(uintptr(copyFD), filepath.Dir(path)), name: filepath.Base(path)}, nil
}

func (s *configStore) load() (_ *authv1.CLIConfig, resultErr error) {
	fd, err := unix.Openat(int(s.dir.Fd()), s.name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open protected configuration: %w", err)
	}
	f := os.NewFile(uintptr(fd), s.name)
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, errors.New("configuration must be a singly linked regular file owned by this user with mode 0600")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDocumentBytes {
		return nil, errors.New("configuration exceeds document limit")
	}
	cfg := &authv1.CLIConfig{}
	if err := protojson.Unmarshal(data, cfg); err != nil {
		return nil, errors.New("configuration is not strict CLIConfig protobuf JSON")
	}
	return cfg, nil
}

func samePin(a, b *authv1.CLIConfig) bool {
	return a.GetServerOrigin() == b.GetServerOrigin() && a.GetCaPem() == b.GetCaPem()
}

func (s *configStore) save(cfg *authv1.CLIConfig) (resultErr error) {
	fd := int(s.dir.Fd())
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Flock(fd, unix.LOCK_UN)) }()
	old, err := s.load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if old != nil && !samePin(old, cfg) {
		return errors.New("refusing to replace pinned server origin or CA")
	}
	data, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(cfg)
	if err != nil {
		return errors.New("encode CLI configuration")
	}
	suffix, err := randomToken()
	if err != nil {
		return err
	}
	name := ".config-" + suffix
	tmpFD, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(tmpFD), name)
	defer func() {
		if err := unix.Unlinkat(fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return fmt.Errorf("write protected configuration: %w", err)
	}
	if err := unix.Renameat(fd, name, fd, s.name); err != nil {
		return err
	}
	return s.dir.Sync()
}
