// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type systemdCredential struct {
	directory string
	name      string
	kind      string
}

// UseDatabaseURLCredential selects an explicit systemd credential for database
// reads only. Serialized references and the config-relative database TLS paths
// remain unchanged. Callers must supply CREDENTIALS_DIRECTORY, never a persistent
// URL path; an unavailable or unsafe credential has no fallback.
func (d *Document) UseDatabaseURLCredential(name, directory string) error {
	credential, err := selectSystemdCredential(name, directory, "database")
	if err != nil {
		return err
	}
	d.databaseURLCredential = credential
	return nil
}

// UseIntegrationEncryptionKeyCredential selects an explicit systemd credential
// without changing the persistent integrations.encryption_key_file reference.
// Unsafe or unavailable credentials never fall back to that persistent source.
func (d *Document) UseIntegrationEncryptionKeyCredential(name, directory string) error {
	credential, err := selectSystemdCredential(name, directory, "integration encryption key")
	if err != nil {
		return err
	}
	d.integrationEncryptionKeyCredential = credential
	return nil
}

func selectSystemdCredential(name, directory, kind string) (*systemdCredential, error) {
	if name == "" || name == "." || name == ".." || len(name) > 255 {
		return nil, fmt.Errorf("%s credential requires a valid credential name", kind)
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return nil, fmt.Errorf("%s credential requires a valid credential name", kind)
		}
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" || strings.ContainsRune(directory, 0) {
		return nil, fmt.Errorf("%s credential requires a clean absolute CREDENTIALS_DIRECTORY", kind)
	}
	return &systemdCredential{directory: directory, name: name, kind: kind}, nil
}

// Pin the private directory and open its single named leaf without following a
// symlink. Unlike persistent resource gates, this boundary admits systemd's
// read-only 0400 file and 0500 directory, still owned by root or the service UID.
func (c *systemdCredential) read() (_ []byte, err error) {
	fd, err := c.openDirectory()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	leaf, err := unix.Openat(fd, c.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(leaf), c.name)
	defer func() { err = errors.Join(err, file.Close()) }()
	var before unix.Stat_t
	if err := unix.Fstat(leaf, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || (before.Uid != 0 && before.Uid != uint32(os.Geteuid())) || (before.Mode&07777 != 0400 && before.Mode&07777 != 0600) || before.Size < 0 || before.Size > maxFileBytes {
		return nil, fmt.Errorf("%s credential must be a bounded private regular file owned by root or the service user", c.kind)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		clear(data)
		return nil, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(leaf, &after); err != nil {
		clear(data)
		return nil, err
	}
	if len(data) > maxFileBytes || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		clear(data)
		return nil, fmt.Errorf("%s credential changed while being read or exceeds 1 MiB", c.kind)
	}
	return data, nil
}

func (c *systemdCredential) openDirectory() (fd int, err error) {
	fd, err = unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer func() {
		if err != nil && fd >= 0 {
			err = errors.Join(err, unix.Close(fd))
		}
	}()
	var root unix.Stat_t
	if err := unix.Fstat(fd, &root); err != nil {
		return fd, err
	}
	if root.Uid != 0 || root.Mode&0022 != 0 {
		return fd, fmt.Errorf("%s credential directory has replaceable root ancestry", c.kind)
	}
	parts := strings.Split(c.directory[1:], "/")
	for i, part := range parts {
		flags := unix.O_PATH
		if i == len(parts)-1 {
			flags = unix.O_RDONLY
		}
		next, openErr := unix.Openat(fd, part, flags|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		closeErr := unix.Close(fd)
		fd = next
		if openErr != nil {
			return -1, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return fd, closeErr
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return fd, err
		}
		if (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || (stat.Mode&0022 != 0 && (stat.Uid != 0 || stat.Mode&unix.S_ISVTX == 0)) {
			return fd, fmt.Errorf("%s credential directory ancestry must be owned and non-replaceable", c.kind)
		}
		if i == len(parts)-1 && stat.Mode&07777 != 0500 && stat.Mode&07777 != 0700 {
			return fd, fmt.Errorf("%s credential directory must be private", c.kind)
		}
	}
	return fd, nil
}
