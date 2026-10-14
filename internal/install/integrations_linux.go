// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
	"lindm/internal/custody"
)

const nativeIntegrationKey = "/etc/lindm/integrations.key"

// A configured source must remain available and valid: a missing source is never
// permission to generate replacement bytes for existing ciphertext.
func ensureIntegrationKey(path, configuredSource string) error {
	var source []byte
	if configuredSource != "" {
		var err error
		source, err = readIntegrationSource(configuredSource)
		if err != nil {
			return err
		}
		defer clear(source)
	}
	existing, err := readIntegrationSource(path)
	if err == nil {
		defer clear(existing)
		if source != nil && !bytes.Equal(source, existing) {
			return errors.New("native integration key differs from the configured key; rekey refused")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if source == nil {
		source = make([]byte, 32)
		defer clear(source)
		if _, err := rand.Read(source); err != nil {
			return err
		}
	}
	if err := atomicNativeFile(path, source, 0, 0, nil); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		// Another create-only publisher won. Preserve it only if valid, and when
		// migrating a configured source insist on the exact same key bytes.
		return ensureIntegrationKey(path, configuredSource)
	}
	return nil
}

func readIntegrationSource(path string) (key []byte, err error) {
	file, before, err := custody.OpenRoot(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			clear(key)
			key = nil
		}
	}()
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != 0 || before.Mode&07777 != 0600 || before.Nlink != 1 || before.Size != 32 {
		return nil, errors.New("native integration key must be root:root 0600 with exactly 32 raw bytes and one link")
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(file, key); err != nil {
		clear(key)
		return nil, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		clear(key)
		return nil, err
	}
	if !sameNativeFile(before, after) {
		clear(key)
		return nil, errors.New("native integration key changed while being read")
	}
	return key, nil
}

func sameNativeFile(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode && before.Uid == after.Uid && before.Gid == after.Gid && before.Nlink == after.Nlink && before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

// Publish a completely written, synced inode through a pinned root directory.
// A new key uses RENAME_NOREPLACE; managed config updates additionally require
// the existing inode and its custody to match the version that was loaded.
func atomicNativeFile(path string, data []byte, uid, gid int, expected *unix.Stat_t) (err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return custody.ErrUnsafe
	}
	parent, _, err := custody.OpenRoot(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	fd := int(parent.Fd())
	temporary := ".lindm-secret-" + uuid.NewString()
	leaf, err := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(leaf), temporary)
	defer func() {
		removeErr := unix.Unlinkat(fd, temporary, 0)
		if errors.Is(removeErr, unix.ENOENT) {
			removeErr = nil
		}
		err = errors.Join(err, file.Close(), removeErr)
	}()
	if err := file.Chown(uid, gid); err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	name := filepath.Base(path)
	flags := uint(unix.RENAME_NOREPLACE)
	if expected != nil {
		var current unix.Stat_t
		if err := unix.Fstatat(fd, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if !sameNativeFile(*expected, current) {
			return errors.New("managed configuration changed before publication")
		}
		flags = 0
	}
	if err := unix.Renameat2(fd, temporary, fd, name, flags); err != nil {
		return err
	}
	return parent.Sync()
}

func enableNativeIntegrations() error {
	uid, _, err := account("lindmd")
	if err != nil {
		return err
	}
	muid, _, err := account("lindmd-migrate")
	if err != nil {
		return err
	}
	return enableNativeIntegrationsAt("/etc/lindm/server.json", "/etc/lindm/migrate/server.json", nativeIntegrationKey, uid, muid)
}

func enableNativeIntegrationsAt(runtimePath, migrationPath, keyPath string, uid, muid int) error {
	runtimeConfig, runtimeStat, err := loadNativeConfig(runtimePath, uid)
	if err != nil {
		return err
	}
	migrationConfig, migrationStat, err := loadNativeConfig(migrationPath, muid)
	if err != nil {
		return err
	}
	source := runtimeConfig.GetIntegrations().GetEncryptionKeyFile()
	if runtimeConfig.GetIntegrations() != nil {
		if source == "" {
			return errors.New("configured integration key source is missing; rekey refused")
		}
		if !filepath.IsAbs(source) {
			source = filepath.Join(filepath.Dir(runtimePath), source)
		}
	}
	if err := ensureIntegrationKey(keyPath, source); err != nil {
		return err
	}
	if runtimeConfig.GetIntegrations().GetEncryptionKeyFile() != keyPath {
		if runtimeConfig.Integrations == nil {
			runtimeConfig.Integrations = &configv1.IntegrationsConfig{}
		}
		runtimeConfig.Integrations.EncryptionKeyFile = keyPath
		if err := replaceNativeConfig(runtimePath, runtimeConfig, runtimeStat); err != nil {
			return err
		}
	}
	if migrationConfig.Integrations != nil {
		migrationConfig.Integrations = nil
		return replaceNativeConfig(migrationPath, migrationConfig, migrationStat)
	}
	return nil
}

func replaceNativeConfig(path string, cfg *configv1.ServerConfig, before unix.Stat_t) error {
	data, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(cfg)
	if err != nil {
		return err
	}
	return atomicNativeFile(path, data, int(before.Uid), int(before.Gid), &before)
}

// Root may inspect a role-owned config, not resolve its runtime secrets. Stage
// only its checked bytes for the existing strict config loader/validator.
func loadNativeConfig(path string, uid int) (_ *configv1.ServerConfig, stat unix.Stat_t, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, stat, custody.ErrUnsafe
	}
	parent, _, err := custody.OpenRoot(filepath.Dir(path), unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, stat, err
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, stat, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&07777 != 0600 || (stat.Uid != 0 && stat.Uid != uint32(uid)) || stat.Size < 0 || stat.Size > 1<<20 {
		return nil, stat, errors.New("unsafe managed configuration")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, stat, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, stat, err
	}
	if len(data) > 1<<20 || !sameNativeFile(stat, after) {
		return nil, stat, errors.New("managed configuration changed while being read")
	}
	stage, err := os.MkdirTemp("/run", "lindm-integration-config-")
	if err != nil {
		return nil, stat, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	stagedPath := filepath.Join(stage, "server.json")
	if err := newFile(stagedPath, data, 0, 0, 0600); err != nil {
		return nil, stat, err
	}
	document, err := config.Load(stagedPath)
	if err != nil {
		return nil, stat, err
	}
	return document.Proto, stat, nil
}

// Publish and validate the exact application key before the upgrade backup.
// The backup must cover the same runtime configuration used after migration.
func prepareNativeIntegrationUpgrade(ctx context.Context, binary string) error {
	if err := enableNativeIntegrations(); err != nil {
		return err
	}
	return checkRuntimeConfigBinary(ctx, binary)
}
