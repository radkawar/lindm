// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// Pending is present only until the first successful readiness check. No secret
// signing material is serialized here: interrupted, unpublished identity creation
// is discarded; a completed identity checkpoint is never regenerated.
type installationProgress struct {
	Binding             string
	Version             string
	Deployment          string
	IdentityReady       bool
	Provisioned         bool
	GeneratedCustodians bool
}

func installationBinding(o Options) (string, error) {
	h := sha256.New()
	// Bind content, not source paths: moving an authenticated bundle is harmless.
	for _, path := range []string{filepath.Join(o.Bundle, "release.json"), filepath.Join(o.Bundle, "installer.sha256"), o.ReleaseKey, o.BackupRecipient, o.DatabaseURL, o.MigrationURL, o.TLSCertificate, o.TLSKey, o.TLSCA} {
		if path == "" {
			_, _ = h.Write([]byte{0})
			continue
		}
		data, err := protected(path, false)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		clear(data)
		_, _ = h.Write([]byte{1})
		_, _ = h.Write(sum[:])
	}
	for _, path := range o.ExecutionRootRecipients {
		data, err := protected(path, false)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		_, _ = h.Write(sum[:])
	}
	configuration, err := json.Marshal(struct {
		Origin, DeviceOrigin, KeyID string
		AdminPort, DevicePort       uint
		Airgap                      bool
		Recipients                  int
	}{o.Origin, o.DeviceOrigin, o.ReleaseKeyID, o.AdminPort, o.DevicePort, o.Airgap, len(o.ExecutionRootRecipients)})
	if err != nil {
		return "", err
	}
	_, _ = h.Write(configuration)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeInstallationState(state *installState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return replaceInstallationState("/etc/lindm/install-state.json", data)
}

func replaceInstallationState(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".install-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

func beginInstallation(o Options, version string) (*installState, error) {
	if _, err := os.Lstat("/etc/lindm/server.json"); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("pre-turnkey manual or laboratory deployment is not a managed upgrade baseline: existing configuration will not be overwritten or rekeyed")
	}
	// Establish exclusive ownership of the bootstrap output namespace before the
	// protected journal authorizes removing any interrupted, unpublished outputs.
	for _, path := range append(identityFiles(), "/etc/lindm/backup-recipient", "/etc/lindm/database-url", "/etc/lindm/migrate/database-url", "/etc/lindm/migrate/server.json", "/etc/systemd/system/lindm-postgresql.service") {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("unmanaged installation artifact %s", path)
		}
	}
	binding, err := installationBinding(o)
	if err != nil {
		return nil, err
	}
	if err := directory("/etc/lindm", 0, 0, 0755); err != nil {
		return nil, err
	}
	state := &installState{Origin: o.Origin, DeviceOrigin: o.DeviceOrigin, TLSCA: "/etc/lindm/transport-ca.crt", LocalDatabase: o.DatabaseURL == "", Pending: &installationProgress{Binding: binding, Version: version, Deployment: uuid.NewString(), GeneratedCustodians: len(o.ExecutionRootRecipients) < 3}}
	if err := writeInstallationState(state); err != nil {
		return nil, err
	}
	return state, nil
}

func validateInstallationResume(state *installState, o Options, version string) error {
	binding, err := installationBinding(o)
	if err != nil {
		return err
	}
	return admitInstallationResume(state, binding, version, o.Rollback)
}

func admitInstallationResume(state *installState, binding, version string, rollback bool) error {
	if rollback || state.Pending == nil || state.Pending.Version != version || state.Pending.Binding != binding {
		return errors.New("in-progress installation requires the same authenticated bundle and provisioning inputs")
	}
	return nil
}

// This list contains only bootstrap outputs; never database files or a published
// server configuration. Once IdentityReady is durable, no output is removed.
func identityFiles() []string {
	return []string{
		"/etc/lindm/device-ca.crt", "/etc/lindm/device-ca.key", "/etc/lindm/server.crt", "/etc/lindm/server.key", "/etc/lindm/transport-ca.crt",
		"/etc/lindm/admin.crt", "/etc/lindm/admin.key", "/etc/lindm/console-ca.crt",
		"/etc/lindm/database-ca.crt", "/etc/lindm/postgresql/server.crt", "/etc/lindm/postgresql/server.key",
		"/etc/lindm/execution-root.json", "/etc/lindm/plan.key", "/etc/lindm/start.key", "/etc/lindm/bootstrap.dsse.json", "/etc/lindm/execution-delegation.json",
		"/etc/lindm/offline/sealed-pki-ca.age", "/etc/lindm/offline/root-key-1.age", "/etc/lindm/offline/root-key-2.age", "/etc/lindm/offline/root-key-3.age",
		"/var/lib/lindmd-operations/recovery-custody.age",
	}
}

func resetUnpublishedIdentity(state *installState) error {
	if state.Pending == nil || state.Pending.IdentityReady {
		return errors.New("cannot discard committed installation identity")
	}
	for _, path := range []string{"/etc/lindm/server.json", "/etc/lindm/migrate/server.json"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("refusing to rekey published installation")
		}
	}
	for _, path := range identityFiles() {
		if err := removeUnpublishedIdentityFile(path); err != nil {
			return err
		}
	}
	return nil
}

func removeUnpublishedIdentityFile(path string) error {
	parent, _, err := custody.OpenRoot(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	unlinkErr := unix.Unlinkat(int(parent.Fd()), filepath.Base(path), 0)
	if errors.Is(unlinkErr, os.ErrNotExist) {
		unlinkErr = nil
	}
	return errors.Join(unlinkErr, parent.Sync(), parent.Close())
}

// Retry only an exact write. This is deliberately not an overwrite primitive:
// existing credentials and configuration remain immutable during bootstrap.
func installationFile(path string, content []byte, uid, gid int, mode os.FileMode) error {
	err := newFile(path, content, uid, gid, mode)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(uid) || stat.Gid != uint32(gid) || os.FileMode(stat.Mode).Perm() != mode.Perm() || stat.Size > 1<<20 {
		return fmt.Errorf("installation artifact custody differs: %s", path)
	}
	existing, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	defer clear(existing)
	if !bytes.Equal(existing, content) {
		return fmt.Errorf("installation artifact differs: %s", path)
	}
	return nil
}
