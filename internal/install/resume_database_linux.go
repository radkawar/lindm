// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func initializeInstallationDatabase(ctx context.Context, data, bin string, uid, gid int) error {
	if _, err := os.Stat(filepath.Join(data, "PG_VERSION")); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if entries, err := os.ReadDir(data); err == nil && len(entries) > 0 {
		return errors.New("refusing to initialize nonempty database directory without PG_VERSION")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(data), 0755); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(filepath.Dir(data), ".lindm-initdb-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	if err := os.Chown(temporary, uid, gid); err != nil {
		return err
	}
	if _, err := command(ctx, nil, "runuser", "-u", "postgres", "--", bin+"initdb", "-D", temporary, "--auth-local=peer", "--auth-host=scram-sha-256", "--encoding=UTF8", "--locale=C"); err != nil {
		return err
	}
	// initdb fsyncs its output. Publish only a complete cluster; an interrupted
	// initdb can never be mistaken for a live database on the next invocation.
	if err := os.Rename(temporary, data); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(data))
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

func installationDatabasePasswords(port string) ([]string, error) {
	passwords := make([]string, 2)
	for i, item := range []struct{ role, path, ca string }{
		{"lindm_runtime", "/etc/lindm/database-url", "/etc/lindm/database-ca.crt"},
		{"lindm_migrator", "/etc/lindm/migrate/database-url", "/etc/lindm/migrate/database-ca.crt"},
	} {
		password, err := installationDatabasePassword(item.path, item.role, port, item.ca)
		if err != nil {
			return nil, err
		}
		passwords[i] = password
	}
	return passwords, nil
}

func installationDatabasePassword(path, role, port, ca string) (string, error) {
	data, err := protected(path, true)
	if errors.Is(err, os.ErrNotExist) {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		password := base64.RawURLEncoding.EncodeToString(raw[:])
		clear(raw[:])
		if err := newDatabaseURL(path, []byte(localDatabaseURL(role, password, port, ca))); err != nil {
			return "", err
		}
		return password, nil
	}
	if err != nil {
		return "", err
	}
	defer clear(data)
	parsed, err := url.Parse(strings.TrimSpace(string(data)))
	if err != nil || parsed.User == nil {
		return "", errors.New("invalid persisted bootstrap database credential")
	}
	password, ok := parsed.User.Password()
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(password)
	defer clear(decoded)
	if !ok || decodeErr != nil || len(decoded) != 32 || string(data) != localDatabaseURL(role, password, port, ca) {
		return "", fmt.Errorf("persisted bootstrap database credential differs: %s", path)
	}
	return password, nil
}
