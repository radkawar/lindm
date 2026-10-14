// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"lindm/internal/config"
)

// rotatedRoles maps each PostgreSQL login role of the maintained fixture to
// the file holding its password.
var rotatedRoles = []struct{ role, file string }{
	{"postgres", "postgres-password"},
	{"lindm_migrator", "migrator-password"},
	{"lindm_runtime", "runtime-password"},
}

// RotateCredentials replaces every PostgreSQL role password of the running
// fixture and rewrites the files derived from them (password files, both
// DSNs, database-init.sql and the manifest). It keeps data, certificates and
// the IdP secrets. New files are staged before the roles change, and the role
// changes commit in one transaction. A running lindmd keeps its sessions but
// must be restarted before it can open new ones.
func RotateCredentials(ctx context.Context, repoRoot string) error {
	return locked(ctx, repoRoot, func(root string) (resultErr error) {
		dir := FixturePath(root)
		if err := validateFixture(dir); err != nil {
			return err
		}
		if err := verifyRunningPostgres(ctx, root); err != nil {
			return err
		}
		document, err := config.Load(filepath.Join(dir, "server.json"))
		if err != nil {
			return err
		}
		migration, err := document.MigrationDatabase()
		if err != nil {
			return err
		}
		if _, err := recreationTarget(migration.ConnConfig); err != nil {
			return err
		}
		current, err := readOwned(filepath.Join(dir, "postgres-password"))
		if err != nil {
			return err
		}
		defer clear(current)
		admin := migration.ConnConfig.Copy()
		admin.User, admin.Password, admin.Database = "postgres", strings.TrimSpace(string(current)), "postgres"

		secrets := make(map[string]string, len(rotatedRoles))
		for _, r := range rotatedRoles {
			var raw [32]byte
			if _, err := rand.Read(raw[:]); err != nil {
				return err
			}
			secrets[r.file] = base64.RawURLEncoding.EncodeToString(raw[:])
		}
		files := rotatedFixtureFiles(dir, secrets)
		staged, err := stageFixtureFiles(dir, files)
		if err != nil {
			return err
		}
		keepStaged := false
		defer func() {
			if !keepStaged {
				resultErr = errors.Join(resultErr, os.RemoveAll(staged))
			}
		}()

		conn, err := pgx.ConnectConfig(ctx, admin)
		if err != nil {
			return errors.New("connect fixture PostgreSQL administration over verified TLS failed")
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, conn.Close(cleanup))
		}()
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			for _, r := range rotatedRoles {
				// ALTER ROLE takes no bind parameters; passwords are base64url.
				if _, err := tx.Exec(ctx, "ALTER ROLE "+pgx.Identifier{r.role}.Sanitize()+" PASSWORD '"+secrets[r.file]+"'"); err != nil {
					return fmt.Errorf("rotate %s password: %w", r.role, err)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		// The roles now hold the new passwords. Install the staged files; the
		// manifest goes last, so a partial install fails validation instead of
		// leaving stale credentials marked as valid.
		if err := installFixtureFiles(dir, staged, files); err != nil {
			keepStaged = true
			return fmt.Errorf("role passwords rotated but fixture files were not fully installed; staged copies remain in %s: %w", staged, err)
		}
		return nil
	})
}

// rotatedFixtureFiles returns the contents of every fixture file derived from
// the PostgreSQL passwords. initialize produces the same files at creation.
func rotatedFixtureFiles(dir string, secrets map[string]string) map[string][]byte {
	files := make(map[string][]byte, len(rotatedRoles)+3)
	for _, r := range rotatedRoles {
		files[r.file] = []byte(secrets[r.file])
	}
	files["database-url"] = fixtureDSN(dir, "lindm_runtime", secrets["runtime-password"])
	files["migration-database-url"] = fixtureDSN(dir, "lindm_migrator", secrets["migrator-password"])
	files["database-init.sql"] = []byte(databaseRoleSQL(secrets["migrator-password"], secrets["runtime-password"]) + applicationDatabaseSQL)
	return files
}

func fixtureDSN(dir, role, password string) []byte {
	u := url.URL{Scheme: "postgresql", User: url.UserPassword(role, password), Host: "localhost:15432", Path: "/lindm"}
	u.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {filepath.Join(dir, "transport-ca.crt")}}.Encode()
	return []byte(u.String())
}

// stageFixtureFiles writes files at 0600 into a private sibling directory, so
// installing them is a same-filesystem rename.
func stageFixtureFiles(dir string, files map[string][]byte) (string, error) {
	staged, err := os.MkdirTemp(filepath.Dir(dir), ".dev-rotate-")
	if err != nil {
		return "", err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(staged, name), data, 0600); err != nil {
			return "", errors.Join(err, os.RemoveAll(staged))
		}
	}
	return staged, nil
}

func installFixtureFiles(dir, staged string, files map[string][]byte) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	for name, data := range files {
		digest := sha256.Sum256(data)
		m.Files[name] = hex.EncodeToString(digest[:])
	}
	encoded, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(staged, "manifest.json"), encoded, 0600); err != nil {
		return err
	}
	for name := range files {
		if err := os.Rename(filepath.Join(staged, name), filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return os.Rename(filepath.Join(staged, "manifest.json"), filepath.Join(dir, "manifest.json"))
}
