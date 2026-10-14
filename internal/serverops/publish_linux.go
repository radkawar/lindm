// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
	"lindm/internal/custody"
)

func ownerIDs(ownerName, groupName string) (int, int, error) {
	owner, err := user.Lookup(ownerName)
	if err != nil {
		return 0, 0, err
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(group.Gid)
	return uid, gid, err
}

// publishPrivate pins directory descriptors throughout the write and rename;
// symlink substitution by a compromised service account never redirects root.
func publishPrivate(path string, input io.Reader, uid, gid int, mode uint32) (err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("operations: invalid_restore_path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		created := false
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(fd, part, 0700); mkdirErr != nil {
				return errors.Join(mkdirErr, unix.Close(fd))
			}
			created = true
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		closeErr := unix.Close(fd)
		if openErr != nil {
			return errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return errors.Join(closeErr, unix.Close(next))
		}
		fd = next
		if created {
			if err = unix.Fchown(fd, uid, gid); err != nil {
				return errors.Join(err, unix.Close(fd))
			}
		}
		var stat unix.Stat_t
		if err = unix.Fstat(fd, &stat); err != nil {
			return errors.Join(err, unix.Close(fd))
		}
		if (stat.Uid != 0 && stat.Uid != uint32(uid)) || stat.Mode&0022 != 0 {
			return errors.Join(errors.New("operations: unsafe_restore_ancestry"), unix.Close(fd))
		}
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	name := ".lindmd-restore-" + filepath.Base(path)
	fileFD, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fileFD), name)
	defer func() {
		removeErr := unix.Unlinkat(fd, name, 0)
		if removeErr != nil && !errors.Is(removeErr, unix.ENOENT) {
			err = errors.Join(err, removeErr)
		}
	}()
	_, copyErr := io.Copy(&boundedWriter{file, maxArchive}, input)
	if copyErr != nil {
		return errors.Join(copyErr, file.Close())
	}
	if err = file.Chown(uid, gid); err != nil {
		return errors.Join(err, file.Close())
	}
	if err = file.Chmod(os.FileMode(mode)); err != nil {
		return errors.Join(err, file.Close())
	}
	if err = errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	if err = unix.Renameat(fd, name, fd, filepath.Base(path)); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func publishRestoredFiles(manifest archiveManifest, r *resourceSet, migrationTarget, runtimeTarget *stagedDatabase) (err error) {
	if r.base == "/etc/lindm" && r.files[RecoveryCustodyBundlePath] == "" {
		// Its distinct fresh database export was preserved before this point.
		// Do not misidentify the discarded target authority bundle as the source.
		if removeErr := os.Remove(RecoveryCustodyBundlePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
	}
	databaseCredentials := map[string]bool{}
	for _, path := range []string{r.config.GetDatabase().GetUrlFile(), r.config.GetDatabase().GetMigrationUrlFile()} {
		if path != "" {
			databaseCredentials[r.reference(path)] = true
		}
	}
	for path := range r.databaseCredentials {
		databaseCredentials[path] = true
	}
	// The archive's migrator configuration is a separate resource. Its old URL
	// must not be imported even when it uses a non-native filename.
	migrationConfig := filepath.Join(r.base, "migrate", "server.json")
	if staged, ok := r.files[migrationConfig]; ok {
		document, loadErr := config.Load(staged)
		if loadErr != nil {
			return loadErr
		}
		for _, path := range []string{document.Proto.GetDatabase().GetUrlFile(), document.Proto.GetDatabase().GetMigrationUrlFile()} {
			if path != "" {
				if !filepath.IsAbs(path) {
					path = filepath.Join(filepath.Dir(migrationConfig), path)
				}
				databaseCredentials[path] = true
			}
		}
	}
	databaseCredentials[runtimeTarget.urlFile] = true
	databaseCredentials[migrationTarget.urlFile] = true
	for _, entry := range manifest.Files {
		// The target cluster's credentials and server TLS are provisioned on the
		// fresh host, not recovered device/application trust.
		if entry.Path == restoreMarker || databaseCredentials[entry.Path] || entry.Path == "/etc/lindm/install-state.json" || strings.HasPrefix(entry.Path, "/etc/lindm/postgresql/") || strings.HasPrefix(entry.Path, "/etc/lindm/database-restored/") || strings.HasPrefix(entry.Path, "/etc/lindm/migrate/database-restored/") {
			continue
		}
		if strings.HasPrefix(entry.Path, "/var/lib/lindmd-operations/database-custody/") {
			continue
		}
		name, directory := filepath.Base(entry.Path), filepath.Dir(entry.Path)
		if (directory == "/etc/lindm" || directory == "/etc/lindm/migrate") && (name == "database-url" || name == "database-ca.crt" || name == "external-database-ca.crt" || name == "external-database-client.crt" || name == "external-database-client.key") {
			continue
		}
		uid, gid, err := ownerIDs(entry.Owner, entry.Group)
		if err != nil {
			return err
		}
		file, err := os.Open(r.files[entry.Path])
		if err != nil {
			return err
		}
		publishErr := publishPrivate(entry.Path, file, uid, gid, entry.Mode)
		if err = errors.Join(publishErr, file.Close()); err != nil {
			return err
		}
	}
	return preserveTargetDatabases(migrationTarget, runtimeTarget, r.config)
}

func preserveDatabaseURL(credential, destination, directory string, uid, gid int) error {
	data, err := custody.ReadRoot(credential, maxResource, false)
	defer clear(data)
	if err != nil {
		return err
	}
	connection := bytes.TrimSpace(data)
	u, err := databaseURL(string(connection))
	if err != nil {
		return err
	}
	query := u.Query()
	for _, name := range []string{"sslrootcert", "sslcert", "sslkey"} {
		source := query.Get(name)
		if source == "" || source == "system" {
			continue
		}
		content, err := custody.ReadRoot(source, maxResource, false)
		if err != nil {
			clear(content)
			return err
		}
		target := filepath.Join(directory, name)
		publishErr := publishPrivate(target, bytes.NewReader(content), uid, gid, 0600)
		clear(content)
		if publishErr != nil {
			return publishErr
		}
		query.Set(name, target)
	}
	base, _, _ := bytes.Cut(connection, []byte("?"))
	encoded := strings.ReplaceAll(query.Encode(), "+", "%20")
	rewritten := make([]byte, 0, len(base)+1+len(encoded))
	rewritten = append(rewritten, base...)
	rewritten = append(rewritten, '?')
	rewritten = append(rewritten, encoded...)
	defer clear(rewritten)
	// systemd LoadCredential reads the original root-owned stable destination.
	// Only the role-owned TLS resources move into database-restored.
	return publishPrivate(destination, bytes.NewReader(rewritten), 0, 0, 0600)
}

func preserveTargetDatabases(migrationTarget, runtimeTarget *stagedDatabase, original *configv1.ServerConfig) error {
	if err := preserveDatabaseURL(runtimeTarget.document.Proto.GetDatabase().GetUrlFile(), runtimeTarget.urlFile, filepath.Join(filepath.Dir(runtimeTarget.configPath), "database-restored"), runtimeTarget.uid, runtimeTarget.gid); err != nil {
		return err
	}
	if err := preserveDatabaseURL(migrationTarget.document.Proto.GetDatabase().GetMigrationUrlFile(), migrationTarget.urlFile, filepath.Join(filepath.Dir(migrationTarget.configPath), "database-restored"), migrationTarget.uid, migrationTarget.gid); err != nil {
		return err
	}
	runtime := proto.CloneOf(original)
	runtime.Database.UrlFile = runtimeTarget.urlFile
	runtime.Database.MigrationUrlFile = nil
	data, err := protojson.Marshal(runtime)
	if err != nil {
		return err
	}
	if err = publishPrivate(runtimeTarget.configPath, bytes.NewReader(data), runtimeTarget.uid, runtimeTarget.gid, 0600); err != nil {
		return err
	}
	migration := proto.CloneOf(original)
	migration.Database.UrlFile = migrationTarget.urlFile
	migration.Database.MigrationUrlFile = &migrationTarget.urlFile
	data, err = protojson.Marshal(migration)
	if err != nil {
		return err
	}
	return publishPrivate(migrationTarget.configPath, bytes.NewReader(data), migrationTarget.uid, migrationTarget.gid, 0600)
}

func restrictRestoredMetadata(ctx context.Context, pool *pgxpool.Pool, runtimeRole string) error {
	role := pgx.Identifier{runtimeRole}.Sanitize()
	for _, table := range []string{"goose_db_version", "lindm_schema_compatibility", "server_recovery_state", "first_run_setup"} {
		var schema string
		if err := pool.QueryRow(ctx, "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=$1::regclass", table).Scan(&schema); err != nil {
			return err
		}
		identifier := pgx.Identifier{schema, table}.Sanitize()
		if _, err := pool.Exec(ctx, "REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON "+identifier+" FROM PUBLIC"); err != nil {
			return err
		}
		rows, err := pool.Query(ctx, "SELECT DISTINCT r.rolname FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a JOIN pg_roles r ON r.oid=a.grantee WHERE c.oid=$1::regclass AND a.grantee<>c.relowner", identifier)
		if err != nil {
			return err
		}
		var grantees []string
		for rows.Next() {
			var grantee string
			if err = rows.Scan(&grantee); err != nil {
				rows.Close()
				return err
			}
			grantees = append(grantees, grantee)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		for _, grantee := range grantees {
			if _, err = pool.Exec(ctx, "REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON "+identifier+" FROM "+pgx.Identifier{grantee}.Sanitize()); err != nil {
				return err
			}
		}
		if _, err = pool.Exec(ctx, "REVOKE ALL ON "+identifier+" FROM "+role); err != nil {
			return err
		}
		if _, err = pool.Exec(ctx, "GRANT SELECT ON "+identifier+" TO "+role); err != nil {
			return err
		}
		if table == "first_run_setup" {
			if _, err = pool.Exec(ctx, "GRANT UPDATE(account_id,consumed_at) ON "+identifier+" TO "+role); err != nil {
				return err
			}
		}
	}
	var sequenceSchema, sequenceName string
	sequenceErr := pool.QueryRow(ctx, "SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_get_serial_sequence('goose_db_version','id')::regclass").Scan(&sequenceSchema, &sequenceName)
	if sequenceErr != nil && !errors.Is(sequenceErr, pgx.ErrNoRows) {
		return sequenceErr
	}
	if sequenceErr == nil {
		if _, err := pool.Exec(ctx, "REVOKE ALL ON SEQUENCE "+pgx.Identifier{sequenceSchema, sequenceName}.Sanitize()+" FROM "+role); err != nil {
			return err
		}
	}
	return nil
}
