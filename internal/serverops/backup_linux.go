// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/reflect/protoreflect"

	"lindm/db"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/custody"
	"lindm/internal/executionauthority"
	"lindm/internal/trust"
)

// BackupOptions names protected native inputs. RecipientFile contains only an
// operator-provisioned age public recipient, never a server-generated identity.
type BackupOptions struct {
	Config, RecipientFile, OutputDirectory, HealthPath string
	ConfirmFenced                                      bool
}

type archiveManifest struct {
	Format               int
	CapturedAt           time.Time
	FencedAt             time.Time
	Version              string
	DeploymentID         string
	PublicURL            string
	DevicePublicURL      string
	ConfigPath           string
	DatabaseSHA256       string
	SchemaMinimumRuntime int64
	SchemaVersions       []int64
	ExecutionRootSHA256  string
	MinimumRecoveryEpoch uint64
	Files                []archiveFile
}
type archiveFile struct {
	Path, SHA256, Owner, Group string
	Mode                       uint32
	Size                       int64
}

// Backup produces a complete standard PostgreSQL custom dump plus every native
// configuration/reference and repository file in one age-encrypted tar stream.
// Plaintext staging is private, bounded and removed before returning.
func Backup(ctx context.Context, options BackupOptions) (artifact string, err error) {
	lease, err := AcquireUpgradeLease(ctx)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, lease.Close()) }()
	return backup(ctx, options)
}

func backup(ctx context.Context, options BackupOptions) (artifact string, err error) {
	if os.Geteuid() != 0 {
		return "", errors.New("operations: root_required")
	}
	if err = custody.PrivateDirectory(options.OutputDirectory); err != nil {
		return "", err
	}
	if options.ConfirmFenced {
		if err = drainCheckpointAuthority(ctx); err != nil {
			return "", err
		}
	}
	if options.HealthPath == "" {
		options.HealthPath = BackupHealthPath
	}
	prior, _ := ReadBackupHealth(options.HealthPath)
	health := beginBackupHealth(BackupHealth{}, BackupIdentity{}, time.Now().UTC())
	defer func() {
		if err != nil {
			err = errors.Join(err, writeOperationJSON(options.HealthPath, health, 0644))
		}
	}()
	stage, err := os.MkdirTemp(options.OutputDirectory, ".backup-*")
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	r, err := newResources(options.Config, stage)
	if err != nil {
		return "", err
	}
	identity, err := NewBackupIdentity(r.config)
	if err != nil {
		return "", err
	}
	health = beginBackupHealth(prior, identity, health.LastAttempt)
	connection, err := r.database(r.config.GetDatabase().GetUrlFile())
	if err != nil {
		return "", err
	}
	doc, err := r.validate(options.Config)
	if err != nil {
		return "", err
	}
	cfg, err := doc.Database()
	if err != nil {
		return "", err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return "", errors.New("operations: database_connect_failed")
	}
	defer pool.Close()
	if err = db.Check(ctx, pool); err != nil {
		return "", err
	}
	resolved, err := doc.Resolve()
	if err != nil {
		return "", err
	}
	defer resolved.HTTPClient.CloseIdleConnections()
	var schemaFloor int64
	var schemaVersions []int64
	if err = pool.QueryRow(ctx, "SELECT minimum_runtime_version,migration_versions FROM lindm_schema_compatibility WHERE singleton").Scan(&schemaFloor, &schemaVersions); err != nil {
		return "", errors.New("operations: schema_metadata_unavailable")
	}
	var executionRootDigest string
	var minimumRecoveryEpoch uint64
	if resolved.ExecutionBootstrap != nil {
		store, storeErr := executionauthority.New(ctx, pool, executionauthority.Config{RootJSON: resolved.ExecutionBootstrap.RootJSON, BootstrapEnvelope: resolved.ExecutionBootstrap.Envelope, TLSPublicKey: resolved.ServerCertificate.Leaf.PublicKey})
		if storeErr != nil {
			return "", storeErr
		}
		snapshot, snapshotErr := store.Get(ctx)
		if snapshotErr != nil {
			return "", snapshotErr
		}
		digest, digestErr := trust.ExecutionRootDigest(snapshot.Root)
		if digestErr != nil {
			return "", digestErr
		}
		executionRootDigest = hex.EncodeToString(digest[:])
		minimumRecoveryEpoch = snapshot.Delegation.GetMinimumRecoveryEpoch()
	}
	if options.ConfirmFenced {
		if err = retireCheckpointSource(ctx, options.Config, pool); err != nil {
			return "", err
		}
	}
	if err = r.inventoryBackup(options.Config); err != nil {
		return "", err
	}
	dump, err := dumpDatabase(ctx, stage, connection)
	if err != nil {
		return "", err
	}
	manifest, err := r.manifest(options.Config, dump)
	if err != nil {
		return "", err
	}
	manifest.SchemaMinimumRuntime = schemaFloor
	manifest.SchemaVersions = schemaVersions
	manifest.ExecutionRootSHA256 = executionRootDigest
	manifest.MinimumRecoveryEpoch = minimumRecoveryEpoch
	if options.ConfirmFenced {
		manifest.FencedAt = manifest.CapturedAt
	}
	artifact = filepath.Join(options.OutputDirectory, "lindmd-"+time.Now().UTC().Format("20060102T150405.000000000Z")+".tar.age")
	recipient, err := loadRecipient(options.RecipientFile)
	if err != nil {
		return "", err
	}
	if err = encryptArchive(ctx, artifact, recipient, manifest, r, dump); err != nil {
		return "", err
	}
	if err = recordBackupCompletion(options.HealthPath, artifact, &health); err != nil {
		return "", err
	}
	return artifact, nil
}

func recordBackupCompletion(path, artifact string, health *BackupHealth) error {
	health.LastCompleted = time.Now().UTC()
	health.LastFailure = ""
	health.Encrypted = true
	health.Verified = true
	health.Artifact = filepath.Base(artifact)
	return writeOperationJSON(path, health, 0644)
}

func drainCheckpointAuthority(ctx context.Context) error {
	if err := requireStopped(ctx); err != nil {
		return err
	}
	// Challenges may be future-issued within admitted skew. Every runtime/HA
	// replica must already be externally stopped and fenced by the operator.
	drained := time.NewTimer(trust.MaxDeviceClockSkew + 31*time.Second)
	defer drained.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-drained.C:
		return nil
	}
}

func retireCheckpointSource(ctx context.Context, configPath string, pool *pgxpool.Pool) error {
	target, err := restoreTargetIdentity(ctx, pool)
	if err != nil {
		return err
	}
	if err = enterRestoreHold(target); err != nil {
		return err
	}
	// Fsync the marker before the replica-authoritative database mutation.
	return fenceCheckpointDatabase(ctx, configPath, target)
}

func (r *resourceSet) inventoryBackup(configPath string) error {
	if err := r.backupCustody(); err != nil {
		return err
	}
	if err := r.inventory(r.config.ProtoReflect()); err != nil {
		return err
	}
	// Root inventories migrator files without granting runtime access.
	for _, native := range []string{filepath.Join(filepath.Dir(configPath), "migrate", "server.json"), filepath.Join(filepath.Dir(configPath), "postgresql", "server.key")} {
		if info, err := os.Lstat(native); err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				return errors.New("operations: unsafe_native_custody")
			}
			r.owners[stat.Uid] = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := r.migrationInventory(filepath.Join(filepath.Dir(configPath), "migrate", "server.json")); err != nil {
		return err
	}
	if err := r.tree(filepath.Dir(configPath)); err != nil {
		return err
	}
	if r.base == "/etc/lindm" {
		for _, directory := range []string{"/var/lib/lindmd", "/var/lib/lindmd-operations"} {
			if _, err := os.Lstat(directory); err == nil {
				if err = r.tree(directory); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func beginBackupHealth(prior BackupHealth, identity BackupIdentity, attempt time.Time) BackupHealth {
	if !BackupHealthMatches(prior, identity) {
		prior = BackupHealth{}
	}
	prior.Identity = identity
	prior.LastAttempt = attempt
	prior.LastFailure = "backup_failed"
	prior.Verified = false
	return prior
}

func (r *resourceSet) inventory(message protoreflect.Message) error {
	var failure error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() == protoreflect.MessageKind {
			if field.IsList() {
				for i := range value.List().Len() {
					failure = r.inventory(value.List().Get(i).Message())
					if failure != nil {
						return false
					}
				}
			} else if !field.IsMap() {
				failure = r.inventory(value.Message())
			}
			return failure == nil
		}
		if field.Kind() == protoreflect.StringKind && value.String() != "" && (field.Name() == "directory" || strings.HasSuffix(string(field.Name()), "_directory")) {
			failure = r.tree(r.reference(value.String()))
		}
		return failure == nil
	})
	return failure
}

func (r *resourceSet) tree(path string) error {
	return filepath.WalkDir(path, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("operations: symlink_in_backup_inventory")
		}
		if entry.IsDir() {
			if name == recoveryCustodyDirectory || name == "/var/lib/lindmd-operations/setup" {
				return fs.SkipDir
			}
			return nil
		}
		if name == restoreMarker || filepath.Base(name) == "backup-health.json" {
			return nil
		}
		return r.copy(name)
	})
}

func digestFile(path string) (_ string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, maxArchive+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *resourceSet) manifest(configPath, dump string) (archiveManifest, error) {
	manifest := archiveManifest{Format: 1, CapturedAt: time.Now().UTC(), Version: buildinfo.Version, DeploymentID: r.config.GetDeploymentId(), PublicURL: r.config.GetPublicUrl(), DevicePublicURL: r.config.GetDevicePublicUrl(), ConfigPath: configPath}
	var err error
	manifest.DatabaseSHA256, err = digestFile(dump)
	if err != nil {
		return manifest, err
	}
	var paths []string
	for path := range r.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		info, ok := r.metadata[path]
		if !ok {
			return manifest, errors.New("operations: missing_inventory_custody")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return manifest, errors.New("operations: missing custody metadata")
		}
		// URL custody is fixed policy, not service-role metadata to carry forward
		// from the source host. The archive records account names, never numeric IDs.
		if r.databaseCredentials[path] && (stat.Uid != 0 || stat.Gid != 0 || stat.Mode&07777 != 0600) {
			return manifest, errors.New("operations: root_private_database_credential_required")
		}
		owner, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
		if err != nil {
			return manifest, err
		}
		group, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10))
		if err != nil {
			return manifest, err
		}
		digest, err := digestFile(r.files[path])
		if err != nil {
			return manifest, err
		}
		manifest.Files = append(manifest.Files, archiveFile{Path: path, SHA256: digest, Owner: owner.Username, Group: group.Name, Mode: uint32(info.Mode().Perm()), Size: info.Size()})
	}
	return manifest, nil
}

func encryptArchive(ctx context.Context, path string, recipient age.Recipient, manifest archiveManifest, r *resourceSet, dump string) (err error) {
	output, err := os.OpenFile(path+".partial", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := os.Remove(path + ".partial"); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	encrypted, err := age.Encrypt(&boundedWriter{output, maxArchive}, recipient)
	if err != nil {
		return errors.Join(err, output.Close())
	}
	err = writeArchive(&contextWriter{ctx: ctx, writer: encrypted}, manifest, r, dump)
	err = errors.Join(err, encrypted.Close(), output.Sync(), output.Close())
	if err != nil {
		return err
	}
	return os.Rename(path+".partial", path)
}

func writeArchive(writer io.Writer, manifest archiveManifest, r *resourceSet, dump string) (err error) {
	archive := tar.NewWriter(&boundedWriter{writer, maxArchive})
	defer func() { err = errors.Join(err, archive.Close()) }()
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err = archive.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(data))}); err != nil {
		return err
	}
	if _, err = archive.Write(data); err != nil {
		return err
	}
	if err = archiveEntry(archive, "database.dump", dump); err != nil {
		return err
	}
	for _, entry := range manifest.Files {
		if err = archiveEntry(archive, "files/"+strings.TrimPrefix(entry.Path, "/"), r.files[entry.Path]); err != nil {
			return err
		}
	}
	return nil
}

func archiveEntry(archive *tar.Writer, name, path string) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if err = archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: info.Size()}); err != nil {
		return err
	}
	_, err = io.Copy(archive, file)
	return err
}
