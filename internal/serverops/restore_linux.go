// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"

	"lindm/db"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/auditkind"
	"lindm/internal/config"
	"lindm/internal/custody"
	"lindm/internal/executionauthority"
	"lindm/internal/trust"
)

// RestoreOptions requires a freshly provisioned target database and explicit
// ingress fencing. Checkpoint signing keys are never read by Restore.
type RestoreOptions struct {
	Config, Archive, SecurityArchive, SecurityCheckpoint, ExecutionUpdate, IdentityFile, RootFile, Reason string
	IdentityPassphrase                                                                                    []byte
	ConfirmFenced                                                                                         bool
}

// DrillResult distinguishes archive validation from a fresh-host live device
// rehearsal; a decrypt-only check never claims dispatch recovery.
type DrillResult struct {
	CapturedAt            time.Time
	Version, DeploymentID string
	Files                 int
	DatabaseArchiveValid  bool
}

// RestoreDrill validates decryption, every inventory digest, strict configuration,
// PKI/trust bindings and PostgreSQL's actual custom archive parser without DDL.
func RestoreDrill(ctx context.Context, archive, identity string, passphrase []byte) (result DrillResult, err error) {
	stage, err := offlineStage("lindmd-drill-*")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	manifest, err := decryptArchive(ctx, archive, identity, passphrase, stage)
	if err != nil {
		return result, err
	}
	_, document, err := archivedConfiguration(manifest, stage)
	if err != nil {
		return result, err
	}
	resources, err := document.Resolve()
	if err != nil {
		return result, err
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if _, _, err = checkDatabaseArchive(ctx, filepath.Join(stage, "database.dump")); err != nil {
		return result, err
	}
	return DrillResult{CapturedAt: manifest.CapturedAt, Version: manifest.Version, DeploymentID: manifest.DeploymentID, Files: len(manifest.Files), DatabaseArchiveValid: true}, nil
}

func requireStopped(ctx context.Context) error {
	var output bytes.Buffer
	if err := runTool(ctx, "systemctl", []string{"show", "lindmd.service", "--property=LoadState", "--property=ActiveState", "--value"}, cleanEnvironment(), nil, &boundedWriter{&output, 1024}); err != nil {
		return err
	}
	text := output.String()
	if !bytes.Contains([]byte(text), []byte("loaded\n")) || (!bytes.Contains([]byte(text), []byte("inactive\n")) && !bytes.Contains([]byte(text), []byte("failed\n"))) {
		return errors.New("operations: stop_runtime_before_recovery")
	}
	return nil
}

// Restore recovers the independently attested checkpoint's complete state. The
// earlier archive is validated and bound by the signature, but is not falsely
// described as containing data added after its capture. All work is fenced before
// mutation, and any partial failure retains the persistent root hold.
func Restore(ctx context.Context, options RestoreOptions) (result DrillResult, err error) {
	lease, err := AcquireUpgradeLease(ctx)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, lease.Close()) }()
	return restore(ctx, options)
}

func restore(ctx context.Context, options RestoreOptions) (result DrillResult, err error) {
	if os.Geteuid() != 0 || !options.ConfirmFenced || strings.TrimSpace(options.Reason) == "" {
		return result, errors.New("operations: fenced_root_restore_and_reason_required")
	}
	if err = requireStopped(ctx); err != nil {
		return result, err
	}
	stage, stageCleanup, err := prepareRestoreStage(options.Archive, options.SecurityArchive)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, stageCleanup()) }()
	var checkpoint restoreCheckpoint
	if err = prepareRestoreCheckpoint(ctx, options, stage, &checkpoint); err != nil {
		return result, err
	}
	defer checkpoint.resources.HTTPClient.CloseIdleConnections()
	current := &checkpoint.current
	inventory := checkpoint.inventory
	migrationTarget, cleanup, err := stageDatabase(options.Config, true)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	target := migrationTarget.document
	runtimePublication, runtimeCleanup, err := stageDatabase(current.ConfigPath, false)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, runtimeCleanup()) }()
	runtimeTarget := runtimePublication.document
	if runtimeTarget.Proto.GetPublicUrl() != current.PublicURL || runtimeTarget.Proto.GetDevicePublicUrl() != current.DevicePublicURL {
		return result, errors.New("operations: fresh_target_origin_mismatch")
	}
	runtimeDatabase, err := runtimeTarget.Database()
	if err != nil {
		return result, err
	}
	runtimePool, err := pgxpool.NewWithConfig(ctx, runtimeDatabase)
	if err != nil {
		return result, errors.New("operations: restore_database_unavailable")
	}
	defer runtimePool.Close()
	targetIdentity, err := restoreTargetIdentity(ctx, runtimePool)
	if err != nil {
		return result, err
	}
	migration, err := target.MigrationDatabase()
	if err != nil {
		return result, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, migration)
	if err != nil {
		return result, errors.New("operations: restore_database_unavailable")
	}
	defer pool.Close()
	if err = checkFreshRestoreTarget(ctx, pool, current); err != nil {
		return result, err
	}
	var freshDatabaseCustody *agentv1.ServerRecoveryDatabaseCustody
	if inventory.base == "/etc/lindm" {
		freshDatabaseCustody, err = preserveFreshDatabaseCustody(ctx, runtimePool)
		if err != nil {
			return result, err
		}
	}
	connection, err := custody.ReadRoot(target.Proto.GetDatabase().GetMigrationUrlFile(), maxResource, false)
	defer clear(connection)
	if err != nil {
		return result, err
	}
	env, err := libpqService(stage, string(connection))
	if err != nil {
		return result, err
	}
	restoreMajor, err := databaseMajor(ctx, pool)
	if err != nil {
		return result, err
	}
	if restoreMajor != checkpoint.databaseMajor {
		return result, errors.New("operations: restore_database_archive_major_mismatch")
	}
	if err = enterRestoreHold(targetIdentity); err != nil {
		return result, err
	}
	if err = runTool(ctx, checkpoint.restoreTool, []string{"--dbname=service=lindm-backup", "--exit-on-error", "--single-transaction", "--clean", "--if-exists", "--no-owner", "--no-acl", "--no-password", filepath.Join(checkpoint.directory, "database.dump")}, env, nil, io.Discard); err != nil {
		return result, err
	}
	if err = db.Check(ctx, pool); err != nil {
		return result, err
	}
	if _, err = pool.Exec(ctx, "UPDATE server_recovery_state SET hold=true WHERE singleton"); err != nil {
		return result, err
	}
	if err = reconcileRestoredAuthority(ctx, pool, options, &checkpoint); err != nil {
		return result, err
	}
	restoredCleanup, err := publishRecovery(ctx, &checkpoint, migrationTarget, runtimePublication, pool, runtimePool, runtimeDatabase.ConnConfig.User, targetIdentity, freshDatabaseCustody, stage)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, restoredCleanup()) }()
	if err = errors.Join(cleanup(), runtimeCleanup(), restoredCleanup(), stageCleanup()); err != nil {
		return result, err
	}
	if _, err = pool.Exec(ctx, "UPDATE server_recovery_state SET hold=false WHERE singleton"); err != nil {
		return result, err
	}
	if err = os.Remove(restoreMarker); err != nil {
		return result, err
	}
	markerDirectory, _, err := custody.OpenRoot(filepath.Dir(restoreMarker), 0)
	if err != nil {
		return result, err
	}
	if err = errors.Join(markerDirectory.Sync(), markerDirectory.Close()); err != nil {
		return result, err
	}
	return DrillResult{CapturedAt: current.CapturedAt, Version: current.Version, DeploymentID: current.DeploymentID, Files: len(current.Files), DatabaseArchiveValid: true}, nil
}

type restoreCheckpoint struct {
	original, current archiveManifest
	directory         string
	rootHash          [32]byte
	signed            *agentv1.ServerRecoveryCheckpoint
	inventory         *resourceSet
	resources         *config.Resources
	restoreTool       string
	databaseMajor     int
}

func prepareRestoreCheckpoint(ctx context.Context, options RestoreOptions, stage string, snapshot *restoreCheckpoint) (err error) {
	originalDir, currentDir := filepath.Join(stage, "original"), filepath.Join(stage, "current")
	if err = os.Mkdir(originalDir, 0700); err != nil {
		return err
	}
	if err = os.Mkdir(currentDir, 0700); err != nil {
		return err
	}
	snapshot.directory = currentDir
	snapshot.original, err = decryptArchive(ctx, options.Archive, options.IdentityFile, options.IdentityPassphrase, originalDir)
	if err != nil {
		return err
	}
	snapshot.current, err = decryptArchive(ctx, options.SecurityArchive, options.IdentityFile, options.IdentityPassphrase, currentDir)
	if err != nil {
		return err
	}
	root, err := readCheckpointRoot(options.RootFile)
	if err != nil {
		return err
	}
	envelope, err := custody.ReadRoot(options.SecurityCheckpoint, 512<<10, false)
	if err != nil {
		return err
	}
	snapshot.signed = new(agentv1.ServerRecoveryCheckpoint)
	if err = verifyCheckpoint(ctx, envelope, snapshot.signed, root); err != nil {
		return err
	}
	originalHash, err := digestBytes(options.Archive)
	if err != nil {
		return err
	}
	currentHash, err := digestBytes(options.SecurityArchive)
	if err != nil {
		return err
	}
	snapshot.rootHash, err = trust.ExecutionRootDigest(root)
	if err != nil {
		return err
	}
	if root.GetDeploymentId() != snapshot.current.DeploymentID {
		return errors.New("operations: checkpoint_root_deployment_mismatch")
	}
	if err = validateRecoveryBinding(snapshot.signed, snapshot.rootHash[:], snapshot.original, snapshot.current, originalHash, currentHash, buildinfo.Version); err != nil {
		return err
	}
	if _, _, err = archivedConfiguration(snapshot.original, originalDir); err != nil {
		return err
	}
	inventory, document, err := archivedConfiguration(snapshot.current, currentDir)
	if err != nil {
		return err
	}
	snapshot.inventory = inventory
	snapshot.resources, err = document.Resolve()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			snapshot.resources.HTTPClient.CloseIdleConnections()
		}
	}()
	if snapshot.resources.ExecutionBootstrap == nil {
		return errors.New("operations: checkpoint_execution_bootstrap_required")
	}
	snapshot.restoreTool, snapshot.databaseMajor, err = checkDatabaseArchive(ctx, filepath.Join(currentDir, "database.dump"))
	return err
}

func checkFreshRestoreTarget(ctx context.Context, pool *pgxpool.Pool, current *archiveManifest) error {
	if err := db.Check(ctx, pool); err != nil {
		return err
	}
	var floor int64
	var versions []int64
	if err := pool.QueryRow(ctx, "SELECT minimum_runtime_version,migration_versions FROM lindm_schema_compatibility WHERE singleton").Scan(&floor, &versions); err != nil {
		return errors.New("operations: target_schema_metadata_unavailable")
	}
	if floor != current.SchemaMinimumRuntime || !slices.Equal(versions, current.SchemaVersions) {
		return errors.New("operations: checkpoint_schema_version_mismatch")
	}
	var occupied bool
	if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM principals) OR EXISTS(SELECT 1 FROM devices)").Scan(&occupied); err != nil {
		return errors.New("operations: fresh_migrated_database_required")
	}
	if occupied {
		return errors.New("operations: restore_target_not_fresh")
	}
	return nil
}

func reconcileRestoredAuthority(ctx context.Context, pool *pgxpool.Pool, options RestoreOptions, snapshot *restoreCheckpoint) error {
	resources := snapshot.resources
	store, err := executionauthority.New(ctx, pool, executionauthority.Config{RootJSON: resources.ExecutionBootstrap.RootJSON, BootstrapEnvelope: resources.ExecutionBootstrap.Envelope, TLSPublicKey: resources.ServerCertificate.Leaf.PublicKey})
	if err != nil {
		return err
	}
	active, err := store.Get(ctx)
	if err != nil {
		return err
	}
	digest, err := trust.ExecutionRootDigest(active.Root)
	if err != nil || digest != snapshot.rootHash || active.Delegation.GetMinimumRecoveryEpoch() != snapshot.current.MinimumRecoveryEpoch {
		return errors.New("operations: restored_execution_root_or_epoch_mismatch")
	}
	if snapshot.signed.GetRecoveryEpoch() <= active.Delegation.GetMinimumRecoveryEpoch() {
		return errors.New("operations: newer_recovery_epoch_required")
	}
	updateData, err := custody.ReadRoot(options.ExecutionUpdate, 512<<10, false)
	if err != nil {
		return err
	}
	update := new(agentv1.UpdateExecutionTrustRequest)
	if err = protojson.Unmarshal(updateData, update); err != nil {
		return errors.New("operations: invalid_execution_update")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var owner uuid.UUID
	if err = tx.QueryRow(ctx, "SELECT p.id FROM deployment_identity d JOIN principals p ON p.id=d.owner_principal_id WHERE p.pinned_role='owner' AND p.deactivated_at IS NULL FOR UPDATE OF p").Scan(&owner); err != nil {
		return errors.New("operations: active_checkpoint_owner_required")
	}
	receipt, err := store.Apply(ctx, tx, update, owner, options.Reason)
	if err != nil {
		return err
	}
	if receipt.GetMinimumRecoveryEpoch() != snapshot.signed.GetRecoveryEpoch() {
		return errors.New("operations: recovery_epoch_update_mismatch")
	}
	if err = invalidateRestoredAuthority(ctx, tx); err != nil {
		return err
	}
	hash, err := digestBytes(options.SecurityCheckpoint)
	if err != nil {
		return err
	}
	details, err := json.Marshal(map[string]any{"checkpoint_sha256": hex.EncodeToString(hash), "original_capture_at": snapshot.original.CapturedAt, "checkpoint_fence_at": snapshot.current.FencedAt, "recovery_epoch": snapshot.signed.GetRecoveryEpoch()})
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(id,occurred_at,actor_id,action,resource_id,reason,details) VALUES($1,clock_timestamp(),$2,$3,$4,$5,$6::jsonb)", uuid.New(), owner, auditkind.ServerRecoveryCheckpoint.String(), snapshot.current.DeploymentID, options.Reason, string(details)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE server_recovery_state SET hold=true,recovery_epoch=$1,checkpoint_sha256=$2,reconciled_at=clock_timestamp() WHERE singleton", strconv.FormatUint(snapshot.signed.GetRecoveryEpoch(), 10), hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func publishRecovery(ctx context.Context, snapshot *restoreCheckpoint, migrationTarget, runtimeTarget *stagedDatabase, pool, runtimePool *pgxpool.Pool, runtimeRole, targetIdentity string, freshDatabaseCustody *agentv1.ServerRecoveryDatabaseCustody, stage string) (cleanup func() error, err error) {
	current, inventory := &snapshot.current, snapshot.inventory
	if err = publishRestoredFiles(*current, inventory, migrationTarget, runtimeTarget); err != nil {
		return nil, err
	}
	if err = restrictRestoredMetadata(ctx, pool, runtimeRole); err != nil {
		return nil, err
	}
	restored, cleanup, err := StageConfig(current.ConfigPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, cleanup())
			cleanup = nil
		}
	}()
	resources, err := restored.Resolve()
	if err != nil {
		return cleanup, err
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if restored.Proto.GetDeploymentId() != current.DeploymentID {
		return cleanup, errors.New("operations: restored_deployment_mismatch")
	}
	if err = db.Check(ctx, runtimePool); err != nil {
		return cleanup, err
	}
	actual, err := restoreTargetIdentity(ctx, runtimePool)
	if err != nil {
		return cleanup, err
	}
	if actual != targetIdentity {
		return cleanup, errors.New("operations: restored_database_identity_changed")
	}
	if inventory.base == "/etc/lindm" {
		original, readErr := newResources(current.ConfigPath, stage)
		if readErr != nil {
			return cleanup, readErr
		}
		if err = rebindRecoveryCustody(original.config, freshDatabaseCustody); err != nil {
			return cleanup, err
		}
		if _, err = ReadRecoveryCustodyHealth(RecoveryCustodyHealthPath); err != nil {
			return cleanup, err
		}
	}
	return cleanup, nil
}

func invalidateRestoredAuthority(ctx context.Context, tx pgx.Tx) error {
	statements := []string{
		"UPDATE sessions SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL",
		"DELETE FROM auth_flows", "DELETE FROM cli_auth_codes", "DELETE FROM cli_auth_requests", "DELETE FROM local_ceremonies", "DELETE FROM local_enrollments",
		"UPDATE first_run_setup SET expires_at=clock_timestamp() WHERE consumed_at IS NULL", "DELETE FROM first_run_attempts",
		"UPDATE principals SET authorization_version=authorization_version+1,directory_observed_at=NULL,directory_enabled=false",
		"UPDATE approval_requests SET state='withdrawn',approver_id=NULL,approver_version=0,decision_reason='restore_reapproval_required' WHERE state IN ('pending','approved')",
		"UPDATE device_actions SET closed_at=clock_timestamp(),closed_reason='restore_reapproval_required',outcome_unknown=(start_authorized_at IS NOT NULL) WHERE closed_at IS NULL",
		"UPDATE resource_actions SET closed_at=clock_timestamp(),closed_reason='restore_reapproval_required' WHERE closed_at IS NULL",
		"UPDATE resource_assignments SET blocked_reason='restore_reapproval_required'",
		"UPDATE resource_releases SET state='release_conflict',reason='restore_reapproval_required' WHERE state='pending'",
		"UPDATE resource_rollouts SET paused=true,pause_reason='restore_reapproval_required'",
		"DELETE FROM target_execution_heads",
		"UPDATE assistance_sessions SET state=6,ended_at=clock_timestamp(),end_cause=1,end_detail='Server restored; fresh assistance consent required',device_ended=true WHERE state<>6",
		"UPDATE assistance_commands SET status=4,reason='restore_reapproval_required',completed_at=clock_timestamp() WHERE status=1",
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return errors.New("operations: restored_authority_invalidation_failed")
		}
	}
	return nil
}
