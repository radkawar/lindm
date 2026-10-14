// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fenceCheckpointDatabase is called only after the root source marker is fsynced
// and the operator has fenced and stopped every ingress and replica. Runtime
// credentials remain SELECT-only on recovery metadata; only the separately
// provisioned migrator can commit this retirement fence before pg_dump.
func fenceCheckpointDatabase(ctx context.Context, configPath, target string) (err error) {
	document, cleanup, err := StageDatabaseConfig(filepath.Join(filepath.Dir(configPath), "migrate", "server.json"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	cfg, err := document.MigrationDatabase()
	if err != nil {
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return errors.New("operations: checkpoint_migrator_unavailable")
	}
	defer pool.Close()
	actual, err := restoreTargetIdentity(ctx, pool)
	if err != nil {
		return err
	}
	if actual != target {
		return errors.New("operations: checkpoint_migrator_target_mismatch")
	}
	return commitCheckpointHold(ctx, pool)
}

func commitCheckpointHold(ctx context.Context, pool *pgxpool.Pool) (err error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, "UPDATE server_recovery_state SET hold=true WHERE singleton")
	if err != nil {
		return errors.New("operations: checkpoint_database_fence_failed")
	}
	if command.RowsAffected() != 1 {
		return errors.New("operations: checkpoint_database_fence_missing")
	}
	return tx.Commit(ctx)
}
