// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
)

// SchemaStatus is the non-secret installer decision for this binary and database.
// Online is granted only by explicitly reviewed expand migrations. A legacy
// database must cross the initial policy migration while traffic is fenced.
type SchemaStatus struct {
	Compatible bool    `json:"compatible"`
	Online     bool    `json:"online"`
	Current    int64   `json:"current"`
	Target     int64   `json:"target"`
	Floor      int64   `json:"floor"`
	Pending    []int64 `json:"pending"`
}

type compatibilityPolicy struct {
	floor    int64
	versions []int64
}

// Preflight checks the exact applied history and migration-owner compatibility
// record in one read-only snapshot. Pending migrations are reported, not applied.
func Preflight(ctx context.Context, pool *pgxpool.Pool) (status SchemaStatus, err error) {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer func() { err = errors.Join(err, sqlDB.Close()) }()
	sources, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return status, err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sources)
	if err != nil {
		return status, fmt.Errorf("read embedded migrations: %w", err)
	}
	tx, err := sqlDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return status, fmt.Errorf("begin schema snapshot: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(); !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, rollbackErr)
		}
	}()
	var historyExists bool
	if err := tx.QueryRowContext(ctx, "SELECT to_regclass('goose_db_version') IS NOT NULL").Scan(&historyExists); err != nil {
		return status, fmt.Errorf("inspect migration history: %w", err)
	}
	applied := make(map[int64]bool)
	if historyExists {
		store, err := database.NewStore(database.DialectPostgres, "goose_db_version")
		if err != nil {
			return status, err
		}
		rows, err := store.ListMigrations(ctx, tx)
		if err != nil {
			return status, fmt.Errorf("read schema versions: %w", err)
		}
		for _, row := range rows {
			if _, seen := applied[row.Version]; !seen {
				applied[row.Version] = row.IsApplied
			}
		}
		delete(applied, 0)
	}
	var policyExists bool
	if err := tx.QueryRowContext(ctx, "SELECT to_regclass('lindm_schema_compatibility') IS NOT NULL").Scan(&policyExists); err != nil {
		return status, fmt.Errorf("inspect schema compatibility: %w", err)
	}
	var policy *compatibilityPolicy
	if policyExists {
		policy = &compatibilityPolicy{}
		if err := tx.QueryRowContext(ctx, "SELECT minimum_runtime_version, migration_versions FROM lindm_schema_compatibility WHERE singleton").Scan(&policy.floor, pgtype.NewMap().SQLScanner(&policy.versions)); err != nil {
			return status, fmt.Errorf("read schema compatibility: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return status, fmt.Errorf("close schema snapshot: %w", err)
	}
	var expected []int64
	for _, source := range provider.ListSources() {
		expected = append(expected, source.Version)
	}
	declarations, err := onlineDeclarations(sources, applied)
	if err != nil {
		return status, err
	}
	return evaluateSchema(expected, applied, policy, declarations)
}

func evaluateSchema(expected []int64, history map[int64]bool, policy *compatibilityPolicy, declarations map[int64]int64) (SchemaStatus, error) {
	status := SchemaStatus{Pending: []int64{}}
	if len(expected) == 0 {
		return status, errors.New("no embedded migrations")
	}
	var applied []int64
	for version, present := range history {
		if present {
			applied = append(applied, version)
		}
	}
	slices.Sort(applied)
	if len(applied) > 0 {
		status.Current = applied[len(applied)-1]
	}
	expectedVersions := make(map[int64]struct{}, len(expected))
	for _, version := range expected {
		expectedVersions[version] = struct{}{}
		status.Target = max(status.Target, version)
		if !history[version] {
			status.Pending = append(status.Pending, version)
		}
	}
	for _, version := range applied {
		if _, known := expectedVersions[version]; !known && version <= status.Target {
			return status, fmt.Errorf("unexpected historical schema migration %d", version)
		}
	}
	status.Floor = status.Current
	// Migration 49 introduces the owner-written compatibility contract. Missing
	// metadata after that cutover is corruption, not a legacy admission path.
	if policy == nil && history[49] {
		return status, errors.New("schema compatibility record is missing after migration 49")
	}
	if policy != nil {
		if policy.floor <= 0 || !history[policy.floor] || !slices.IsSorted(policy.versions) || !slices.Equal(applied, policy.versions) {
			return status, errors.New("schema compatibility record does not match exact applied migration history")
		}
		status.Floor = policy.floor
	}
	status.Compatible = len(status.Pending) == 0 && (status.Current <= status.Target || (policy != nil && status.Target >= policy.floor))
	status.Online = status.Compatible
	if len(status.Pending) > 0 {
		status.Online = policy != nil && status.Current <= status.Target
		for _, version := range status.Pending {
			floor, reviewed := declarations[version]
			if !reviewed || floor <= 0 || floor > status.Current || floor > status.Target || version <= status.Current {
				status.Online = false
			}
			if reviewed {
				status.Floor = max(status.Floor, floor)
			} else {
				status.Floor = max(status.Floor, version)
			}
		}
	}
	return status, nil
}

// Only an explicit release-reviewed marker permits online application. Contract
// migrations omit the marker and increase the metadata floor in their transaction.
func onlineDeclarations(sources fs.FS, applied map[int64]bool) (map[int64]int64, error) {
	entries, err := fs.ReadDir(sources, ".")
	if err != nil {
		return nil, err
	}
	result := make(map[int64]int64)
	const prefix = "-- lindm:online-compatible minimum-runtime="
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		versionText, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("invalid migration name %s", entry.Name())
		}
		version, err := strconv.ParseInt(versionText, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse migration version: %w", err)
		}
		if applied[version] {
			continue
		}
		content, err := fs.ReadFile(sources, entry.Name())
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(content), "\n") {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			floor, err := strconv.ParseInt(strings.TrimPrefix(line, prefix), 10, 64)
			if err != nil || floor <= 0 || floor >= version {
				return nil, fmt.Errorf("invalid online compatibility declaration for migration %d", version)
			}
			if _, duplicate := result[version]; duplicate {
				return nil, fmt.Errorf("duplicate online compatibility declaration for migration %d", version)
			}
			result[version] = floor
		}
	}
	return result, nil
}
