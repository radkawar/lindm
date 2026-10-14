// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"

	"lindm/internal/config"
)

// ErrNoFixture reports a checkout without a development fixture.
var ErrNoFixture = errors.New("devlab: no development fixture")

// invalidDropTimeout bounds each drop: dropping a database waits for a
// cluster-wide checkpoint, which takes minutes on a busy shared cluster, and
// a cancelled drop is exactly what leaves an invalid database behind.
const invalidDropTimeout = 30 * time.Minute

// DropInvalidDatabases drops the invalid lindm_* databases of the checkout's
// development PostgreSQL cluster and returns their names (with dryRun, only
// lists them). PostgreSQL marks a database invalid (pg_database.datconnlimit
// = -2) when a DROP DATABASE is interrupted after it began removing files,
// as cancelled authority fixture drops do; such a database accepts no
// connections and can only be dropped. Valid databases, which may belong to
// held demos, are never touched. It returns ErrNoFixture for a checkout
// without a fixture.
func DropInvalidDatabases(ctx context.Context, repoRoot string, dryRun bool) ([]string, error) {
	dir := FixturePath(repoRoot)
	if _, err := os.Stat(filepath.Join(dir, "server.json")); errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoFixture
	}
	document, err := config.Load(filepath.Join(dir, "server.json"))
	if err != nil {
		return nil, err
	}
	admin, err := authorityDatabaseAdmin(document, dir)
	if err != nil {
		return nil, err
	}
	connect, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(connect, admin)
	if err != nil {
		return nil, fmt.Errorf("connect development PostgreSQL administration: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	return dropInvalid(ctx, conn, dryRun)
}

// dropInvalid drops (or lists) every invalid lindm_* database, continuing
// past a failed drop.
func dropInvalid(ctx context.Context, conn *pgx.Conn, dryRun bool) ([]string, error) {
	rows, err := conn.Query(ctx, `SELECT datname FROM pg_database WHERE datconnlimit = -2 AND datname LIKE 'lindm\_%' ORDER BY datname`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || dryRun {
		return names, err
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("SET statement_timeout = %d", invalidDropTimeout.Milliseconds())); err != nil {
		return nil, err
	}
	var dropped []string
	var failures []error
	for _, name := range names {
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()); err != nil {
			failures = append(failures, fmt.Errorf("drop invalid database %s: %w", name, err))
			continue
		}
		dropped = append(dropped, name)
	}
	return dropped, errors.Join(failures...)
}
