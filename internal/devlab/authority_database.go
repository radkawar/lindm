package devlab

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/config"
)

// The real server deliberately rejects arbitrary PostgreSQL runtime parameters.
// Use a separate database rather than weakening that boundary for search_path.
// Cluster administration stays in the lab; lindmd receives only the existing
// non-superuser migration role restricted to the owned database URL.
type authorityDatabase struct {
	name    string
	admin   *pgx.ConnConfig
	created bool
}

func authorityDatabaseAdmin(document *config.Document, shared string) (*pgx.ConnConfig, error) {
	return authorityDatabaseAdminFor(document, shared, "lindm")
}

func authorityDatabaseAdminFor(document *config.Document, shared, databaseName string) (*pgx.ConnConfig, error) {
	cfg, err := document.MigrationDatabase()
	if err != nil {
		return nil, err
	}
	if cfg.ConnConfig.User != "lindm_migrator" || cfg.ConnConfig.Database != databaseName {
		return nil, errors.New("isolated authority database requires the maintained development fixture")
	}
	password, err := readOwned(filepath.Join(shared, "postgres-password"))
	if err != nil {
		return nil, err
	}
	defer clear(password)
	admin := cfg.ConnConfig.Copy()
	admin.User, admin.Password, admin.Database = "postgres", strings.TrimSpace(string(password)), "postgres"
	return admin, nil
}

func newAuthorityDatabase(ctx context.Context, document *config.Document, shared string) (_ *authorityDatabase, resultErr error) {
	admin, err := authorityDatabaseAdmin(document, shared)
	if err != nil {
		return nil, err
	}
	database := &authorityDatabase{name: "lindm_authority_" + strings.ReplaceAll(uuid.NewString(), "-", ""), admin: admin}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, database.Close())
		}
	}()
	connection, err := pgx.ConnectConfig(ctx, admin.Copy())
	if err != nil {
		return nil, errors.New("connect development database administration failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, connection.Close(cleanup))
	}()
	name := pgx.Identifier{database.name}.Sanitize()
	if _, err := connection.Exec(ctx, "CREATE DATABASE "+name+" OWNER lindm_migrator TEMPLATE template0"); err != nil {
		return nil, fmt.Errorf("create owned authority database %s: %w", database.name, err)
	}
	database.created = true
	if _, err := connection.Exec(ctx, "REVOKE ALL ON DATABASE "+name+" FROM PUBLIC"); err != nil {
		return nil, err
	}
	return database, nil
}

// An owned database drop has two separately bounded waits.
//
// Blockers fail visibly: a session holding a lock that DROP DATABASE needs
// fails it after dropLockBudget through PostgreSQL's lock_timeout, and a
// remaining target-database client fails it after PostgreSQL's own five-second
// check. Neither is terminated.
//
// Once admitted, PostgreSQL marks the database invalid, then forces an immediate
// cluster-wide checkpoint and waits for the checkpoint already in progress plus
// a complete new one, then for every backend to release the files. That work
// scales with every tenant's dirty files, not with the dropped database, and
// cancelling it cannot keep the database: it leaves an invalid one that needs
// another full checkpoint wait. On the shared development cluster during a full
// integration run, consecutive forced checkpoints took 533 and 574 seconds
// (fsyncing 77,251 and 83,614 files), so an admitted drop can need about
// 18.5 minutes. dropBudget bounds the whole drop above that.
const (
	dropLockBudget = 3 * time.Minute
	dropBudget     = 20 * time.Minute
)

func (d *authorityDatabase) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), dropBudget)
	defer cancel()
	return d.drop(ctx, false, dropLockBudget)
}

// drop is bounded overall by ctx and, for lock waits only, by lockBudget.
func (d *authorityDatabase) drop(ctx context.Context, missingOK bool, lockBudget time.Duration) (resultErr error) {
	if !d.created {
		return nil
	}
	if lockBudget < time.Millisecond {
		return errors.New("owned database drop requires a positive lock budget")
	}
	connection, err := pgx.ConnectConfig(ctx, d.admin.Copy())
	if err != nil {
		return fmt.Errorf("cleanup owned authority database %s: administration connection failed", d.name)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		resultErr = errors.Join(resultErr, connection.Close(cleanup))
	}()
	if _, err := connection.Exec(ctx, "SET lock_timeout = "+strconv.FormatInt(lockBudget.Milliseconds(), 10)); err != nil {
		return fmt.Errorf("bound owned authority database %s drop lock waits: %w", d.name, err)
	}
	// No FORCE: a surviving client makes cleanup fail visibly, never terminates
	// another process. The fixture stops and joins its server before this call.
	statement := "DROP DATABASE "
	if missingOK {
		statement += "IF EXISTS "
	}
	if _, err := connection.Exec(ctx, statement+pgx.Identifier{d.name}.Sanitize()); err != nil {
		activity, activityErr := d.dropActivity(ctx, connection.PgConn().PID())
		return errors.Join(fmt.Errorf("remove owned authority database %s: %w; cleanup activity: %s", d.name, err, activity), activityErr)
	}
	d.created = false
	return nil
}

// Observe only after failure, on an independent connection: cancellation may
// have closed the DROP connection already. Database-object locks can be held
// from another database, while checkpoint work may leave the DROP backend alive
// without any target-database clients. This is a snapshot, not a causal claim.
func (d *authorityDatabase) dropActivity(ctx context.Context, dropPID uint32) (activity string, resultErr error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, d.admin.Copy())
	if err != nil {
		return "unavailable", errors.New("observe owned database cleanup: administration connection failed")
	}
	defer func() { resultErr = errors.Join(resultErr, connection.Close(ctx)) }()
	rows, err := connection.Query(ctx, `
SELECT pid,
       CASE WHEN pid = $2 THEN 'drop' WHEN datname = $1 THEN 'client' ELSE 'database-lock' END,
       COALESCE(usename, ''), COALESCE(application_name, ''),
       COALESCE(state, ''), COALESCE(wait_event_type, ''), COALESCE(wait_event, '')
FROM pg_stat_activity
WHERE datname = $1 OR pid = $2 OR pid IN (
    SELECT pid FROM pg_locks
    WHERE locktype = 'object' AND classid = 'pg_database'::regclass
      AND objid = (SELECT oid FROM pg_database WHERE datname = $1) AND granted
)
ORDER BY pid
LIMIT 33`, d.name, dropPID)
	if err != nil {
		return "unavailable", fmt.Errorf("observe owned database cleanup: %w", err)
	}
	defer rows.Close()
	var output strings.Builder
	fmt.Fprintf(&output, "drop_pid=%d; observed after failure", dropPID)
	count := 0
	for rows.Next() {
		if count == 32 {
			output.WriteString("; additional sessions omitted")
			break
		}
		var pid uint32
		var role, user, application, state, waitType, waitEvent string
		if err := rows.Scan(&pid, &role, &user, &application, &state, &waitType, &waitEvent); err != nil {
			return "unavailable", fmt.Errorf("read owned database cleanup activity: %w", err)
		}
		fmt.Fprintf(&output, "; %s pid=%d user=%q application=%q state=%q wait=%q/%q",
			role, pid, user, application, state, waitType, waitEvent)
		count++
	}
	if err := rows.Err(); err != nil {
		return "unavailable", fmt.Errorf("read owned database cleanup activity: %w", err)
	}
	if count == 0 {
		output.WriteString("; no remaining target clients, DROP backend or database-object lock holders")
	}
	return output.String(), nil
}
