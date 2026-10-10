package devlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	databaseProfileTimeout      = 5 * time.Second
	profileActivityLimit        = 128
	profileLockLimit            = 256
	profileStatementLimit       = 32
	authorityProfileApplication = "lindm-authority-profile"
	// Activity exports only the generated sqlc name, never raw SQL. Statement
	// statistics separately export bounded, conservatively redacted DML.
	profileQueryNamePattern = `^-- name: ([A-Za-z][A-Za-z0-9_]{0,95}) :(?:one|many|exec|execrows|execresult|copyfrom|batchone|batchmany|batchexec)[\r\n]`
)

// DatabaseProfile is nonsecret evidence about one owned disposable database.
// Statements are cumulative, not interval deltas. Samples are not an atomic
// snapshot across views. A nil error does not imply Statements.Available: callers
// requiring query timings must gate their workload on that explicit prerequisite.
// Do not sample more frequently than every ten seconds: lock inspection itself
// briefly takes PostgreSQL's lock-manager locks.
type DatabaseProfile struct {
	ObservedAt           time.Time
	CompletedAt          time.Time
	DatabaseOID          uint32
	Configuration        DatabaseProfileConfiguration
	Connections          AuthorityConnectionCounts
	Activity             []DatabaseActivity
	ActivityTruncated    bool
	Locks                []DatabaseLock
	LocksTruncated       bool
	Statements           StatementProfileStatus
	TopQueries           []DatabaseStatement
	TopQueriesTruncated  bool
	OmittedTopQueryTexts int
}

// DatabaseProfileConfiguration deliberately excludes paths, URLs and arbitrary
// settings. Sizes in Settings retain PostgreSQL's explicit units. DatabaseBytes
// is logical allocated size, not filesystem capacity, disk latency or media type.
type DatabaseProfileConfiguration struct {
	Settings                  []DatabaseSetting
	DatabaseBytes             int64
	DefaultTablespaceOID      uint32
	PhysicalStorageObserved   bool
	TrackActivities           bool
	ComputeQueryID            string
	StatementLibraryPreloaded bool
	StatementTracking         string
}

type DatabaseSetting struct {
	Name  string
	Value string
	Unit  string
}

// StatementProfileStatus distinguishes absent prerequisites from a genuinely
// empty top-query result. RequiredBootstrap is instructions, never executed by
// ProfileDatabase. Installing the extension is separately operator gated.
type StatementProfileStatus struct {
	Available            bool
	ExtensionAvailable   bool
	ExtensionInstalled   bool
	AllStatisticsVisible bool
	Reasons              []string
	RequiredBootstrap    []string
}

type DatabaseActivity struct {
	PID                   int32
	BackendType           string
	State                 string
	WaitEventType         string
	WaitEvent             string
	QueryID               string
	QueryName             string
	QueryAgeSeconds       *float64
	TransactionAgeSeconds *float64
	BlockingPIDs          []int32
	BlockersTruncated     bool
}

// DatabaseLock aggregates lock counts, not relation identifiers or tuple values.
// Only locks whose backend belongs to the owned database are returned; a lock
// with a nonzero database OID must additionally match that database.
type DatabaseLock struct {
	PID         int32
	BackendType string
	Type        string
	Mode        string
	Granted     bool
	Count       int64
}

// DatabaseStatement retains PostgreSQL's (userid, dbid, queryid, toplevel) key.
// NormalizedSQL is a bounded, redacted diagnostic rendering, not executable SQL.
// PostgreSQL can discard leading sqlc comments from stored statement text, so
// statement identity uses QueryID, not an inferred sqlc name. Utility, oversized
// and unrecognized text remains explicitly unavailable while counters survive.
type DatabaseStatement struct {
	UserOID                    uint32
	QueryID                    string
	TopLevel                   bool
	NormalizedSQL              string
	StatementTextAvailable     bool
	StatementTextOmittedReason string
	Calls                      int64
	Rows                       int64
	TotalExecutionMilliseconds float64
	MeanExecutionMilliseconds  float64
	SharedBlocksHit            int64
	SharedBlocksRead           int64
	SharedBlocksDirtied        int64
	SharedBlocksWritten        int64
	StatisticsSince            time.Time
}

// AuthorityConnectionCounts counts client occupancy separately from background
// work. Active includes waiting clients, and Waiting counts only active clients.
type AuthorityConnectionCounts struct {
	Connections                  int
	ActiveConnections            int
	IdleConnections              int
	IdleInTransactionConnections int
	WaitingConnections           int
	AutovacuumWorkers            int
	OtherBackgroundBackends      int
}

func (c *AuthorityConnectionCounts) add(backend, state string, waiting bool, count int) {
	if backend == "autovacuum worker" {
		c.AutovacuumWorkers += count
		return
	}
	if backend != "client backend" {
		c.OtherBackgroundBackends += count
		return
	}
	c.Connections += count
	switch state {
	case "active":
		c.ActiveConnections += count
		if waiting {
			c.WaitingConnections += count
		}
	case "idle":
		c.IdleConnections += count
	case "idle in transaction", "idle in transaction (aborted)":
		c.IdleInTransactionConnections += count
	}
}

func readAuthorityConnectionCounts(ctx context.Context, conn *pgx.Conn) (AuthorityConnectionCounts, error) {
	var counts AuthorityConnectionCounts
	rows, err := conn.Query(ctx, `SELECT
CASE backend_type WHEN 'client backend' THEN 'client backend' WHEN 'autovacuum worker' THEN 'autovacuum worker' ELSE 'background' END,
CASE WHEN state IN ('active', 'idle', 'idle in transaction', 'idle in transaction (aborted)') THEN state ELSE '' END,
wait_event IS NOT NULL, count(*)
FROM pg_catalog.pg_stat_activity
WHERE datid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()) AND pid <> pg_backend_pid()
AND application_name <> $1
GROUP BY 1, 2, 3`, authorityProfileApplication)
	if err != nil {
		return counts, err
	}
	defer rows.Close()
	for rows.Next() {
		var backend, state string
		var waiting bool
		var count int
		if err := rows.Scan(&backend, &state, &waiting, &count); err != nil {
			return counts, err
		}
		counts.add(backend, state, waiting, count)
	}
	return counts, rows.Err()
}

func (f *AuthorityFixture) profileConnection(ctx context.Context, readOnly bool) (*pgx.Conn, error) {
	if f == nil || f.closed || f.database == nil || !f.database.created || f.database.admin == nil || f.database.name == "" || f.DatabaseName != f.database.name {
		return nil, errors.New("database profiling requires a live owned authority database")
	}
	cfg := f.database.admin.Copy()
	cfg.Database = f.database.name
	cfg.ConnectTimeout = databaseProfileTimeout
	cfg.RuntimeParams["statement_timeout"] = "4000"
	if readOnly {
		cfg.RuntimeParams["application_name"] = authorityProfileApplication
		cfg.RuntimeParams["default_transaction_read_only"] = "on"
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, profileError("connect owned database", err)
	}
	return conn, nil
}

func closeProfileConnection(conn *pgx.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return profileError("close profiling connection", conn.Close(ctx))
}

// profileError intentionally omits PostgreSQL error detail, SQL and connection
// configuration. A SQLSTATE and cancellation cause suffice for this evidence API.
func profileError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("database profile %s: %w", operation, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("database profile %s: %w", operation, context.DeadlineExceeded)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Errorf("database profile %s failed (SQLSTATE %s)", operation, pgErr.Code)
	}
	return fmt.Errorf("database profile %s failed", operation)
}

// EnableStatementProfiling installs only the extension in this fixture's owned
// database, after checking cluster prerequisites. This explicit setup method is
// not part of sampling; it never loads libraries, resets statistics, changes
// shared settings, creates a shared-database extension or restarts PostgreSQL.
func (f *AuthorityFixture) EnableStatementProfiling(ctx context.Context) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, databaseProfileTimeout)
	defer cancel()
	conn, err := f.profileConnection(ctx, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeProfileConnection(conn)) }()
	var profile DatabaseProfile
	if _, err := readProfileConfiguration(ctx, conn, &profile); err != nil {
		return profileError("probe statement prerequisites", err)
	}
	c := profile.Configuration
	if !c.StatementLibraryPreloaded || (c.ComputeQueryID != "auto" && c.ComputeQueryID != "on") || (c.StatementTracking != "top" && c.StatementTracking != "all") || !profile.Statements.ExtensionAvailable {
		return errors.New("database profile requires installed pg_stat_statements library, shared_preload_libraries=pg_stat_statements, compute_query_id=on, pg_stat_statements.track=top and a coordinated PostgreSQL restart before owned-database extension setup")
	}
	_, err = conn.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pg_stat_statements`)
	return profileError("install owned database statement extension", err)
}

// ProfileDatabase returns bounded read-only diagnostics. It opens one independent
// administration connection with a five-second deadline and excludes that
// connection from activity/occupancy/locks. Never call concurrently with Close.
func (f *AuthorityFixture) ProfileDatabase(ctx context.Context) (profile DatabaseProfile, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, databaseProfileTimeout)
	defer cancel()
	profile.ObservedAt = time.Now().UTC()
	defer func() { profile.CompletedAt = time.Now().UTC() }()
	conn, err := f.profileConnection(ctx, true)
	if err != nil {
		return profile, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeProfileConnection(conn)) }()
	schema, err := readProfileConfiguration(ctx, conn, &profile)
	if err != nil {
		return profile, profileError("read configuration", err)
	}
	profile.Connections, err = readAuthorityConnectionCounts(ctx, conn)
	if err != nil {
		return profile, profileError("read client occupancy", err)
	}
	if err := readProfileActivity(ctx, conn, &profile); err != nil {
		return profile, profileError("read owned activity", err)
	}
	if err := readProfileLocks(ctx, conn, &profile); err != nil {
		return profile, profileError("read owned locks", err)
	}
	profile.Statements.Reasons, profile.Statements.RequiredBootstrap = statementPrerequisites(profile.Configuration, profile.Statements)
	if len(profile.Statements.Reasons) != 0 {
		return profile, nil
	}
	if err := readProfileStatements(ctx, conn, schema, &profile); err != nil {
		profile.Statements.Reasons = []string{"statement_query_failed"}
		return profile, profileError("read owned statement statistics", err)
	}
	profile.Statements.Available = true
	return profile, nil
}

func readProfileConfiguration(ctx context.Context, conn *pgx.Conn, p *DatabaseProfile) (string, error) {
	var schema string
	err := conn.QueryRow(ctx, `SELECT d.oid, d.dattablespace, pg_database_size(d.oid),
current_setting('track_activities') = 'on', current_setting('compute_query_id'),
EXISTS (SELECT 1 FROM unnest(string_to_array(current_setting('shared_preload_libraries'), ',')) AS library WHERE trim(both ' "' from library) IN ('pg_stat_statements', '$libdir/pg_stat_statements')),
coalesce(current_setting('pg_stat_statements.track', true), ''),
EXISTS (SELECT 1 FROM pg_catalog.pg_available_extensions WHERE name = 'pg_stat_statements'),
EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'pg_stat_statements'),
(SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) OR pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER'),
coalesce((SELECT n.nspname FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'pg_stat_statements'), '')
FROM pg_catalog.pg_database d WHERE d.datname = current_database()`).Scan(
		&p.DatabaseOID, &p.Configuration.DefaultTablespaceOID, &p.Configuration.DatabaseBytes,
		&p.Configuration.TrackActivities, &p.Configuration.ComputeQueryID,
		&p.Configuration.StatementLibraryPreloaded, &p.Configuration.StatementTracking,
		&p.Statements.ExtensionAvailable, &p.Statements.ExtensionInstalled, &p.Statements.AllStatisticsVisible, &schema)
	if err != nil {
		return "", err
	}
	rows, err := conn.Query(ctx, `SELECT name, left(setting, 128), coalesce(unit, '') FROM pg_catalog.pg_settings
WHERE name IN ('server_version', 'max_connections', 'shared_buffers', 'work_mem', 'maintenance_work_mem',
'effective_cache_size', 'block_size', 'segment_size', 'wal_segment_size', 'default_table_access_method',
'fsync', 'synchronous_commit', 'full_page_writes', 'track_io_timing', 'track_activity_query_size',
'pg_stat_statements.max', 'pg_stat_statements.track_planning', 'pg_stat_statements.track_utility', 'pg_stat_statements.save') ORDER BY name`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var setting DatabaseSetting
		if err := rows.Scan(&setting.Name, &setting.Value, &setting.Unit); err != nil {
			return "", err
		}
		p.Configuration.Settings = append(p.Configuration.Settings, setting)
	}
	return schema, rows.Err()
}

func statementPrerequisites(c DatabaseProfileConfiguration, s StatementProfileStatus) (reasons, instructions []string) {
	if !s.ExtensionAvailable {
		reasons = append(reasons, "extension_package_unavailable")
		instructions = append(instructions, "Install the PostgreSQL-major-matching pg_stat_statements extension package in the development PostgreSQL image.")
	}
	if !c.StatementLibraryPreloaded {
		reasons = append(reasons, "library_not_preloaded")
		instructions = append(instructions, "Add pg_stat_statements to shared_preload_libraries, preserving existing entries, then coordinate a development PostgreSQL restart; do not restart shared dependencies from the load harness.")
	}
	if c.ComputeQueryID != "auto" && c.ComputeQueryID != "on" {
		reasons = append(reasons, "query_id_computation_disabled")
		instructions = append(instructions, "Configure compute_query_id=on (auto is also supported with pg_stat_statements loaded).")
	}
	if c.StatementTracking != "top" && c.StatementTracking != "all" {
		reasons = append(reasons, "statement_tracking_disabled")
		instructions = append(instructions, "Configure pg_stat_statements.track=top in the development PostgreSQL startup settings.")
	}
	if !s.ExtensionInstalled {
		reasons = append(reasons, "extension_not_installed_in_owned_database")
		instructions = append(instructions, "Call AuthorityFixture.EnableStatementProfiling(ctx) explicitly to CREATE EXTENSION IF NOT EXISTS pg_stat_statements in only the owned disposable database.")
	}
	if !s.AllStatisticsVisible {
		reasons = append(reasons, "statistics_visibility_denied")
		instructions = append(instructions, "Use the owned fixture administration connection with pg_read_all_stats or superuser visibility; never widen the lindmd runtime role.")
	}
	if !c.TrackActivities {
		reasons = append(reasons, "activity_tracking_disabled")
		instructions = append(instructions, "Configure track_activities=on in the development PostgreSQL startup settings.")
	}
	return reasons, instructions
}

func readProfileActivity(ctx context.Context, conn *pgx.Conn, p *DatabaseProfile) error {
	rows, err := conn.Query(ctx, `SELECT a.pid, left(a.backend_type, 64), coalesce(a.state, ''),
coalesce(left(a.wait_event_type, 64), ''), coalesce(left(a.wait_event, 64), ''), coalesce(a.query_id::text, ''),
coalesce(substring(a.query from $2), ''),
extract(epoch FROM clock_timestamp() - a.query_start)::float8,
extract(epoch FROM clock_timestamp() - a.xact_start)::float8,
ARRAY(SELECT DISTINCT b.pid FROM pg_catalog.pg_stat_activity b WHERE b.datid = $1 AND b.pid = ANY(pg_blocking_pids(a.pid)) ORDER BY b.pid LIMIT 17)
FROM pg_catalog.pg_stat_activity a WHERE a.datid = $1 AND a.pid <> pg_backend_pid() AND a.application_name <> $4
ORDER BY (a.wait_event_type = 'Lock') DESC NULLS LAST, (a.state = 'active') DESC NULLS LAST, a.query_start NULLS LAST, a.pid LIMIT $3`, p.DatabaseOID, profileQueryNamePattern, profileActivityLimit+1, authorityProfileApplication)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a DatabaseActivity
		if err := rows.Scan(&a.PID, &a.BackendType, &a.State, &a.WaitEventType, &a.WaitEvent, &a.QueryID, &a.QueryName, &a.QueryAgeSeconds, &a.TransactionAgeSeconds, &a.BlockingPIDs); err != nil {
			return err
		}
		if len(p.Activity) == profileActivityLimit {
			p.ActivityTruncated = true
			continue
		}
		if len(a.BlockingPIDs) > 16 {
			a.BlockingPIDs = a.BlockingPIDs[:16]
			a.BlockersTruncated = true
		}
		p.Activity = append(p.Activity, a)
	}
	return rows.Err()
}

func readProfileLocks(ctx context.Context, conn *pgx.Conn, p *DatabaseProfile) error {
	rows, err := conn.Query(ctx, `SELECT l.pid, left(a.backend_type, 64), left(l.locktype, 64), left(l.mode, 64), l.granted, count(*)
FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid
WHERE a.datid = $1 AND l.pid <> pg_backend_pid() AND a.application_name <> $3 AND (l.database IS NULL OR l.database = 0 OR l.database = $1)
GROUP BY l.pid, a.backend_type, l.locktype, l.mode, l.granted
ORDER BY l.granted, l.pid, l.locktype, l.mode LIMIT $2`, p.DatabaseOID, profileLockLimit+1, authorityProfileApplication)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var lock DatabaseLock
		if err := rows.Scan(&lock.PID, &lock.BackendType, &lock.Type, &lock.Mode, &lock.Granted, &lock.Count); err != nil {
			return err
		}
		if len(p.Locks) == profileLockLimit {
			p.LocksTruncated = true
			continue
		}
		p.Locks = append(p.Locks, lock)
	}
	return rows.Err()
}

func readProfileStatements(ctx context.Context, conn *pgx.Conn, schema string, p *DatabaseProfile) error {
	rows, err := conn.Query(ctx, `SELECT userid, queryid::text, toplevel,
CASE WHEN octet_length(query) <= $2 THEN query ELSE NULL END,
calls, rows, total_exec_time, mean_exec_time, shared_blks_hit, shared_blks_read, shared_blks_dirtied, shared_blks_written, stats_since
FROM `+pgx.Identifier{schema, "pg_stat_statements"}.Sanitize()+`
WHERE dbid = $1 ORDER BY total_exec_time DESC, queryid, userid, toplevel LIMIT $3`, p.DatabaseOID, profileStatementTextLimit, profileStatementLimit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var statement DatabaseStatement
		var text *string
		if err := rows.Scan(&statement.UserOID, &statement.QueryID, &statement.TopLevel, &text, &statement.Calls, &statement.Rows, &statement.TotalExecutionMilliseconds, &statement.MeanExecutionMilliseconds, &statement.SharedBlocksHit, &statement.SharedBlocksRead, &statement.SharedBlocksDirtied, &statement.SharedBlocksWritten, &statement.StatisticsSince); err != nil {
			return err
		}
		if len(p.TopQueries) == profileStatementLimit {
			p.TopQueriesTruncated = true
			continue
		}
		if text == nil {
			statement.StatementTextOmittedReason = "text_unavailable_or_exceeds_limit"
		} else {
			statement.NormalizedSQL, statement.StatementTextAvailable = profileStatementText(*text)
			if !statement.StatementTextAvailable {
				statement.StatementTextOmittedReason = "utility_or_unrecognized_sql"
			}
		}
		if !statement.StatementTextAvailable {
			p.OmittedTopQueryTexts++
		}
		p.TopQueries = append(p.TopQueries, statement)
	}
	return rows.Err()
}
