//go:build integration && consolelab

package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"lindm/internal/config"
)

// Opt in separately for tmpfs and nvme. This uses the same public constructor as
// loadlab, including real migrations/server startup, and never resets shared dev.
func TestDedicatedLoadPostgresTLSRolesExtensionAndCleanup(t *testing.T) {
	storage := os.Getenv("LINDM_LOAD_POSTGRES_INTEGRATION")
	if storage == "" {
		t.Skip("set LINDM_LOAD_POSTGRES_INTEGRATION=tmpfs or nvme to create an owned PostgreSQL container")
	}
	if storage != "tmpfs" && storage != "nvme" {
		t.Fatal("LINDM_LOAD_POSTGRES_INTEGRATION must be tmpfs or nvme")
	}
	repository, binary := os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD")
	if repository == "" || binary == "" {
		t.Fatal("set LINDM_CONSOLE_REPOSITORY and LINDM_CONSOLE_LINDMD for the dedicated load fixture regression")
	}
	sharedURLPath := filepath.Join(FixturePath(repository), "migration-database-url")
	sharedURL, err := os.ReadFile(sharedURLPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sharedURL)
	sharedHash := sha256.Sum256(sharedURL)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	fixture, err := OpenLoadAuthorityFixture(ctx, repository, binary, LoadAuthorityOptions{DatabaseStorage: storage, PostgresCPUs: os.Getenv("LINDM_LOAD_POSTGRES_CPUS"), ServerCPUs: os.Getenv("LINDM_LOAD_SERVER_CPUS")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	})
	environment := fixture.ExperimentEnvironment()
	if environment.ContainerID == "" || environment.Image != loadPostgresImage || environment.ImageDigest != loadPostgresDigest {
		t.Fatal("dedicated fixture omitted container identity or pinned image")
	}
	if environment.PostgresEffectiveCPUs == "" || validateLoadCPUList(environment.PostgresEffectiveCPUs) != nil {
		t.Fatal("dedicated fixture omitted actual PostgreSQL process CPU affinity")
	}
	if storage == "tmpfs" && (environment.Storage != "storage: tmpfs (no durable fsync cost)" || environment.StorageLimitBytes != 24<<30) {
		t.Fatal("tmpfs environment makes an incorrect durability or capacity claim")
	}
	if storage == "nvme" && (environment.Filesystem != "xfs" || environment.LoopDevice == "" || len(environment.BackingDevices) == 0) {
		t.Fatal("durable environment omitted XFS/loop/NVMe evidence")
	}
	document, err := config.Load(fixture.configPath())
	if err != nil {
		t.Fatal(err)
	}
	database, err := document.MigrationDatabase()
	if err != nil {
		t.Fatal(err)
	}
	sharedConfiguration, err := pgx.ParseConfig(strings.TrimSpace(string(sharedURL)))
	if err != nil {
		t.Fatal("parse maintained shared PostgreSQL URL failed")
	}
	if database.ConnConfig.Database != fixture.DatabaseName || database.ConnConfig.Port == sharedConfiguration.Port || database.ConnConfig.Port != fixture.database.admin.Port {
		t.Fatal("server database configuration is not bound exclusively to its dedicated cluster and owned database")
	}
	connection, err := pgx.ConnectConfig(ctx, database.ConnConfig.Copy())
	if err != nil {
		t.Fatal("connect owned migrated database failed")
	}
	t.Cleanup(func() { _ = closeProfileConnection(connection) })
	var ssl bool
	var version, user string
	if err := connection.QueryRow(ctx, `SELECT s.ssl, s.version, current_user
FROM pg_stat_ssl s WHERE s.pid = pg_backend_pid()`).Scan(&ssl, &version, &user); err != nil {
		t.Fatal(err)
	}
	if !ssl || version != "TLSv1.3" || user != "lindm_migrator" {
		t.Fatal("dedicated cluster did not retain development TLS or migration role")
	}
	// Server-level settings intentionally remain unavailable to application
	// roles. Observe them through the existing read-only owned-DB profiler.
	observer, err := fixture.profileConnection(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeProfileConnection(observer) })
	var fsync bool
	var preload, queryIDs, tracking string
	if err := observer.QueryRow(ctx, `SELECT current_setting('fsync')::boolean,
current_setting('shared_preload_libraries'), current_setting('compute_query_id'),
current_setting('pg_stat_statements.track')`).Scan(&fsync, &preload, &queryIDs, &tracking); err != nil {
		t.Fatal(err)
	}
	if !fsync || !strings.Contains(preload, "pg_stat_statements") || queryIDs != "on" || tracking != "top" {
		t.Fatal("dedicated cluster did not retain development fsync or statement configuration")
	}
	if err := closeProfileConnection(observer); err != nil {
		t.Fatal(err)
	}
	var safeRoles int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN ('lindm_migrator', 'lindm_runtime') AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls`).Scan(&safeRoles); err != nil || safeRoles != 2 {
		t.Fatal("dedicated cluster application roles do not match maintained development privileges")
	}
	if err := fixture.EnableStatementProfiling(ctx); err != nil {
		t.Fatal(err)
	}
	var extension bool
	if err := connection.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&extension); err != nil || !extension {
		t.Fatal("statement extension was not installed in the owned database")
	}
	shared, err := pgx.ConnectConfig(ctx, sharedConfiguration)
	if err != nil {
		t.Fatal("read-only shared cluster isolation check failed")
	}
	var leaked bool
	err = shared.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", fixture.DatabaseName).Scan(&leaked)
	closeErr := closeProfileConnection(shared)
	if err != nil || closeErr != nil || leaked {
		t.Fatal("owned dedicated database leaked into the shared development cluster")
	}
	encoded, err := json.Marshal(environment)
	if err != nil || strings.Contains(string(encoded), database.ConnConfig.Password) || strings.Contains(string(encoded), fixture.database.admin.Password) {
		t.Fatal("experiment environment exposed a database credential")
	}
	if err := closeProfileConnection(connection); err != nil {
		t.Fatal(err)
	}
	privateDirectory := fixture.cluster.directory
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	cleanup, stop := context.WithTimeout(t.Context(), 30*time.Second)
	defer stop()
	remaining, err := loadDocker(cleanup, "ps", "--all", "--no-trunc", "--quiet", "--filter", "id="+environment.ContainerID)
	if err != nil || strings.TrimSpace(string(remaining)) != "" {
		t.Fatal("exact owned container survived cleanup")
	}
	for _, path := range []string{privateDirectory, fixture.directory, environment.BackingFile} {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("owned resource survived cleanup: %s", path)
		}
	}
	if storage == "nvme" {
		output, err := loadStorageCommand(cleanup, true, "losetup", "--json", "--output", "NAME,BACK-FILE")
		if err != nil || strings.Contains(string(output), environment.BackingFile) {
			t.Fatal("owned loop backing survived cleanup")
		}
	}
	unchanged, err := os.ReadFile(sharedURLPath)
	if err != nil || sha256.Sum256(unchanged) != sharedHash {
		t.Fatal("dedicated fixture changed shared database credentials")
	}
	clear(unchanged)
}
