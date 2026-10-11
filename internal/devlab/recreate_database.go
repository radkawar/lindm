package devlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/config"
	"lindm/internal/labexec"
)

// Shared with initial provisioning; cluster roles already exist on recreation.
const applicationDatabaseSQL = `ALTER DATABASE lindm OWNER TO lindm_migrator;
REVOKE ALL ON DATABASE lindm FROM PUBLIC;
GRANT CONNECT ON DATABASE lindm TO lindm_runtime;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO lindm_migrator;
GRANT USAGE ON SCHEMA public TO lindm_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO lindm_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO lindm_runtime;
`

func recreationTarget(cfg *pgx.ConnConfig) (string, error) {
	if cfg.User != "lindm_migrator" || cfg.Database != "lindm" || cfg.Host != "localhost" || cfg.Port != 15432 || cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify {
		return "", errors.New("database recreation requires the maintained localhost:15432/lindm fixture with verified TLS")
	}
	return "lindm", nil
}

// RecreateDatabase destroys only the shared application database, never cluster
// roles or other databases. Explicit consent is mandatory even without clients.
func RecreateDatabase(ctx context.Context, repoRoot string, confirm bool) error {
	if !confirm {
		return errors.New("recreate-database requires -confirm-delete; this destroys lindm data and terminates its connections")
	}
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
		name, err := recreationTarget(migration.ConnConfig)
		if err != nil {
			return err
		}
		password, err := os.ReadFile(filepath.Join(dir, "postgres-password"))
		if err != nil {
			return err
		}
		defer clear(password)
		admin := migration.ConnConfig.Copy()
		admin.User, admin.Password, admin.Database = "postgres", strings.TrimSpace(string(password)), "postgres"
		conn, err := pgx.ConnectConfig(ctx, admin)
		if err != nil {
			return errors.New("connect fixture PostgreSQL administration over verified TLS failed")
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, conn.Close(cleanup))
		}()
		var superuser bool
		if err := conn.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&superuser); err != nil {
			return err
		}
		if !superuser {
			return errors.New("fixture administration role is not a superuser")
		}
		// FORCE terminates only sessions in this exact database, including lindmd.
		// PostgreSQL also prevents new connections while performing the drop.
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			return fmt.Errorf("drop application database: %w", err)
		}
		if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" OWNER lindm_migrator"); err != nil {
			return fmt.Errorf("recreate application database: %w", err)
		}
		admin = admin.Copy()
		admin.Database = name
		application, err := pgx.ConnectConfig(ctx, admin)
		if err != nil {
			return errors.New("connect recreated application database failed")
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, application.Close(cleanup))
		}()
		if _, err := application.Exec(ctx, applicationDatabaseSQL); err != nil {
			return fmt.Errorf("provision application database permissions: %w", err)
		}
		return migrateAndBootstrap(ctx, root, document.Proto.GetAuthentication().GetLocal() != nil)
	})
}

func verifyRunningPostgres(ctx context.Context, root string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Inspect the checkout-specific Compose container and its actual mount and
	// published endpoint; do not trust a reachable PostgreSQL port alone.
	format := `{{.State.Running}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{range .Mounts}}{{if eq .Destination "/run/lindm-dev/postgres-password"}}{{.Source}}{{end}}{{end}}|{{range (index .NetworkSettings.Ports "5432/tcp")}}{{.HostIp}}:{{.HostPort}}{{end}}`
	output := nativeexec.NewBuffer(4096)
	if err := labexec.Run(ctx, labexec.Command{Path: "docker", Args: []string{"inspect", "--format", format, ProjectName(root) + "-postgres-1"}, Stdout: output}); err != nil {
		return fmt.Errorf("inspect checkout-owned PostgreSQL container: %w", err)
	}
	if output.Truncated() {
		return errors.New("checkout-owned PostgreSQL inspection exceeded output limit")
	}
	want := "true|" + ProjectName(root) + "|postgres|" + filepath.Join(FixturePath(root), "postgres-password") + "|" + net.JoinHostPort("127.0.0.1", "15432")
	if strings.TrimSpace(output.String()) != want {
		return errors.New("running PostgreSQL container does not match this checkout's Compose project, protected secret mount and loopback port")
	}
	return nil
}
