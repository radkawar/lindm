package devlab

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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

func (d *authorityDatabase) Close() error {
	// DROP may wait for PostgreSQL checkpoint/storage work: an exact owned
	// database DROP took 127 seconds during the capacity lane without FORCE.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return d.drop(ctx, false)
}

func (d *authorityDatabase) drop(ctx context.Context, missingOK bool) (resultErr error) {
	if !d.created {
		return nil
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
	// No FORCE: a surviving client makes cleanup fail visibly, never terminates
	// another process. The fixture stops and joins its server before this call.
	statement := "DROP DATABASE "
	if missingOK {
		statement += "IF EXISTS "
	}
	if _, err := connection.Exec(ctx, statement+pgx.Identifier{d.name}.Sanitize()); err != nil {
		return fmt.Errorf("remove owned authority database %s: %w", d.name, err)
	}
	d.created = false
	return nil
}
