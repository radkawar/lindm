// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"context"
	"crypto/x509"
	"errors"
	"os"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/custody"
	"lindm/internal/serverops"
)

// DeployDatabaseDiagnostic contains only fixed classifications and privilege
// booleans. Driver messages may contain passwords and must never be exported.
type DeployDatabaseDiagnostic struct {
	StageLoaded      bool   `json:"stage_loaded"`
	PoolBuilt        bool   `json:"pool_built"`
	QuerySucceeded   bool   `json:"query_succeeded"`
	Restricted       bool   `json:"restricted"`
	DatabaseOwner    bool   `json:"database_owner"`
	SchemaCreate     bool   `json:"schema_create"`
	SchemaOwnerUsage bool   `json:"schema_owner_usage"`
	ErrorCategory    string `json:"error_category,omitempty"`
	SQLState         string `json:"sqlstate,omitempty"`
}

// ObserveDeployDatabaseDiagnostic runs only in a failed lab guest before its
// owned cleanup. It makes no role/configuration changes and cannot qualify a run.
func ObserveDeployDatabaseDiagnostic(ctx context.Context) (*DeployDatabaseDiagnostic, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("deploy: database_diagnostic_root_required")
	}
	if err := custody.LockSecretMemory(); err != nil {
		return nil, errors.New("deploy: database_diagnostic_secret_memory_unavailable")
	}
	result := new(DeployDatabaseDiagnostic)
	document, cleanup, err := serverops.StageDatabaseConfig("/etc/lindm/migrate/server.json")
	if err != nil {
		result.ErrorCategory = "stage_failed"
		return result, nil
	}
	result.StageLoaded = true
	config, err := document.MigrationDatabase()
	if err != nil {
		result.ErrorCategory = "configuration_failed"
		if cleanup() != nil {
			result.ErrorCategory = "configuration_and_cleanup_failed"
		}
		return result, nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	cleanupErr := cleanup()
	if err != nil || cleanupErr != nil {
		if pool != nil {
			pool.Close()
		}
		result.ErrorCategory = "pool_or_cleanup_failed"
		return result, nil
	}
	defer pool.Close()
	result.PoolBuilt = true
	err = pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication, current_user = pg_get_userbyid(d.datdba), has_schema_privilege(current_user,'public','CREATE'), pg_has_role(current_user,n.nspowner,'USAGE') FROM pg_roles r JOIN pg_database d ON d.datname=current_database() JOIN pg_namespace n ON n.nspname='public' WHERE r.rolname=current_user`).Scan(&result.Restricted, &result.DatabaseOwner, &result.SchemaCreate, &result.SchemaOwnerUsage)
	if err != nil {
		result.ErrorCategory, result.SQLState = deployDatabaseErrorClassification(err)
		return result, nil
	}
	result.QuerySucceeded = true
	return result, nil
}

func deployDatabaseErrorClassification(err error) (string, string) {
	if errors.Is(err, context.Canceled) {
		return "canceled", ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline", ""
	}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	switch {
	case errors.As(err, &unknown):
		return "tls_unknown_authority", ""
	case errors.As(err, &hostname):
		return "tls_hostname", ""
	case errors.As(err, &certificate):
		return "tls_certificate", ""
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		code := postgres.Code
		if len(code) == 5 {
			for _, c := range code {
				if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
					return "postgres", ""
				}
			}
			return "postgres", code
		}
		return "postgres", ""
	}
	var connection *pgconn.ConnectError
	if errors.As(err, &connection) {
		return "connection", ""
	}
	return "query", ""
}
