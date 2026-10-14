// SPDX-License-Identifier: Apache-2.0

//go:build integration

package testdb

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Template is a logical snapshot of a freshly migrated, otherwise unused schema.
// The integration fixture obtains SQL from its pinned PostgreSQL pg_dump, including
// migration history and seed rows. It never substitutes a second migration parser.
// Each restore owns new tables, sequences, functions, triggers and seed rows.
// Logical schema copies avoid DROP DATABASE's cluster-wide forced checkpoints.
type Template struct {
	Schema string
	SQL    string
}

// NewFromTemplate restores a run-owned migration snapshot into a private schema.
// New remains the uncached path for tests exercising the migration runner itself.
func NewFromTemplate(ctx context.Context, dsn string, template Template) (*Database, error) {
	if !strings.HasPrefix(template.Schema, "lindm_test_") || len(template.Schema) != len("lindm_test_")+32 || strings.Trim(template.Schema[len("lindm_test_"):], "0123456789abcdef") != "" || template.SQL == "" {
		return nil, errors.New("invalid integration migration template")
	}
	return newDatabase(ctx, dsn, func(pool *pgxpool.Pool, schema string) error {
		// Both names contain only the reserved prefix and random lowercase hex.
		// pg_dump emits this generated schema name as an unquoted identifier.
		// Remove its exact CREATE statement (New already created the schema)
		// and remap qualified references in a single pass over the snapshot.
		sql := strings.NewReplacer("CREATE SCHEMA "+template.Schema+";", "", template.Schema, schema).Replace(template.SQL)
		// Restore volatile identity seed defaults independently for each test.
		_, err := pool.Exec(ctx, "BEGIN;\n"+sql+"\nSET search_path = "+schema+";\nUPDATE deployment_identity SET deployment_id = DEFAULT;\nUPDATE report_audit_head SET chain_id = DEFAULT;\nCOMMIT;")
		return err
	})
}
