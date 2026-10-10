package journal

import (
	"context"
	"strings"

	"lindm/internal/agent/journal/journaldb"
)

// Only reviewed table definitions may be present. Checking SQL also rejects
// removed constraints, foreign indexes and triggers. Opening never repairs DDL,
// and an older service-only journal holds for re-provisioning.
func validateJournalSchema(ctx context.Context, db journaldb.DBTX) error {
	expected := map[string]string{"executor_state": "table", "execution_trust": "table", "resource_actions_read_only": "index", "device_actions": "table", "device_action_usage": "table", "account_locks": "table", "account_lock_owners": "table", "account_lock_usage": "table"}
	for _, name := range resourceTableNames {
		expected[name] = "table"
	}
	rows, err := db.QueryContext(ctx, `SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL`)
	if err != nil {
		return stateReadError(ctx)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kind, name, ddl string
		if err := rows.Scan(&kind, &name, &ddl); err != nil {
			return stateReadError(ctx)
		}
		if expected[name] != kind || normalizeDDL(ddl) != normalizeDDL(journalObjectDDL(name)) {
			return ErrRecoveryHold
		}
		delete(expected, name)
	}
	if err := rows.Err(); err != nil {
		return stateReadError(ctx)
	}
	if len(expected) != 0 {
		return ErrRecoveryHold
	}
	return nil
}

var resourceTableNames = [...]string{"resource_actions", "resource_floors", "resource_action_usage", "resource_ownership", "resource_ownership_usage", "resource_ownership_reservations", "resource_preparation_cancellations"}

func normalizeDDL(ddl string) string {
	return strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(ddl), ";")), " ")
}

func journalObjectDDL(name string) string {
	// schema.sql contains only whole-line comments and semicolon-delimited DDL.
	var source strings.Builder
	for _, line := range strings.Split(schema, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			source.WriteString(line)
			source.WriteByte('\n')
		}
	}
	for _, statement := range strings.Split(source.String(), ";") {
		statement = strings.TrimSpace(statement)
		if strings.HasPrefix(statement, "CREATE TABLE "+name+" (") || strings.HasPrefix(statement, "CREATE INDEX "+name+" ON ") {
			return statement
		}
	}
	panic("missing reviewed journal schema definition")
}
