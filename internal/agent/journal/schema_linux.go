package journal

import (
	"context"
	"strings"

	"lindm/internal/agent/journal/journaldb"
)

// Only reviewed table definitions may be present. Checking SQL also rejects
// removed constraints, foreign indexes and triggers. Opening never repairs DDL.
func validateJournalSchema(ctx context.Context, db journaldb.DBTX) error {
	expected := map[string]bool{"executor_state": true, "execution_trust": true}
	for _, name := range serviceTableNames {
		expected[name] = true
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
		if kind != "table" || !expected[name] || normalizeDDL(ddl) != normalizeDDL(journalTableDDL(name)) {
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

var serviceTableNames = [...]string{"service_actions", "service_resource_floors", "service_action_usage"}

func normalizeDDL(ddl string) string {
	return strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(ddl), ";")), " ")
}

func journalTableDDL(name string) string {
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
		if strings.HasPrefix(statement, "CREATE TABLE "+name+" (") {
			return statement
		}
	}
	panic("missing reviewed journal table definition")
}
