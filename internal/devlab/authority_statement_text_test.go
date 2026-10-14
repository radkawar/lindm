// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"strings"
	"testing"
)

func TestProfileStatementTextRedactsNonsecretDML(t *testing.T) {
	for _, test := range []struct {
		name  string
		query string
		want  string
	}{
		{"normalized_probe", "SELECT $1::text || $2, pg_sleep($3)", "SELECT $1 :: text || $2 , pg_sleep ( $3 )"},
		{"strings", "SELECT 'secret-value', 'another''secret', N'secret-value', E'secret-value'", "SELECT ? , ? , ? , ?"},
		{"dollar_quotes", "SELECT $$secret-value ' \" -- /* $$, $tag$secret-value$other$tag$", "SELECT ? , ?"},
		{"quoted_identifiers", `SELECT "secret-value", "secret""value" FROM "secret-table"`, "SELECT ? , ? FROM ?"},
		{"nested_comments", "/* secret-value /* secret-value */ secret-value */ SELECT $1 /* secret-value /* nested */ end */ -- secret-value\nFROM devices", "SELECT $1 FROM devices"},
		{"sqlc_comment", "-- name: OwnedProfileProbe :one\nSELECT $1; -- secret-value", "SELECT $1"},
		{"insert", "INSERT INTO devices (id) VALUES ($1)", "INSERT INTO devices ( id ) VALUES ( $1 )"},
		{"update", "UPDATE devices SET hostname = $1 WHERE id=$2", "UPDATE devices SET hostname = $1 WHERE id = $2"},
		{"delete", "DELETE FROM devices WHERE id=$1", "DELETE FROM devices WHERE id = $1"},
		{"cte", "WITH x AS (SELECT 'secret-value') SELECT * FROM x", "WITH x AS ( SELECT ? ) SELECT * FROM x"},
		{"comment_after_operator", "SELECT $1+/* secret-value */$2", "SELECT $1 + $2"},
		{"unicode_literal", "SELECT '秘密secret-value', U&'secret-value', B'1010', X'AF'", "SELECT ? , ? , ? , ?"},
		{"numbers", "SELECT 123456, 1.234e5", "SELECT ? , ?"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, available := profileStatementText(test.query)
			if !available || got != test.want {
				t.Fatalf("incorrect redacted statement: available=%t got=%q want=%q", available, got, test.want)
			}
			if strings.Contains(got, "secret") {
				t.Fatal("statement diagnostic leaked literal, identifier or comment content")
			}
		})
	}
}

func TestProfileStatementTextOmissionIsExplicitAndComplete(t *testing.T) {
	for _, query := range []string{
		"",
		"/* only comment */",
		"CREATE ROLE profile_test PASSWORD 'secret-value'",
		"ALTER ROLE profile_test PASSWORD $$secret-value$$",
		"SET application_name = 'secret-value'",
		"COPY devices FROM PROGRAM 'secret-value'",
		"DO $$BEGIN RAISE NOTICE 'secret-value'; END$$",
		"EXPLAIN SELECT 'secret-value'",
		"SELECT 'unterminated secret-value",
		"SELECT \"unterminated secret-value",
		"SELECT $tag$unterminated secret-value",
		"SELECT $1 /* secret-value /* nested */",
		"SELECT $1; CREATE ROLE profile_test PASSWORD 'secret-value'",
		"SELECT $1; SELECT 'secret-value'",
		`SELECT E'escaped\'secret-value'`,
		`SELECT '\', 'secret-value', '\'`,
		`SELECT U&'\0073ecret-value'`,
		`SELECT U&"\0073ecret-value"`,
		"SELECT $invalid_dollar_tag",
		"SELECT $1 \x00 secret-value",
		"SELECT " + strings.Repeat("x", profileStatementTextLimit),
		"SELECT " + strings.Repeat("()", profileStatementTextLimit/2-4),
	} {
		got, available := profileStatementText(query)
		if available || got != "" {
			t.Fatalf("unsafe or incomplete statement was exposed: available=%t text=%q", available, got)
		}
	}
}
