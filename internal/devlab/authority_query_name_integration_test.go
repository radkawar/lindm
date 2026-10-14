// SPDX-License-Identifier: Apache-2.0

//go:build integration

package devlab

import (
	"strings"
	"testing"

	"lindm/internal/testdb"
)

// pg_stat_statements normalizes literals, not every comment or utility command.
// Exercise the actual PostgreSQL projection rather than a Go approximation of
// its regex syntax; neither credentials nor arbitrary SQL may leave the server.
func TestDatabaseProfileQueryNamesExcludeSQLAndSecrets(t *testing.T) {
	_, conn := testdb.Open(t)
	for _, test := range []struct {
		name  string
		query string
		want  string
	}{
		{"sqlc", "-- name: LockInventoryReservation :one\nSELECT reserved_bytes FROM inventory_reservation FOR UPDATE", "LockInventoryReservation"},
		{"sqlc_parameters", "-- name: InsertDeviceCertificate :exec\nINSERT INTO secrets VALUES ('credential-must-not-leave-postgres')", "InsertDeviceCertificate"},
		{"crlf", "-- name: GetDeviceForUpdate :one\r\nSELECT 1", "GetDeviceForUpdate"},
		{"utility", "CREATE ROLE profile_test PASSWORD 'credential-must-not-leave-postgres'", ""},
		{"comment", "/* credential-must-not-leave-postgres */ SELECT 1", ""},
		{"trailing_secret", "-- name: PublicName :one credential-must-not-leave-postgres\nSELECT 1", ""},
		{"embedded_label", "SELECT '-- name: Secret :one\n'", ""},
		{"oversized_label", "-- name: " + strings.Repeat("x", 97) + " :one\nSELECT 1", ""},
		{"injected_name", "-- name: credential-must-not-leave-postgres :one\nSELECT 1", ""},
		{"unknown_command", "-- name: Secret :password\nSELECT 1", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got string
			if err := conn.QueryRow(t.Context(), `SELECT coalesce(substring($1::text from $2::text), '')`, test.query, profileQueryNamePattern).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("unsafe or missing query label: got %q, want %q", got, test.want)
			}
		})
	}
}
