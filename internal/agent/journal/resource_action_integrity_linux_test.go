package journal

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestResourceActionsDamagedCurrentSchemaNeverRepairs(t *testing.T) {
	cases := []string{
		"missing action table", "missing floor table", "missing accounting table", "missing accounting row", "missing action", "missing floor", "empty actions and floors",
		"foreign table", "foreign trigger", "normalized state", "normalized identity", "lower floor", "higher floor", "foreign floor action", "wrong totals", "unknown proto field", "malformed proto", "invalid digest", "invalid grant time",
		"lost reservation",
	}
	for _, damage := range cases {
		t.Run(damage, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			record := f.record(t, 1, "example.service", true)
			if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
				t.Fatal(err)
			}
			queued := serviceQueued(record)
			if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, queued); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			db := openFixtureDB(t, f.directory, "rw")
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := db.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch damage {
			case "missing action table":
				exec(`DROP TABLE resource_actions`)
			case "missing floor table":
				exec(`DROP TABLE resource_floors`)
			case "missing accounting table":
				exec(`DROP TABLE resource_action_usage`)
			case "missing accounting row":
				exec(`DELETE FROM resource_action_usage`)
			case "missing action":
				exec(`DELETE FROM resource_actions`)
			case "missing floor":
				exec(`DELETE FROM resource_floors`)
			case "empty actions and floors":
				exec(`DELETE FROM resource_floors`)
				exec(`DELETE FROM resource_actions`)
			case "foreign table":
				exec(`CREATE TABLE unexpected (value TEXT)`)
			case "foreign trigger":
				exec(`CREATE TRIGGER unexpected AFTER UPDATE ON resource_actions BEGIN SELECT 1; END`)
			case "normalized state":
				exec(`UPDATE resource_actions SET state = 3`)
			case "normalized identity":
				exec(`UPDATE resource_actions SET canonical_key = 'foreign.service'`)
			case "lower floor":
				exec(`UPDATE resource_actions SET resource_sequence = 2`)
			case "higher floor":
				exec(`UPDATE resource_floors SET resource_sequence = 2`)
			case "foreign floor action":
				exec(`UPDATE resource_floors SET action_id = '00000000-0000-4000-8000-000000000001'`)
			case "wrong totals":
				exec(`UPDATE resource_action_usage SET record_bytes = record_bytes + 1`)
			case "lost reservation":
				exec(`UPDATE resource_action_usage SET record_bytes = ?`, proto.Size(queued))
			default:
				changed := proto.CloneOf(queued)
				switch damage {
				case "unknown proto field":
					changed.NativePlan.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
				case "invalid digest":
					changed.IntentSha256[0]++
				case "invalid grant time":
					changed.GrantAcceptedAt = nil
				}
				encoded, err := proto.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
				if damage == "malformed proto" {
					encoded = []byte{0xff}
				}
				exec(`UPDATE resource_actions SET record = ?`, encoded)
				// QUEUED capacity remains reserved regardless of malformed
				// serialized size, so record validation must diagnose damage.
				exec(`UPDATE resource_action_usage SET record_bytes = ?`, maximumResourceActionBytes)
			}
			before := serviceDatabaseSnapshot(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if store, err := Open(t.Context(), f.directory); !errors.Is(err, ErrRecoveryHold) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatalf("damaged current schema opened: %v", err)
			}
			db = openFixtureDB(t, f.directory, "ro")
			defer func() { _ = db.Close() }()
			if after := serviceDatabaseSnapshot(t, db); after != before {
				t.Fatal("recovery hold repaired or rewrote protected data")
			}
		})
	}
}

// Capture tables and their exact values without assuming the damaged schema has
// any required tables. Snapshot values remain local and are never in failures.
func serviceDatabaseSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var result bytes.Buffer
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(&result, version)
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Error(err)
		}
	}()
	var tables []string
	for rows.Next() {
		var name, ddl string
		if err := rows.Scan(&name, &ddl); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
		fmt.Fprintln(&result, name, ddl)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		serviceTableSnapshot(t, db, table, &result)
	}
	return result.String()
}

func serviceTableSnapshot(t *testing.T, db *sql.DB, table string, result *bytes.Buffer) {
	t.Helper()
	rows, err := db.Query(`SELECT * FROM "` + table + `" ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Error(err)
		}
	}()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(result, values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
