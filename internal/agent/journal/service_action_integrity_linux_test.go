package journal

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func TestServiceActionsMigrateGenuineHistoricalSchemas(t *testing.T) {
	for _, version := range []int{priorSchemaVersion, trustSchemaVersion} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			state := acknowledgedState(t)
			trust := configuredTrust(state.GetInstallationId(), 1, 1, 1, time.Unix(1_800_000_000, 0).UTC())
			trustBytes, err := proto.Marshal(trust)
			if err != nil {
				t.Fatal(err)
			}
			// A redundant known field is valid protobuf but is not the default
			// encoder output: migration must preserve these exact stored bytes.
			trustBytes = append(trustBytes, 0x08, 0x01)
			directory, authorityBytes := writeHistoricalJournal(t, state, 4, func(db *sql.DB, _ string) {
				if version == trustSchemaVersion {
					if _, err := db.Exec(executionTrustDDL()); err != nil {
						t.Fatal(err)
					}
					if _, err := db.Exec(`INSERT INTO execution_trust (id, revision, state) VALUES (1, 7, ?)`, trustBytes); err != nil {
						t.Fatal(err)
					}
				}
			})
			if version == trustSchemaVersion {
				db := openFixtureDB(t, directory, "rw")
				if _, err := db.Exec(`PRAGMA user_version = 2`); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			store, err := Open(t.Context(), directory)
			if err != nil {
				t.Fatalf("historical schema %d: %v", version, err)
			}
			defer func() { _ = store.Close() }()
			assertSchemaIdentity(t, store.db, schemaVersion)
			if revision, encoded := authorityColumn(t, store.db); revision != 4 || !bytes.Equal(encoded, authorityBytes) {
				t.Fatal("migration changed authority bytes/revision")
			}
			if version == trustSchemaVersion {
				row, err := store.queries.ReadExecutionTrust(t.Context())
				if err != nil || row.Revision != 7 || !bytes.Equal(row.State, trustBytes) {
					t.Fatalf("migration changed trust bytes/revision: %v", err)
				}
				fixture := serviceJournalFixture{store: store, directory: directory, authority: state, trust: trust}
				record := fixture.record(t, 1, "example.service", true)
				if _, err := store.AcceptServiceAction(t.Context(), 4, 7, record); err != nil {
					t.Fatalf("migrated configured trust cannot accept work: %v", err)
				}
				assertServiceRecord(t, store, record, 1)
			} else {
				loaded, revision, err := store.LoadExecutionTrust(t.Context())
				if err != nil || revision != 1 {
					t.Fatalf("v1 trust initialization: %v", err)
				}
				assertUnconfiguredTrust(t, loaded, state.GetInstallationId())
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(t.Context(), directory)
			if err != nil {
				t.Fatalf("migrated schema cannot reopen: %v", err)
			}
			defer func() { _ = reopened.Close() }()
			if revision, encoded := authorityColumn(t, reopened.db); revision != 4 || !bytes.Equal(encoded, authorityBytes) {
				t.Fatal("service migration/update rewrote authority")
			}
		})
	}
}

func TestServiceActionsRejectHistoricalStampsOnPartialNewSchema(t *testing.T) {
	for _, version := range []int{priorSchemaVersion, trustSchemaVersion} {
		for _, table := range serviceTableNames {
			t.Run(fmt.Sprintf("v%d/%s", version, table), func(t *testing.T) {
				state := acknowledgedState(t)
				trustBytes, err := proto.Marshal(unconfiguredExecutionTrust(state.GetInstallationId()))
				if err != nil {
					t.Fatal(err)
				}
				directory, authorityBytes := writeHistoricalJournal(t, state, 4, func(db *sql.DB, _ string) {
					if version == trustSchemaVersion {
						if _, err := db.Exec(executionTrustDDL()); err != nil {
							t.Fatal(err)
						}
						if _, err := db.Exec(`INSERT INTO execution_trust (id, revision, state) VALUES (1, 3, ?)`, trustBytes); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := db.Exec(journalTableDDL(table)); err != nil {
						t.Fatal(err)
					}
				})
				db := openFixtureDB(t, directory, "rw")
				if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				if store, err := Open(t.Context(), directory); !errors.Is(err, ErrRecoveryHold) {
					if store != nil {
						_ = store.Close()
					}
					t.Fatalf("partial newer schema migrated: %v", err)
				}
				facts := inspectJournal(t, directory)
				if facts.version != version || facts.authorityRev != 4 || !bytes.Equal(facts.authority, authorityBytes) || facts.hasTrustTable != (version == trustSchemaVersion) {
					t.Fatal("rejected migration changed historical state")
				}
				if version == trustSchemaVersion && (facts.trustRevision != 3 || !bytes.Equal(facts.trust, trustBytes)) {
					t.Fatal("rejected migration changed prior trust")
				}
			})
		}
	}
}

func TestServiceActionsDamagedCurrentSchemaNeverRepairs(t *testing.T) {
	cases := []string{
		"missing action table", "missing floor table", "missing accounting table", "missing accounting row", "missing action", "missing floor", "empty actions and floors",
		"foreign table", "foreign trigger", "normalized state", "normalized identity", "lower floor", "higher floor", "foreign floor action", "wrong totals", "unknown proto field", "malformed proto", "invalid digest", "invalid grant time",
		"lost reservation",
	}
	for _, damage := range cases {
		t.Run(damage, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			record := f.record(t, 1, "example.service", true)
			if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, record); err != nil {
				t.Fatal(err)
			}
			queued := serviceQueued(record)
			if _, err := f.store.UpdateServiceAction(t.Context(), 1, 1, 2, queued); err != nil {
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
				exec(`DROP TABLE service_actions`)
			case "missing floor table":
				exec(`DROP TABLE service_resource_floors`)
			case "missing accounting table":
				exec(`DROP TABLE service_action_usage`)
			case "missing accounting row":
				exec(`DELETE FROM service_action_usage`)
			case "missing action":
				exec(`DELETE FROM service_actions`)
			case "missing floor":
				exec(`DELETE FROM service_resource_floors`)
			case "empty actions and floors":
				exec(`DELETE FROM service_resource_floors`)
				exec(`DELETE FROM service_actions`)
			case "foreign table":
				exec(`CREATE TABLE unexpected (value TEXT)`)
			case "foreign trigger":
				exec(`CREATE TRIGGER unexpected AFTER UPDATE ON service_actions BEGIN SELECT 1; END`)
			case "normalized state":
				exec(`UPDATE service_actions SET state = 3`)
			case "normalized identity":
				exec(`UPDATE service_actions SET unit = 'foreign.service'`)
			case "lower floor":
				exec(`UPDATE service_actions SET resource_sequence = 2`)
			case "higher floor":
				exec(`UPDATE service_resource_floors SET resource_sequence = 2`)
			case "foreign floor action":
				exec(`UPDATE service_resource_floors SET action_id = '00000000-0000-4000-8000-000000000001'`)
			case "wrong totals":
				exec(`UPDATE service_action_usage SET record_bytes = record_bytes + 1`)
			case "lost reservation":
				exec(`UPDATE service_action_usage SET record_bytes = ?`, proto.Size(queued))
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
				exec(`UPDATE service_actions SET record = ?`, encoded)
				// QUEUED capacity remains reserved regardless of malformed
				// serialized size, so record validation must diagnose damage.
				exec(`UPDATE service_action_usage SET record_bytes = ?`, maximumServiceActionBytes)
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
