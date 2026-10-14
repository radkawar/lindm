// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Background maintenance caused the old occupancy sample to exceed the actual
// client pool size. Exercise the reducer on the same grouped rows used by both
// Measure and ProfileDatabase, including null-state and aborted transactions.
func TestAuthorityConnectionCountsExcludeBackgroundWorkers(t *testing.T) {
	var counts AuthorityConnectionCounts
	for _, row := range []struct {
		backend string
		state   string
		waiting bool
		count   int
	}{
		{"client backend", "active", false, 2},
		{"client backend", "active", true, 3},
		{"client backend", "idle", true, 1},
		{"client backend", "idle in transaction", true, 1},
		{"client backend", "idle in transaction (aborted)", true, 1},
		{"autovacuum worker", "active", true, 4},
		{"parallel worker", "active", true, 2},
		{"logical replication worker", "", false, 1},
	} {
		counts.add(row.backend, row.state, row.waiting, row.count)
	}
	want := AuthorityConnectionCounts{
		Connections: 8, ActiveConnections: 5, IdleConnections: 1,
		IdleInTransactionConnections: 2, WaitingConnections: 3,
		AutovacuumWorkers: 4, OtherBackgroundBackends: 3,
	}
	if counts != want {
		t.Fatalf("client pool occupancy includes maintenance or inactive waits: got %+v, want %+v", counts, want)
	}
}

func TestStatementPrerequisitesDistinguishUnavailableFromEmpty(t *testing.T) {
	configuration := DatabaseProfileConfiguration{
		TrackActivities: true, ComputeQueryID: "on",
		StatementLibraryPreloaded: true, StatementTracking: "top",
	}
	status := StatementProfileStatus{
		ExtensionAvailable: true, ExtensionInstalled: true, AllStatisticsVisible: true,
	}
	for _, test := range []struct {
		name   string
		change func(*DatabaseProfileConfiguration, *StatementProfileStatus)
		reason string
	}{
		{"ready", func(*DatabaseProfileConfiguration, *StatementProfileStatus) {}, ""},
		{"auto", func(c *DatabaseProfileConfiguration, _ *StatementProfileStatus) { c.ComputeQueryID = "auto" }, ""},
		{"all", func(c *DatabaseProfileConfiguration, _ *StatementProfileStatus) { c.StatementTracking = "all" }, ""},
		{"package", func(_ *DatabaseProfileConfiguration, s *StatementProfileStatus) { s.ExtensionAvailable = false }, "extension_package_unavailable"},
		{"preload", func(c *DatabaseProfileConfiguration, _ *StatementProfileStatus) { c.StatementLibraryPreloaded = false }, "library_not_preloaded"},
		{"query_id", func(c *DatabaseProfileConfiguration, _ *StatementProfileStatus) { c.ComputeQueryID = "off" }, "query_id_computation_disabled"},
		{"tracking", func(c *DatabaseProfileConfiguration, _ *StatementProfileStatus) { c.StatementTracking = "none" }, "statement_tracking_disabled"},
		{"extension", func(_ *DatabaseProfileConfiguration, s *StatementProfileStatus) { s.ExtensionInstalled = false }, "extension_not_installed_in_owned_database"},
		{"visibility", func(_ *DatabaseProfileConfiguration, s *StatementProfileStatus) { s.AllStatisticsVisible = false }, "statistics_visibility_denied"},
		{"activity", func(c *DatabaseProfileConfiguration, _ *StatementProfileStatus) { c.TrackActivities = false }, "activity_tracking_disabled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, s := configuration, status
			test.change(&c, &s)
			reasons, instructions := statementPrerequisites(c, s)
			if test.reason == "" {
				if len(reasons) != 0 || len(instructions) != 0 {
					t.Fatalf("ready prerequisites rejected: %v", reasons)
				}
				return
			}
			if len(reasons) != 1 || reasons[0] != test.reason || len(instructions) != 1 || instructions[0] == "" {
				t.Fatalf("missing actionable prerequisite: %v / %v", reasons, instructions)
			}
		})
	}
}

func TestDatabaseProfileRejectsUnownedDatabaseBeforeConnecting(t *testing.T) {
	for _, fixture := range []*AuthorityFixture{
		nil,
		{},
		{DatabaseName: "shared", database: &authorityDatabase{name: "owned", created: true}},
		{closed: true, DatabaseName: "owned", database: &authorityDatabase{name: "owned", created: true}},
		{DatabaseName: "owned", database: &authorityDatabase{name: "owned", created: false}},
	} {
		if _, err := fixture.ProfileDatabase(t.Context()); err == nil {
			t.Fatal("profiling accepted an unowned or closed database")
		}
		if err := fixture.EnableStatementProfiling(t.Context()); err == nil {
			t.Fatal("extension setup accepted an unowned or closed database")
		}
	}
}

func TestDatabaseProfileErrorsDoNotPersistConnectionOrSQLSecrets(t *testing.T) {
	const secret = "postgres://user:secret@example.invalid/private"
	for _, source := range []error{
		errors.New(secret),
		&pgconn.PgError{Code: "42501", Message: secret, Detail: secret, InternalQuery: secret},
		fmt.Errorf("%s: %w", secret, context.Canceled),
		fmt.Errorf("%s: %w", secret, context.DeadlineExceeded),
	} {
		got := profileError("sample", source)
		if got == nil || strings.Contains(got.Error(), secret) {
			t.Fatalf("unsafe diagnostic error: %v", got)
		}
		if errors.Is(source, context.Canceled) && !errors.Is(got, context.Canceled) {
			t.Fatal("lost cancellation cause")
		}
		if errors.Is(source, context.DeadlineExceeded) && !errors.Is(got, context.DeadlineExceeded) {
			t.Fatal("lost deadline cause")
		}
	}
	if profileError("sample", nil) != nil {
		t.Fatal("successful observation produced an error")
	}
}
