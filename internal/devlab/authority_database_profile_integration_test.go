// SPDX-License-Identifier: Apache-2.0

//go:build integration && consolelab

package devlab

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This opt-in lane needs protected development trust, a prebuilt lindmd, and the
// development PostgreSQL pg_stat_statements preload. It creates only owned DBs;
// it does not reset shared statistics or change/restart shared dependencies.
func TestAuthorityDatabaseProfileOwnsScopeAndObservesBlocking(t *testing.T) {
	repository, binary := os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD")
	if repository == "" || binary == "" {
		t.Fatal("set LINDM_CONSOLE_REPOSITORY and LINDM_CONSOLE_LINDMD for the owned database profiling regression")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	fixture, err := OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := fixture.EnableStatementProfiling(ctx); err != nil {
		t.Fatal(err)
	}
	blocker, err := fixture.profileConnection(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeProfileConnection(blocker); err != nil {
			t.Error(err)
		}
	})
	foreign := &authorityDatabase{
		name:  "lindm_profile_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		admin: fixture.database.admin.Copy(),
	}
	if _, err := blocker.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{foreign.name}.Sanitize()+" TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	foreign.created = true
	t.Cleanup(func() {
		if err := foreign.Close(); err != nil {
			t.Error(err)
		}
	})
	foreignConfig := foreign.admin.Copy()
	foreignConfig.Database = foreign.name
	foreignConn, err := pgx.ConnectConfig(ctx, foreignConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeProfileConnection(foreignConn); err != nil {
			t.Error(err)
		}
	})
	observerConfig := foreignConfig.Copy()
	observerConfig.RuntimeParams["application_name"] = authorityProfileApplication
	observer, err := pgx.ConnectConfig(ctx, observerConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeProfileConnection(observer); err != nil {
			t.Error(err)
		}
	})
	counts, err := readAuthorityConnectionCounts(ctx, foreignConn)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Connections != 0 {
		t.Fatalf("diagnostic connection inflated owned pool occupancy: %+v", counts)
	}
	peer, err := pgx.ConnectConfig(ctx, foreignConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeProfileConnection(peer); err != nil {
			t.Error(err)
		}
	})
	counts, err = readAuthorityConnectionCounts(ctx, foreignConn)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Connections != 1 {
		t.Fatalf("real client was omitted from owned pool occupancy: %+v", counts)
	}
	if _, err := foreignConn.Exec(ctx, "-- name: ForeignDatabaseQuery :one\nSELECT pg_advisory_lock(7722341), pg_sleep(0.2), 4878374::numeric"); err != nil {
		t.Fatal(err)
	}
	const secret = "credential-must-not-leave-postgres"
	for range 3 {
		if _, err := blocker.Exec(ctx, "-- name: OwnedProfileProbe :one\nSELECT $1::text || 'profile-probe', pg_sleep(0.05)", secret); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := blocker.Exec(ctx, "-- name: OwnedProfileLock :one\nSELECT pg_advisory_lock(7722341)"); err != nil {
		t.Fatal(err)
	}
	waiter, err := fixture.profileConnection(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, stopWait := context.WithCancel(ctx)
	waitDone := make(chan error, 1)
	go func() {
		_, err := waiter.Exec(waitCtx, "-- name: OwnedProfileWait :one\nSELECT pg_advisory_lock(7722341)")
		waitDone <- err
	}()
	t.Cleanup(func() {
		stopWait()
		select {
		case err := <-waitDone:
			if err == nil {
				t.Error("waiter acquired a lock still held by blocker")
			}
		case <-time.After(5 * time.Second):
			t.Error("blocked query did not cancel")
		}
		if err := closeProfileConnection(waiter); err != nil {
			t.Error(err)
		}
	})
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		profile, err := fixture.ProfileDatabase(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !profile.Statements.Available {
			t.Fatalf("statement profile unavailable: %v; bootstrap: %v", profile.Statements.Reasons, profile.Statements.RequiredBootstrap)
		}
		if profile.Configuration.DatabaseBytes <= 0 || len(profile.Configuration.Settings) == 0 || profile.DatabaseOID == 0 {
			t.Fatal("missing PostgreSQL configuration/storage evidence")
		}
		if len(profile.Activity) > profileActivityLimit || len(profile.Locks) > profileLockLimit || len(profile.TopQueries) > profileStatementLimit {
			t.Fatal("unbounded database sample")
		}
		var waiting, locked, identified bool
		for _, activity := range profile.Activity {
			if activity.PID == int32(foreignConn.PgConn().PID()) {
				t.Fatal("activity exposed another database")
			}
			if activity.PID == int32(waiter.PgConn().PID()) && activity.QueryName == "OwnedProfileWait" && activity.WaitEventType == "Lock" {
				for _, pid := range activity.BlockingPIDs {
					waiting = waiting || pid == int32(blocker.PgConn().PID())
				}
			}
		}
		for _, lock := range profile.Locks {
			if lock.PID == int32(foreignConn.PgConn().PID()) {
				t.Fatal("locks exposed another database")
			}
			locked = locked || (lock.PID == int32(waiter.PgConn().PID()) && !lock.Granted)
		}
		for _, query := range profile.TopQueries {
			if query.NormalizedSQL == "SELECT pg_advisory_lock ( $1 ) , pg_sleep ( $2 ) , $3 :: numeric" {
				t.Fatal("statement statistics exposed another database")
			}
			if query.StatementTextAvailable && query.NormalizedSQL == "SELECT $1 :: text || $2 , pg_sleep ( $3 )" && query.Calls == 3 && query.TotalExecutionMilliseconds > 0 && query.MeanExecutionMilliseconds > 0 && query.QueryID != "" {
				identified = true
			}
		}
		encoded, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "'profile-probe'") || strings.Contains(string(encoded), "-- name:") {
			t.Fatal("persistable evidence contains literal SQL, comments or parameter secrets")
		}
		if waiting && locked && identified {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("missing real database evidence: waiting=%t lock=%t identified=%t; top queries=%+v", waiting, locked, identified, profile.TopQueries)
		case <-tick.C:
		}
	}
}
