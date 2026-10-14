// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package devlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"lindm/internal/testdb"
)

func TestPersistentDestroyReportsRemainingSessions(t *testing.T) {
	binary, repository := nativeServer(t)
	pool, _ := testdb.Open(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("", "pfx-destroy-")
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "controller")
	var fixture *AuthorityFixture
	defer func() {
		if fixture != nil {
			if err := fixture.Close(); err != nil {
				t.Error(err)
			}
		}
		if err := DestroyPersistentFixture(context.Background(), repository, state); err != nil {
			t.Errorf("destroy failed; private state retained at %s: %v", state, err)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	}()
	fixture, err = OpenPersistentFixture(ctx, repository, binary, state, LoadAuthorityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	// Retaining the independent testdb pool must not retain a fixture client.
	// TCP termination can be processed after the child exits, so observe it
	// with a deadline rather than assuming immediate pg_stat_activity removal.
	closed, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	for {
		var clients int
		if err := pool.QueryRow(closed, "SELECT count(*) FROM pg_stat_activity WHERE datname=$1", fixture.DatabaseName).Scan(&clients); err != nil {
			t.Fatal(err)
		}
		if clients == 0 {
			break
		}
		select {
		case <-closed.Done():
			t.Fatalf("fixture.Close retained %d database clients: %v", clients, closed.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Log("fixture.Close released all target database clients while the shared testdb pool remained open")
	for _, kind := range []string{"client", "database-lock"} {
		t.Run(kind, func(t *testing.T) {
			configuration := fixture.database.admin.Copy()
			application := "persistent-destroy-regression-" + kind
			configuration.RuntimeParams["application_name"] = application
			if kind == "client" {
				configuration.Database = fixture.DatabaseName
			}
			blocker, err := pgx.ConnectConfig(ctx, configuration)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := blocker.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			if kind == "database-lock" {
				// An uncommitted rename holds the database-object lock from
				// postgres; no target-database client exists. Closing this
				// connection rolls back the rename before final destruction.
				if _, err := blocker.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				if _, err := blocker.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{fixture.DatabaseName}.Sanitize()+" RENAME TO "+pgx.Identifier{fixture.DatabaseName + "_locked"}.Sanitize()); err != nil {
					t.Fatal(err)
				}
			}
			deadline, stop := context.WithTimeout(ctx, 2*time.Second)
			err = DestroyPersistentFixture(deadline, repository, state)
			stop()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("destroy with retained blocker = %v, want deadline", err)
			}
			for _, want := range []string{fmt.Sprintf("%s pid=%d", kind, blocker.PgConn().PID()), fmt.Sprintf("application=%q", application)} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("destroy diagnostic missing %s: %v", want, err)
				}
			}
			if _, err := os.Stat(state); err != nil {
				t.Fatalf("failed destroy discarded persistent state: %v", err)
			}
			if err := blocker.Ping(ctx); err != nil {
				t.Fatalf("destroy terminated the retained connection: %v", err)
			}
			t.Logf("bounded destroy retained state and live blocker: %v", err)
			// Routine teardown passes no short deadline, so the drop's storage
			// budget must not hold a blocked drop: a lock holder fails it through
			// the lock budget (55P03), a target client through PostgreSQL's own
			// five-second check (55006). Neither is terminated.
			code := map[string]string{"client": "55006", "database-lock": "55P03"}[kind]
			owned := &authorityDatabase{name: fixture.DatabaseName, admin: fixture.database.admin.Copy(), created: true}
			err = owned.drop(t.Context(), true, time.Second)
			var refused *pgconn.PgError
			if !errors.As(err, &refused) || refused.Code != code || !strings.Contains(err.Error(), fmt.Sprintf("%s pid=%d", kind, blocker.PgConn().PID())) {
				t.Fatalf("drop without caller deadline and retained %s = %v, want SQLSTATE %s naming the blocker", kind, err, code)
			}
			if err := blocker.Ping(ctx); err != nil {
				t.Fatalf("lock-bounded drop terminated the retained connection: %v", err)
			}
			t.Logf("drop without caller deadline refused the live blocker: %v", err)
		})
	}
	// The final drop waits for cluster-wide checkpoints under its own budget;
	// the five-minute setup deadline above must not truncate it under load.
	if err := DestroyPersistentFixture(t.Context(), repository, state); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := pool.QueryRow(t.Context(), "SELECT EXISTS (SELECT FROM pg_database WHERE datname=$1)", fixture.DatabaseName).Scan(&exists); err != nil || exists {
		t.Fatalf("retry retained owned database: exists=%t err=%v", exists, err)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry retained persistent state: %v", err)
	}
	t.Logf("retry after blockers closed removed database %s and persistent state", fixture.DatabaseName)
}
