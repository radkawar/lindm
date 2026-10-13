//go:build linux && integration

package vmlab

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"lindm/internal/devlab"
	"lindm/internal/testdb"
)

// The real account endpoint rejects reused usernames. Exercise the same account
// creation/retirement helpers as the scenario browser across controller and lane
// restarts, not just random-string generation or a mocked account API.
func TestPersistentAssistanceOperatorAccountsAcrossResume(t *testing.T) {
	binary, repository := os.Getenv("LINDM_NATIVE_SERVER_BINARY"), os.Getenv("LINDM_NATIVE_REPOSITORY")
	if binary == "" || repository == "" {
		t.Fatal("requires LINDM_NATIVE_SERVER_BINARY and LINDM_NATIVE_REPOSITORY; use go run ./cmd/devenv test-integration")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("", "pfx-operator-")
	if err != nil {
		t.Fatal(err)
	}
	state, laneState := filepath.Join(root, "controller"), filepath.Join(root, "lane")
	var fixture *devlab.AuthorityFixture
	var lane *devlab.AuthorityFixture
	defer func() {
		if lane != nil {
			if err := lane.Close(); err != nil {
				t.Errorf("lane close failed; private state retained at %s: %v", root, err)
				return
			}
		}
		if fixture != nil {
			if err := fixture.Close(); err != nil {
				t.Errorf("controller close failed; private state retained at %s: %v", root, err)
				return
			}
		}
		if err := devlab.DestroyPersistentAuthorityFixture(laneState); err != nil {
			t.Errorf("lane destroy failed; private state retained at %s: %v", root, err)
			return
		}
		// Destroy already bounds DROP to three minutes for checkpoint/storage
		// work. A shorter outer cleanup budget truncates that bound under load.
		if err := devlab.DestroyPersistentFixture(context.Background(), repository, state); err != nil {
			t.Errorf("controller destroy failed; private state retained at %s: %v", root, err)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	}()
	fixture, err = devlab.OpenPersistentFixture(ctx, repository, binary, state, devlab.LoadAuthorityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.ConfigureDeviceActions(ctx); err != nil {
		t.Fatal(err)
	}
	human, err := fixture.CreateConsoleEnrollment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	human.Secret = ""
	humanID, database := human.GetAccountId(), fixture.DatabaseName
	openLane := func() *devlab.AuthorityFixture {
		t.Helper()
		handle, err := fixture.ExportControlPlane(ctx, "assistance-lane-regression")
		if err != nil {
			t.Fatal(err)
		}
		connected, err := devlab.ConnectPersistentAuthorityFixture(ctx, handle, laneState)
		if err != nil {
			t.Fatal(err)
		}
		return connected
	}
	lane = openLane()
	pool, _ := testdb.Open(t)
	// Config returns an independent copy. The testdb pool remains connected to
	// the shared database; only this separately closed observer uses the fixture.
	config := pool.Config().ConnConfig.Copy()
	config.Database = database
	config.RuntimeParams["search_path"] = "public"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := connection.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	type account struct {
		username string
		enabled  bool
	}
	readAccounts := func() map[string]account {
		t.Helper()
		rows, err := connection.Query(ctx, "SELECT id::text, username, enabled FROM local_accounts")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		accounts := make(map[string]account)
		for rows.Next() {
			var id string
			var item account
			if err := rows.Scan(&id, &item.username, &item.enabled); err != nil {
				t.Fatal(err)
			}
			accounts[id] = item
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return accounts
	}
	protected := readAccounts()
	if humanAccount, ok := protected[humanID]; !ok || humanAccount.username != "console-owner" || !humanAccount.enabled {
		t.Fatal("human owner was not created independently")
	}
	var firstID, firstUsername string
	for round := range 2 {
		username, enrollment, err := createAssistanceOperator(ctx, lane, true, assistanceOperator, "owner")
		if err != nil {
			t.Fatal(err)
		}
		enrollment.Secret = ""
		operatorID := enrollment.GetAccountId()
		if round == 0 {
			firstID, firstUsername = operatorID, username
		} else if operatorID == firstID || username == firstUsername {
			t.Fatal("resumed scenario reused its earlier account identity or username")
		}
		accounts := readAccounts()
		if got := accounts[operatorID]; got.username != username || !got.enabled {
			t.Fatal("scenario helper did not create a real enabled account")
		}
		if _, ok := protected[operatorID]; ok {
			t.Fatal("scenario borrowed a human or lane account")
		}
		// Failed/canceled scenarios must retire their account too; cleanup is
		// deliberately detached from the scenario cancellation but bounded.
		canceled, stop := context.WithCancel(ctx)
		stop()
		if err := retireAssistanceOperator(canceled, lane, operatorID); err != nil {
			t.Fatal(err)
		}
		accounts = readAccounts()
		if accounts[operatorID].enabled || accounts[firstID].enabled {
			t.Fatal("scenario cleanup left a browser operator enabled")
		}
		if len(accounts) != len(protected)+round+1 {
			t.Fatal("scenario lifecycle changed unrelated account cardinality")
		}
		for id, want := range protected {
			if got, ok := accounts[id]; !ok || got != want {
				t.Fatalf("scenario lifecycle changed protected account %s", want.username)
			}
		}
		if round == 0 {
			if err := lane.Close(); err != nil {
				t.Fatal(err)
			}
			if err := fixture.Close(); err != nil {
				t.Fatal(err)
			}
			resumed, err := devlab.OpenPersistentFixture(ctx, repository, binary, state, devlab.LoadAuthorityOptions{})
			if err != nil {
				t.Fatal(err)
			}
			fixture = resumed
			if !fixture.Resumed || fixture.DatabaseName != database {
				t.Fatal("fixture did not reopen its named database")
			}
			lane = openLane()
		}
	}
}
