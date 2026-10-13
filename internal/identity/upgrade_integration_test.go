//go:build integration

package identity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/permissionupgrade"
	"lindm/internal/testdb"
)

// upgradeExpectation is expect.json beside each release's state.sql.
type upgradeExpectation struct {
	// Retired lists the permission names state.sql persists that this server retired.
	Retired []string `json:"retired"`
	// Persisted is the decoded runtime policy state.sql stores; Upgraded is what
	// the server must persist after starting on it.
	Persisted json.RawMessage `json:"persisted"`
	Upgraded  json.RawMessage `json:"upgraded"`
	// Audit holds the identity.authorization_upgraded details that name the rewrite.
	Audit struct {
		Renamed string `json:"renamed"`
		Lists   string `json:"lists"`
	} `json:"audit"`
	// Accounts are principals state.sql assigns; their grants after the upgrade.
	Accounts []struct {
		ID      uuid.UUID    `json:"id"`
		Granted []Permission `json:"granted"`
		Denied  []Permission `json:"denied"`
	} `json:"accounts"`
}

// Each testdata/upgrade/<release> directory holds the rows a deployment last
// served by that release persisted (state.sql) and what this server must make of
// them when it starts (expect.json). Retiring a permission name adds a release
// directory; existing directories stay so every earlier release keeps upgrading.
func TestUpgradeFromEarlierReleaseState(t *testing.T) {
	releases, err := os.ReadDir(filepath.Join("testdata", "upgrade"))
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, release := range releases {
		if !release.IsDir() {
			t.Fatalf("testdata/upgrade/%s is not a release directory", release.Name())
		}
		dir := filepath.Join("testdata", "upgrade", release.Name())
		var expect upgradeExpectation
		data, err := os.ReadFile(filepath.Join(dir, "expect.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &expect); err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, name := range expect.Retired {
			covered[name] = true
		}
		t.Run(release.Name(), func(t *testing.T) { exerciseReleaseUpgrade(t, dir, &expect) })
	}
	for _, rename := range permissionupgrade.Renames() {
		if !covered[rename.Legacy] {
			t.Errorf("no testdata/upgrade release persists retired permission %s", rename.Legacy)
		}
	}
}

func exerciseReleaseUpgrade(t *testing.T, dir string, expect *upgradeExpectation) {
	pool, conn := testdb.Open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	state, err := os.ReadFile(filepath.Join(dir, "state.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(state)); err != nil {
		t.Fatalf("load %s/state.sql: %v", dir, err)
	}
	persisted, upgraded := new(authv1.AuthorizationPolicy), new(authv1.AuthorizationPolicy)
	if err := protojson.Unmarshal(expect.Persisted, persisted); err != nil {
		t.Fatal(err)
	}
	if err := protojson.Unmarshal(expect.Upgraded, upgraded); err != nil {
		t.Fatal(err)
	}
	before := readUpgradePolicy(t, ctx, conn)
	if !proto.Equal(before.policy, persisted) {
		t.Fatal("state.sql does not store expect.json persisted")
	}
	versions := upgradeAuthorizationVersions(t, ctx, conn)

	s := startUpgradeService(t, ctx, pool)
	after := readUpgradePolicy(t, ctx, conn)
	if !proto.Equal(after.policy, upgraded) {
		t.Fatalf("persisted policy after upgrade = %v, want %v", after.policy, upgraded)
	}
	if after.revision != before.revision+1 || hex.EncodeToString(after.digest) != hex.EncodeToString(s.policy.digest) {
		t.Fatalf("upgrade revision %d -> %d or digest not the active policy", before.revision, after.revision)
	}
	var actor *uuid.UUID
	var reason string
	var details map[string]string
	if err := conn.QueryRow(ctx, "SELECT actor_id, reason, details FROM audit_events WHERE action = 'identity.authorization_upgraded'").Scan(&actor, &reason, &details); err != nil {
		t.Fatalf("one upgrade audit event: %v", err)
	}
	want := map[string]string{
		"previous_revision":      strconv.FormatInt(before.revision, 10),
		"revision":               strconv.FormatInt(after.revision, 10),
		"previous_policy_sha256": hex.EncodeToString(before.digest),
		"policy_sha256":          hex.EncodeToString(after.digest),
		"renamed":                expect.Audit.Renamed,
		"lists":                  expect.Audit.Lists,
	}
	if actor != nil || reason != reasonPermissionUpgrade || !maps.Equal(details, want) {
		t.Fatalf("upgrade audit actor=%v reason=%q details=%v, want %v", actor, reason, details, want)
	}
	for id, version := range upgradeAuthorizationVersions(t, ctx, conn) {
		if version <= versions[id] {
			t.Fatalf("principal %s kept authorization version %d across the upgrade", id, version)
		}
	}
	for _, account := range expect.Accounts {
		for _, permission := range account.Granted {
			if _, err := s.AuthorizeFresh(ctx, account.ID, permission); err != nil {
				t.Fatalf("%s lost %s: %v", account.ID, permission, err)
			}
		}
		for _, permission := range account.Denied {
			if _, err := s.AuthorizeFresh(ctx, account.ID, permission); !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatalf("%s gained %s: %v", account.ID, permission, err)
			}
		}
	}

	// A second start finds nothing retired: no rewrite, revision or audit.
	startUpgradeService(t, ctx, pool)
	again := readUpgradePolicy(t, ctx, conn)
	var events int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action = 'identity.authorization_upgraded'").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if again.revision != after.revision || !proto.Equal(again.policy, upgraded) || events != 1 {
		t.Fatalf("restart rewrote the upgraded policy: revision %d, %d audit events", again.revision, events)
	}
	// The policy API still rejects the retired names it was upgraded from.
	if _, err := compilePolicy(s.policyConfiguration(persisted), s.rules); err == nil {
		t.Fatal("policy validation accepted retired permission names as new input")
	}
}

type upgradePolicyRow struct {
	policy   *authv1.AuthorizationPolicy
	digest   []byte
	revision int64
}

func readUpgradePolicy(t *testing.T, ctx context.Context, conn *pgx.Conn) upgradePolicyRow {
	t.Helper()
	var row upgradePolicyRow
	var definition []byte
	if err := conn.QueryRow(ctx, "SELECT digest, definition, revision FROM authorization_policy").Scan(&row.digest, &definition, &row.revision); err != nil {
		t.Fatal(err)
	}
	row.policy = new(authv1.AuthorizationPolicy)
	if err := proto.Unmarshal(definition, row.policy); err != nil {
		t.Fatal(err)
	}
	return row
}

func upgradeAuthorizationVersions(t *testing.T, ctx context.Context, conn *pgx.Conn) map[uuid.UUID]int64 {
	t.Helper()
	rows, err := conn.Query(ctx, "SELECT id, authorization_version FROM principals")
	if err != nil {
		t.Fatal(err)
	}
	versions := map[uuid.UUID]int64{}
	var id uuid.UUID
	var version int64
	if _, err := pgx.ForEachRow(rows, []any{&id, &version}, func() error { versions[id] = version; return nil }); err != nil {
		t.Fatal(err)
	}
	return versions
}

func startUpgradeService(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *Service {
	t.Helper()
	s, err := New(ctx, pool, Config{Local: true, PublicURL: localTestOrigin, HTTPClient: &http.Client{Transport: rejectIdentityTransport{t}}})
	if err != nil {
		t.Fatalf("start on earlier release state: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}
