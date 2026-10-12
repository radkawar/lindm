//go:build integration

package targeting

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/testdb"
)

// Groups and rollouts saved before the targeting names migration become
// searchable by the names in their stored definitions, including multi-byte
// names whose length takes two varint bytes and fields stored after the name.
func TestMigrationBackfillsTargetingNames(t *testing.T) {
	pool, _ := testdb.Open(t)
	sqlDB := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = sqlDB.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("../../db/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	var version int64
	for _, source := range provider.ListSources() {
		if strings.HasSuffix(source.Path, "_targeting_names.sql") {
			version = source.Version
		}
	}
	if version == 0 {
		t.Fatal("targeting names migration not found")
	}
	if _, err := provider.DownTo(t.Context(), version-1); err != nil {
		t.Fatal(err)
	}

	actor := uuid.New()
	if _, err := pool.Exec(t.Context(), "INSERT INTO principals(id,issuer,subject) VALUES ($1,'https://targeting.example',$2)", actor, actor.String()); err != nil {
		t.Fatal(err)
	}
	groupName := strings.Repeat("é", 70) + " Fedora"
	group := &adminv1.DynamicTargetGroup{GroupId: uuid.NewString(), Name: groupName, Revision: 3, Expression: &adminv1.TargetExpression{InventoryMaxAgeSeconds: 60, Nodes: []*adminv1.TargetNode{{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: &adminv1.DeviceFilter{OsId: "fedora"}}}}}}
	ring := func(name string) *policyv1.RolloutRing {
		return &policyv1.RolloutRing{Name: name, Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: uuid.NewString()}}, CumulativeBasisPoints: 5000, MinimumCanaries: 300, MinimumObserved: 1, SoakSeconds: 2592000, FailureBasisPoints: 1, HealthMaxAgeSeconds: 86400, ManualPromotion: true}
	}
	rollout := &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: []byte(strings.Repeat("s", 32)), Rings: []*policyv1.RolloutRing{ring("canary"), ring("wave.2"), ring("broad_all")}}
	encode := proto.MarshalOptions{Deterministic: true}
	groupBytes, err := encode.Marshal(group)
	if err != nil {
		t.Fatal(err)
	}
	rolloutBytes, err := encode.Marshal(rollout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "INSERT INTO dynamic_target_groups(id,revision,definition) VALUES ($1,3,$2)", uuid.MustParse(group.GroupId), groupBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "INSERT INTO resource_rollouts(id,creator_id,definition) VALUES ($1,$2,$3)", uuid.MustParse(rollout.RolloutId), actor, rolloutBytes); err != nil {
		t.Fatal(err)
	}

	if _, err := provider.UpTo(t.Context(), version); err != nil {
		t.Fatal(err)
	}
	var gotGroup, gotRollout string
	if err := pool.QueryRow(t.Context(), "SELECT name FROM dynamic_target_groups WHERE id=$1", uuid.MustParse(group.GroupId)).Scan(&gotGroup); err != nil {
		t.Fatal(err)
	}
	if gotGroup != groupName {
		t.Fatalf("backfilled group name = %q", gotGroup)
	}
	if err := pool.QueryRow(t.Context(), "SELECT name FROM resource_rollouts WHERE id=$1", uuid.MustParse(rollout.RolloutId)).Scan(&gotRollout); err != nil {
		t.Fatal(err)
	}
	if want := rolloutName(rollout); gotRollout != want || want != "canary, wave.2, broad_all" {
		t.Fatalf("backfilled rollout name = %q, store would write %q", gotRollout, want)
	}
	if _, err := provider.UpTo(t.Context(), 1<<62); err != nil {
		t.Fatal(err)
	}
}
