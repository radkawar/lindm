//go:build integration

package policy

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/testdb"
)

type profileFixture struct {
	pool  *pgxpool.Pool
	store *Store
	actor uuid.UUID
}

func newProfileFixture(t *testing.T) *profileFixture {
	t.Helper()
	pool, _ := testdb.Open(t)
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	actor := uuid.New()
	if _, err := pool.Exec(t.Context(), "INSERT INTO principals (id,issuer,subject) VALUES ($1,'https://profiles.example',$2)", actor, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	return &profileFixture{pool: pool, store: store, actor: actor}
}

func profileRequest() *adminv1.PublishProfileRevisionRequest {
	a, b, c := uuid.NewString(), uuid.NewString(), uuid.NewString()
	baseline := spec("Server baseline",
		resource(c, "worker.service", runtimeActive(), enablementEnabled(), []string{b, a}),
		resource(a, "network.service", runtimeActive(), enablementUnmanaged(), nil),
		resource(b, "database.service", runtimeActive(), enablementEnabled(), []string{a}),
	)
	group := groupResource(uuid.NewString(), "operators")
	group.Desired.GetLocalGroup().Gid = proto.Uint32(1500)
	group.Desired.GetLocalGroup().Members = &resourcev1.MemberSet{Mode: resourcev1.SetMode_SET_MODE_ADDITIVE, LocalUserNames: []string{"alice", "bob"}}
	baseline.Resources = append(baseline.Resources, group)
	baseline.Resources[0].DependsOn = append(baseline.Resources[0].DependsOn, &policyv1.ResourceDependency{
		Ref: proto.CloneOf(group.Desired.Ref), Condition: policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_PRESENT,
	})
	return &adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "publish resource baseline", Spec: baseline}
}

func (f *profileFixture) publish(ctx context.Context, request *adminv1.PublishProfileRevisionRequest) (*adminv1.ProfileRevision, error) {
	tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var actor uuid.UUID
	if err := tx.QueryRow(ctx, "SELECT id FROM principals WHERE id=$1 FOR UPDATE", f.actor).Scan(&actor); err != nil {
		return nil, err
	}
	revision, err := f.store.Publish(ctx, tx, request, actor)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return revision, nil
}

func TestProfilePublicationRetainsCanonicalHistoryAndRetry(t *testing.T) {
	f := newProfileFixture(t)
	request := profileRequest()
	original := proto.CloneOf(request)
	first, err := f.publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(request, original) {
		t.Fatal("publication mutated caller's profile")
	}
	profileID := uuid.MustParse(request.GetProfileId())
	firstID := uuid.MustParse(first.GetRevisionId())
	stored, err := f.store.Get(t.Context(), profileID, &firstID)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(stored, first) {
		t.Fatal("normalized relational history changed the accepted revision")
	}
	next := proto.CloneOf(request)
	next.RequestId = uuid.NewString()
	next.ExpectedRevisionId = proto.String(first.GetRevisionId())
	next.Spec.Name = "Revised baseline"
	second, err := f.publish(t.Context(), next)
	if err != nil {
		t.Fatal(err)
	}
	if second.GetRevisionNumber() != 2 || second.GetRevisionId() == first.GetRevisionId() {
		t.Fatal("publication did not create a distinct monotonic revision")
	}
	replay := proto.CloneOf(request)
	slices.Reverse(replay.Spec.Resources)
	for _, resource := range replay.Spec.Resources {
		slices.Reverse(resource.DependsOn)
		if group := resource.GetDesired().GetLocalGroup(); group != nil {
			slices.Reverse(group.Members.LocalUserNames)
		}
	}
	retried, err := f.publish(t.Context(), replay)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(retried, first) {
		t.Fatal("exact semantic retry rebound to a later revision")
	}
	head, err := f.store.Get(t.Context(), profileID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(head, second) {
		t.Fatal("historical retry rewound the catalog head")
	}
	changed := proto.CloneOf(request)
	changed.Spec.Name = "different request bytes"
	if _, err := f.publish(t.Context(), changed); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("changed request reuse: %v", err)
	}
	var audits, revisions, receipts int
	if err := f.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM audit_events WHERE action='profile.publish'), (SELECT count(*) FROM profile_revisions), (SELECT count(*) FROM profile_requests)").Scan(&audits, &revisions, &receipts); err != nil {
		t.Fatal(err)
	}
	if audits != 2 || revisions != 2 || receipts != 2 {
		t.Fatalf("retry/conflict mutated durable history: audit=%d revision=%d receipt=%d", audits, revisions, receipts)
	}
}

func TestProfileConcurrentHeadCompareAndSwap(t *testing.T) {
	f := newProfileFixture(t)
	initial := profileRequest()
	first, err := f.publish(t.Context(), initial)
	if err != nil {
		t.Fatal(err)
	}
	requests := []*adminv1.PublishProfileRevisionRequest{proto.CloneOf(initial), proto.CloneOf(initial)}
	for i, request := range requests {
		request.RequestId = uuid.NewString()
		request.ExpectedRevisionId = proto.String(first.GetRevisionId())
		request.Spec.Name = []string{"candidate one", "candidate two"}[i]
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*adminv1.ProfileRevision, 2)
	failures := make([]error, 2)
	for i := range requests {
		wg.Go(func() { <-start; results[i], failures[i] = f.publish(t.Context(), requests[i]) })
	}
	close(start)
	wg.Wait()
	var winner *adminv1.ProfileRevision
	conflicts := 0
	for i, err := range failures {
		if err == nil {
			if winner != nil {
				t.Fatal("two stale-head publications committed")
			}
			winner = results[i]
		} else if errors.Is(err, ErrProfileConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if winner == nil || conflicts != 1 {
		t.Fatalf("missing unique head winner: conflicts=%d", conflicts)
	}
	head, err := f.store.Get(t.Context(), uuid.MustParse(initial.GetProfileId()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(head, winner) || head.GetRevisionNumber() != 2 {
		t.Fatal("head differs from the only committed publication")
	}
	var revisions, receipts, audits int
	if err := f.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM profile_revisions),(SELECT count(*) FROM profile_requests),(SELECT count(*) FROM audit_events WHERE action='profile.publish')").Scan(&revisions, &receipts, &audits); err != nil {
		t.Fatal(err)
	}
	if revisions != 2 || receipts != 2 || audits != 2 {
		t.Fatal("losing publication left accepted evidence")
	}
}

func TestProfileRollbackAndCorruptHeadCannotPublish(t *testing.T) {
	f := newProfileFixture(t)
	request := profileRequest()
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := f.store.Publish(t.Context(), tx, request, f.actor); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	profileID := uuid.MustParse(request.GetProfileId())
	if _, err := f.store.Get(t.Context(), profileID, nil); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("rolled-back catalog became visible: %v", err)
	}
	first, err := f.publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE profile_resources SET resource_proto=resource_proto || decode('a00601','hex') WHERE revision_id=$1 AND canonical_key='worker.service'", uuid.MustParse(first.GetRevisionId())); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Get(t.Context(), profileID, nil); !errors.Is(err, ErrProfileCorrupt) {
		t.Fatalf("modified immutable resource accepted: %v", err)
	}
	next := proto.CloneOf(request)
	next.RequestId = uuid.NewString()
	next.ExpectedRevisionId = proto.String(first.GetRevisionId())
	if _, err := f.publish(t.Context(), next); !errors.Is(err, ErrProfileCorrupt) {
		t.Fatalf("corrupt head was extended: %v", err)
	}
	var revisions, receipts, audits int
	if err := f.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM profile_revisions),(SELECT count(*) FROM profile_requests),(SELECT count(*) FROM audit_events WHERE action='profile.publish')").Scan(&revisions, &receipts, &audits); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 || receipts != 1 || audits != 1 {
		t.Fatal("rollback or corrupt-head rejection left accepted evidence")
	}
}

func TestProfileRetainedRevisionLookupAndTypedIdentityCorruption(t *testing.T) {
	f := newProfileFixture(t)
	request := profileRequest()
	first, err := f.publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	retained, err := f.store.GetRevisionInTransaction(t.Context(), tx, uuid.MustParse(first.GetRevisionId()))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(retained, first) {
		t.Fatal("retained revision lookup changed typed resources")
	}
	if _, err := f.store.GetRevisionInTransaction(t.Context(), tx, uuid.New()); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("missing revision=%v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Change both valid typed content and its relational identity consistently:
	// the immutable digest, not only schema validity, must detect the mutation.
	for _, item := range first.Spec.Resources {
		if item.Desired.GetRef().GetKind() != resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP {
			continue
		}
		changed := proto.CloneOf(item)
		changed.DependsOn = nil
		changed.Desired.GetLocalGroup().Gid = proto.Uint32(1600)
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(t.Context(), "UPDATE profile_resources SET resource_proto=$1 WHERE revision_id=$2 AND resource_id=$3", encoded, uuid.MustParse(first.RevisionId), uuid.MustParse(item.ResourceId)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.Get(t.Context(), uuid.MustParse(request.ProfileId), nil); !errors.Is(err, ErrProfileCorrupt) {
		t.Fatalf("typed content tampering=%v", err)
	}
}
