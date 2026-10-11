//go:build integration

package advisory

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/testdb"
)

// Identical package sets under one feed generation share one matched set, so
// findings are stored once; different content gets its own set, exceptions stay
// per-device overlays, and summaries weight shared sets by bound devices.
func TestIdenticalPackageSetsShareOneFindingSet(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx := t.Context()
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(ctx, source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	vulnerable := &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"}
	fixed := &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-10.p2.fc44", Architecture: "x86_64", Manager: "rpm"}
	first := seedInventory(t, pool, "fedora", "44", vulnerable)
	second := seedInventory(t, pool, "fedora", "44", vulnerable)
	clear := seedInventory(t, pool, "fedora", "44", fixed)
	list := func(device uuid.UUID) *adminv1.ListDeviceFindingsResponse {
		t.Helper()
		response, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: device.String()}, true, []byte("[]"))
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	firstFindings, secondFindings := list(first), list(second)
	if len(firstFindings.GetFindings()) != 1 || len(secondFindings.GetFindings()) != 1 || firstFindings.Findings[0].GetId() != secondFindings.Findings[0].GetId() {
		t.Fatalf("identical devices did not report the same set finding: %v / %v", firstFindings, secondFindings)
	}
	if clearFindings := list(clear); len(clearFindings.GetFindings()) != 0 || clearFindings.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR {
		t.Fatalf("fixed device not clear: %v", clearFindings)
	}
	var sets, rows, sharedDevices int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_finding_sets").Scan(&sets); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_set_findings").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_evaluations WHERE finding_set_id=(SELECT finding_set_id FROM advisory_evaluations WHERE device_id=$1)", first).Scan(&sharedDevices); err != nil {
		t.Fatal(err)
	}
	if sets != 2 || rows != 1 || sharedDevices != 2 {
		t.Fatalf("finding storage not shared by content: sets=%d rows=%d sharedDevices=%d", sets, rows, sharedDevices)
	}
	// Migration 00019's SQL key reproduces the Go finding key.
	f := firstFindings.Findings[0]
	var sqlKey uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT encode(substring(sha256(convert_to($1::text,'UTF8')||'\x00'::bytea||convert_to($2::text,'UTF8')||'\x00'::bytea||
convert_to($3::text,'UTF8')||'\x00'::bytea||convert_to($4::text,'UTF8')||'\x00'::bytea||convert_to($5::text,'UTF8')) FROM 1 FOR 16),'hex')::uuid`,
		source.GetId(), f.GetAdvisoryId(), f.GetPackageName(), f.GetInstalledVersion(), f.GetArchitecture()).Scan(&sqlKey); err != nil {
		t.Fatal(err)
	}
	if sqlKey.String() != f.GetId() {
		t.Fatalf("finding key not reproducible in SQL: sql=%s api=%s", sqlKey, f.GetId())
	}
	actor := uuid.New()
	mustExec(t, ctx, pool, "INSERT INTO principals(id,issuer,subject) VALUES($1,'https://advisory.test',$2)", actor, uuid.NewString())
	acceptFinding(t, s, actor, &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: first.String(), FindingId: f.GetId(), Reason: "Accepted on one device only", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))})
	if list(first).Findings[0].GetException() == nil || list(second).Findings[0].GetException() != nil {
		t.Fatal("exception leaked across devices sharing a finding set")
	}
	summary, err := s.Summary(ctx, &adminv1.ListAdvisorySummaryRequest{}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.GetAdvisories()) != 1 || summary.Advisories[0].GetAffectedDevices() != 1 || summary.Advisories[0].GetAcceptedDevices() != 1 || summary.Advisories[0].GetUnknownDevices() != 0 || summary.GetEvaluatedDevices() != 3 {
		t.Fatalf("set-weighted summary wrong: %v", summary)
	}
	// A new snapshot with identical content binds the existing set without
	// matching again; the old set is unreferenced only when nobody binds it.
	again := seedInventory(t, pool, "fedora", "44", vulnerable)
	if len(list(again).GetFindings()) != 1 {
		t.Fatal("identical new device lost shared findings")
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_finding_sets").Scan(&sets); err != nil || sets != 2 {
		t.Fatalf("identical content created another set: %d %v", sets, err)
	}
	mustExec(t, ctx, pool, "UPDATE advisory_finding_sets SET created_at=clock_timestamp()-interval '1 hour'")
	mustExec(t, ctx, pool, "DELETE FROM advisory_evaluations WHERE device_id=$1", clear)
	if pruned, err := advisorydb.New(pool).PruneAdvisoryFindingSets(ctx, findingSetPruneBatch); err != nil || pruned != 1 {
		t.Fatalf("unbound set not pruned exactly: %d %v", pruned, err)
	}
}

// A cold fleet of identical devices evaluated concurrently builds the missing
// set once, outside device transactions, and every device binds it.
func TestConcurrentColdEvaluationBuildsOneSet(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx := t.Context()
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(ctx, source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	vulnerable := &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"}
	devices := make([]uuid.UUID, 3*evaluationWorkers)
	for i := range devices {
		devices[i] = seedInventory(t, pool, "fedora", "44", vulnerable)
	}
	attempted, failures, err := s.evaluatePending(ctx, int32(len(devices)))
	if err != nil || failures != 0 || attempted != len(devices) {
		t.Fatalf("cold concurrent evaluation: attempted=%d failures=%d err=%v", attempted, failures, err)
	}
	var sets, bound int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_finding_sets").Scan(&sets); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_evaluations WHERE state='evaluated' AND finding_set_id IS NOT NULL").Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if sets != 1 || bound != len(devices) {
		t.Fatalf("sets=%d bound=%d want 1/%d", sets, bound, len(devices))
	}
}

// A device whose row is being updated is skipped without a serialization
// failure and evaluated once the updater commits.
func TestEvaluatorSkipsBusyDevice(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx := t.Context()
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(ctx, source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	device := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	updater, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updater.Exec(ctx, "UPDATE devices SET last_seen_at=now() WHERE id=$1", device); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Evaluate(ctx, device); !errors.Is(err, ErrDeviceBusy) {
		t.Fatalf("busy device: %v", err)
	}
	if attempted, failures, err := s.evaluatePending(ctx, evaluationBatch); err != nil || attempted != 1 || failures != 1 {
		t.Fatalf("all-busy batch must be deferred without errors: attempted=%d failures=%d err=%v", attempted, failures, err)
	}
	if err := updater.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if evaluation, err := s.Evaluate(ctx, device); err != nil || evaluation.State != "evaluated" {
		t.Fatalf("released device not evaluated: %+v %v", evaluation, err)
	}
}
