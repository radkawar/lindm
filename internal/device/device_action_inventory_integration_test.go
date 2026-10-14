// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
)

func TestRefreshAdmissionSurvivesPostgrantRoutineBacklog(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, staging := range []bool{false, true} {
		name := "failed-attempt"
		if staging {
			name = "staging-snapshot"
		}
		t.Run(name, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			committedID := f.publishPackages(t, 1, "committed-history")
			action := f.create(t, f.request(refreshActionSpec()))
			start, challenge := f.startRequest(t, f.work(t))
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
				t.Fatal(err)
			}
			oldAt := challenge.GetIssuedAt().AsTime().Add(-time.Second)
			oldHost := hostObservation(f.generation, 2, "queued-routine-host")
			oldHost.Observation.StartedAt = timestamppb.New(oldAt)
			oldHost.Observation.FinishedAt = timestamppb.New(oldAt)
			ageInventoryAdmissions(t, f)
			if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(oldHost)); err != nil {
				t.Fatal(err)
			}
			raw := packageBatch(t, &inventoryv1.Package{Name: "queued-routine-package", Version: "1", Architecture: "amd64", Manager: "apt"})
			old := snapshotManifest(t, f.generation, 2, oldAt, [][]byte{raw})
			var oldReceipt *devicev1.BeginPackageSnapshotResponse
			if staging {
				var err error
				oldReceipt, err = f.begin(t, old, 1)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.put(t, old.GetSnapshotId(), 0, raw, 1); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.svc.ReportPackageAttempt(f.deviceCtx(), connect.NewRequest(refreshFailedAttempt(f, 2, oldAt))); err != nil {
				t.Fatal(err)
			}
			assertRefreshAdmissionSlots(t, f, action.GetActionId(), 0, 0)
			if _, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(&devicev1.ConfirmRefreshInventoryPublicationRequest{SessionEpoch: 1, ActionId: action.GetActionId()})); connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "inventory_refresh_not_published" {
				t.Fatalf("routine backlog borrowed action publication: %v", err)
			}
			queued := proto.CloneOf(oldHost)
			queued.Sequence = 3
			if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(queued)); rpcReason(err) != "rate_limited" {
				t.Fatalf("old host borrowed unused refresh slot: %v", err)
			}
			if _, err := f.begin(t, snapshotManifest(t, f.generation, 3, oldAt, nil), 1); rpcReason(err) != "rate_limited" {
				t.Fatalf("old package borrowed unused refresh slot: %v", err)
			}
			if _, err := f.svc.ReportPackageAttempt(f.deviceCtx(), connect.NewRequest(refreshFailedAttempt(f, 3, time.Now().UTC()))); rpcReason(err) != "rate_limited" {
				t.Fatalf("failed collection borrowed full-inventory slot: %v", err)
			}
			freshHost := hostObservation(f.generation, 4, "explicit-refresh-host")
			for range 2 {
				if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(freshHost)); err != nil {
					t.Fatalf("fresh host/exact replay blocked by routine backlog: %v", err)
				}
			}
			fresh := snapshotManifest(t, f.generation, 4, time.Now().UTC(), nil)
			for range 2 {
				if _, err := f.begin(t, fresh, 1); err != nil {
					t.Fatalf("fresh package/exact replay blocked by routine backlog: %v", err)
				}
			}
			assertRefreshAdmissionSlots(t, f, action.GetActionId(), 4, 4)
			assertRefreshReservations(t, f)
			q := devicedb.New(f.svc.Pool)
			history, err := q.GetPackageSnapshot(t.Context(), uuid.MustParse(committedID))
			if err != nil || history.State != "committed" || !history.BulkRetained {
				t.Fatalf("begin discarded committed inventory history: %+v %v", history, err)
			}
			if staging {
				row, err := q.GetPackageSnapshot(t.Context(), uuid.MustParse(old.GetSnapshotId()))
				if err != nil || row.State != "superseded" || row.BulkRetained || row.ReservedBytes != row.MetadataBytes || row.CommittedAt.Valid {
					t.Fatalf("old staging did not release bulk and retain receipt: %+v %v", row, err)
				}
				var packages, batches int
				if err := f.svc.Pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM snapshot_packages WHERE snapshot_id=$1), (SELECT count(*) FROM snapshot_batches WHERE snapshot_id=$1)", old.GetSnapshotId()).Scan(&packages, &batches); err != nil || packages != 0 || batches != 1 {
					t.Fatalf("staging cleanup lost receipt or retained bulk: packages=%d batches=%d %v", packages, batches, err)
				}
				replayed, err := f.begin(t, old, 1)
				if err != nil || replayed.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_SUPERSEDED || !proto.Equal(replayed.GetAcceptedAt(), oldReceipt.GetAcceptedAt()) || !proto.Equal(replayed.GetReceiptExpiresAt(), oldReceipt.GetReceiptExpiresAt()) {
					t.Fatalf("superseded begin changed immutable receipt: %+v %v", replayed, err)
				}
				if _, err := f.put(t, old.GetSnapshotId(), 0, raw, 1); err != nil {
					t.Fatalf("superseded batch receipt rejected exact retry: %v", err)
				}
				if response, err := f.commit(t, old, 1); err != nil || response.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_SUPERSEDED || response.GetPublishedSequence() != 1 {
					t.Fatalf("superseded commit republished old staging: %+v %v", response, err)
				}
			}
			if _, err := f.commit(t, fresh, 1); err != nil {
				t.Fatal(err)
			}
			confirmation := &devicev1.ConfirmRefreshInventoryPublicationRequest{SessionEpoch: 1, ActionId: action.GetActionId()}
			confirmed, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(confirmation))
			if err != nil {
				t.Fatalf("fresh full refresh failed publication: %v", err)
			}
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 5, "excess-host"))); rpcReason(err) != "rate_limited" {
				t.Fatalf("grant replay replenished host allowance: %v", err)
			}
			if _, err := f.begin(t, snapshotManifest(t, f.generation, 5, time.Now().UTC(), nil), 1); rpcReason(err) != "rate_limited" {
				t.Fatalf("grant replay replenished package allowance: %v", err)
			}
			replayed, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(confirmation))
			if err != nil || !bytes.Equal(replayed.Msg.GetReceiptEnvelope(), confirmed.Msg.GetReceiptEnvelope()) {
				t.Fatalf("receipt replay changed binding: %v", err)
			}
			assertRefreshAdmissionSlots(t, f, action.GetActionId(), 4, 4)
			assertRefreshReservations(t, f)
		})
	}
}

func TestRefreshRoutineAllowedFreshAdmissionStillBindsSlots(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	f.create(t, f.request(refreshActionSpec()))
	start, _ := f.startRequest(t, f.work(t))
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	ageInventoryAdmissions(t, f)
	host := hostObservation(f.generation, 2, "fresh-routine-interval")
	manifest := snapshotManifest(t, f.generation, 1, time.Now().UTC(), nil)
	for range 2 {
		if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(host)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.begin(t, manifest, 1); err != nil {
			t.Fatal(err)
		}
	}
	assertRefreshAdmissionSlots(t, f, start.GetActionId(), 2, 1)
	changed := proto.CloneOf(host)
	changed.Observation.Hostname.Value = "different-same-sequence"
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(changed)); rpcReason(err) != "inventory_conflict" {
		t.Fatalf("changed same-sequence host retry admitted: %v", err)
	}
	changedManifest := proto.CloneOf(manifest)
	changedManifest.Backend = "rpm"
	if _, err := f.begin(t, changedManifest, 1); rpcReason(err) != "inventory_conflict" {
		t.Fatalf("changed same-snapshot retry admitted: %v", err)
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 3, "extra"))); rpcReason(err) != "rate_limited" {
		t.Fatalf("routine admission left host allowance unbound: %v", err)
	}
	if _, err := f.begin(t, snapshotManifest(t, f.generation, 2, time.Now().UTC(), nil), 1); rpcReason(err) != "rate_limited" {
		t.Fatalf("routine admission left package allowance unbound: %v", err)
	}
	ageInventoryAdmissions(t, f)
	if _, err := f.begin(t, snapshotManifest(t, f.generation, 2, time.Now().UTC(), nil), 1); rpcReason(err) != "open_upload" {
		t.Fatalf("same-action staging was replaced after routine interval: %v", err)
	}
	assertRefreshAdmissionSlots(t, f, start.GetActionId(), 2, 1)
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(&devicev1.ConfirmRefreshInventoryPublicationRequest{SessionEpoch: 1, ActionId: start.GetActionId()})); err != nil {
		t.Fatalf("normally admitted fresh collection could not confirm: %v", err)
	}
}

func TestRefreshRejectedAdmissionCannotSupersedeStaging(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, mode := range []string{"ungranted", "closed", "fenced", "stale", "generation", "quota"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			action := f.create(t, f.request(refreshActionSpec()))
			start, challenge := f.startRequest(t, f.work(t))
			oldAt := challenge.GetIssuedAt().AsTime().Add(-time.Second)
			raw := packageBatch(t, &inventoryv1.Package{Name: "retained-staging", Version: "1", Architecture: "amd64", Manager: "apt"})
			old := snapshotManifest(t, f.generation, 1, oldAt, [][]byte{raw})
			if _, err := f.begin(t, old, 1); err != nil {
				t.Fatal(err)
			}
			if _, err := f.put(t, old.GetSnapshotId(), 0, raw, 1); err != nil {
				t.Fatal(err)
			}
			if mode != "ungranted" {
				if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "closed" {
				if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE device_actions SET closed_at=clock_timestamp(), closed_reason='test_closed' WHERE id=$1", action.GetActionId()); err != nil {
					t.Fatal(err)
				}
			}
			q := devicedb.New(f.svc.Pool)
			before, err := q.GetPackageSnapshot(t.Context(), uuid.MustParse(old.GetSnapshotId()))
			if err != nil {
				t.Fatal(err)
			}
			budget := f.svc.InventoryBudget
			if mode == "quota" {
				// Retaining the old receipt alone fills the budget: even after
				// tentative bulk release, fresh admission must roll everything back.
				f.svc.InventoryBudget = before.MetadataBytes
			}
			fresh := snapshotManifest(t, f.generation, 2, time.Now().UTC(), nil)
			epoch := uint64(1)
			expected := "rate_limited"
			switch mode {
			case "fenced":
				epoch = 2
				expected = "session_fenced"
			case "stale":
				fresh.StartedAt = timestamppb.New(oldAt)
			case "generation":
				fresh.EnrollmentGeneration = uuid.NewString()
				expected = "generation_mismatch"
			case "quota":
				expected = "inventory_budget"
			}
			if _, err := f.begin(t, fresh, epoch); rpcReason(err) != expected {
				t.Fatalf("rejected %s admission: got %v, want %s", mode, err, expected)
			}
			f.svc.InventoryBudget = budget
			assertRefreshAdmissionSlots(t, f, action.GetActionId(), 0, 0)
			after, err := q.GetPackageSnapshot(t.Context(), uuid.MustParse(old.GetSnapshotId()))
			if err != nil || after.State != "staging" || !after.BulkRetained || after.ReservedBytes != before.ReservedBytes || after.SupersededAt.Valid {
				t.Fatalf("failed admission mutated old staging: %+v %v", after, err)
			}
			var sequence int64
			var open uuid.UUID
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT g.package_sequence, d.open_snapshot_id FROM enrollment_generations g JOIN devices d ON d.id=g.device_id WHERE g.id=$1", f.principal.GenerationID).Scan(&sequence, &open); err != nil || sequence != 1 || open.String() != old.GetSnapshotId() {
				t.Fatalf("failed admission changed sequence/open upload: %d %s %v", sequence, open, err)
			}
			var packages int
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM snapshot_packages WHERE snapshot_id=$1", old.GetSnapshotId()).Scan(&packages); err != nil || packages != 1 {
				t.Fatalf("failed admission discarded staging packages: %d %v", packages, err)
			}
			assertRefreshReservations(t, f)
			if mode == "quota" {
				if _, err := f.begin(t, fresh, 1); err != nil {
					t.Fatalf("failed quota admission consumed grant or sequence: %v", err)
				}
				assertRefreshAdmissionSlots(t, f, action.GetActionId(), 0, 2)
				assertRefreshReservations(t, f)
			}
		})
	}
}

func TestRefreshStagingSupersessionReusesDeviceAndGlobalQuota(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	f.svc.InventoryBudget = inventory.MaxDeviceInventoryBytes
	oldAt := time.Now().UTC().Add(-10 * time.Second)
	// Three superseded receipts still retain bulk under the ordinary retention
	// policy. The fourth staging upload brings both budgets close to capacity.
	for sequence := uint64(1); sequence <= 7; sequence += 2 {
		ageInventoryAdmissions(t, f)
		if _, err := f.begin(t, declaredManifest(t, f.generation, sequence, oldAt, 80, core.MaxBatchBytes), 1); err != nil {
			t.Fatal(err)
		}
		if sequence < 7 {
			ageInventoryAdmissions(t, f)
			if _, err := f.svc.ReportPackageAttempt(f.deviceCtx(), connect.NewRequest(refreshFailedAttempt(f, sequence+1, oldAt))); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.create(t, f.request(refreshActionSpec()))
	start, _ := f.startRequest(t, f.work(t))
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	fresh := declaredManifest(t, f.generation, 8, time.Now().UTC(), 80, core.MaxBatchBytes)
	if _, err := f.begin(t, fresh, 1); err != nil {
		t.Fatalf("refresh could not reuse obsolete staging reservation: %v", err)
	}
	assertRefreshAdmissionSlots(t, f, start.GetActionId(), 0, 8)
	assertRefreshReservations(t, f)
	var retained int
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM package_snapshots WHERE generation_id=$1 AND sequence < 7 AND bulk_retained", f.principal.GenerationID).Scan(&retained); err != nil || retained != 3 {
		t.Fatalf("refresh reclaimed unrelated retained history: %d %v", retained, err)
	}
}

func TestRefreshSupersedesPregrantStagingAcrossCollectorClockWindow(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	f.create(t, f.request(refreshActionSpec()))
	start, challenge := f.startRequest(t, f.work(t))
	// The collector timestamp lies after preflight, but the server admitted the
	// routine upload before issuing this grant. It cannot own the action slot.
	old := snapshotManifest(t, f.generation, 1, challenge.GetIssuedAt().AsTime().Add(time.Millisecond), nil)
	if _, err := f.begin(t, old, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	fresh := snapshotManifest(t, f.generation, 2, time.Now().UTC(), nil)
	if _, err := f.begin(t, fresh, 1); err != nil {
		t.Fatalf("pregrant staging blocked fresh action through clock overlap: %v", err)
	}
	assertRefreshAdmissionSlots(t, f, start.GetActionId(), 0, 2)
	row, err := devicedb.New(f.svc.Pool).GetPackageSnapshot(t.Context(), uuid.MustParse(old.GetSnapshotId()))
	if err != nil || row.State != "superseded" || row.CommittedAt.Valid || row.BulkRetained {
		t.Fatalf("pregrant staging was not safely closed: %+v %v", row, err)
	}
	assertRefreshReservations(t, f)
}

func TestRefreshPublicationRecoversBoundInventoryAfterRoutineOverwrite(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	f.create(t, f.request(refreshActionSpec()))
	start, _ := f.startRequest(t, f.work(t))
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	request := &devicev1.ConfirmRefreshInventoryPublicationRequest{SessionEpoch: 1, ActionId: start.GetActionId()}
	notPublished := func() {
		t.Helper()
		if _, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "inventory_refresh_not_published" {
			t.Fatalf("incomplete action publication was not retryable: %v", err)
		}
	}
	notPublished()
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 2, "bound-host"))); err != nil {
		t.Fatal(err)
	}
	notPublished()
	bound := snapshotManifest(t, f.generation, 1, time.Now().UTC(), nil)
	if _, err := f.begin(t, bound, 1); err != nil {
		t.Fatal(err)
	}
	notPublished()
	if _, err := f.commit(t, bound, 1); err != nil {
		t.Fatal(err)
	}
	snapshot, err := devicedb.New(f.svc.Pool).GetPackageSnapshot(t.Context(), uuid.MustParse(bound.GetSnapshotId()))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate losing COMMIT's response and all local publication identifiers.
	// A later routine upload overwrites the latest host and current snapshot
	// before the network process can ask for its first signed receipt.
	ageInventoryAdmissions(t, f)
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 3, "later-routine-host"))); err != nil {
		t.Fatal(err)
	}
	later := snapshotManifest(t, f.generation, 2, time.Now().UTC(), nil)
	if _, err := f.begin(t, later, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, later, 1); err != nil {
		t.Fatal(err)
	}
	confirmed, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(request))
	if err != nil {
		t.Fatalf("action-only confirmation could not recover durable publication: %v", err)
	}
	receipt := new(agentv1.DeviceActionInventoryReceipt)
	if err := f.svc.Authority.Verify(t.Context(), confirmed.Msg.GetReceiptEnvelope(), receipt, 1, ed25519.PublicKey(f.svc.Signing.StartKey[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	if receipt.GetHostSequence() != 2 || receipt.GetPackageSequence() != 1 || receipt.GetSnapshotId() != bound.GetSnapshotId() || !receipt.GetPublishedAt().AsTime().Equal(snapshot.CommittedAt.Time) {
		t.Fatalf("confirmation borrowed newer routine publication: %+v", receipt)
	}
	replayed, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(request))
	if err != nil || !bytes.Equal(replayed.Msg.GetReceiptEnvelope(), confirmed.Msg.GetReceiptEnvelope()) {
		t.Fatalf("lost confirmation response did not retain exact receipt: %v", err)
	}
	assertRefreshAdmissionSlots(t, f, start.GetActionId(), 2, 1)
}

func refreshFailedAttempt(f *deviceActionFixture, sequence uint64, when time.Time) *devicev1.ReportPackageAttemptRequest {
	return &devicev1.ReportPackageAttemptRequest{EnrollmentGeneration: f.generation, SessionEpoch: 1, Sequence: sequence, StartedAt: timestamppb.New(when), FinishedAt: timestamppb.New(when), Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, Backend: "apt"}
}

func assertRefreshAdmissionSlots(t *testing.T, f *deviceActionFixture, actionID string, host, packages int64) {
	t.Helper()
	var gotHost, gotPackages int64
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT inventory_host_sequence, inventory_package_sequence FROM device_actions WHERE id=$1", actionID).Scan(&gotHost, &gotPackages); err != nil || gotHost != host || gotPackages != packages {
		t.Fatalf("refresh slots = (%d,%d), want (%d,%d): %v", gotHost, gotPackages, host, packages, err)
	}
}

func assertRefreshReservations(t *testing.T, f *deviceActionFixture) {
	t.Helper()
	var device, snapshots, global, allSnapshots int64
	err := f.svc.Pool.QueryRow(t.Context(), `SELECT d.reserved_inventory_bytes,
		(SELECT coalesce(sum(reserved_bytes),0)::bigint FROM package_snapshots WHERE device_id=d.id),
		(SELECT reserved_bytes FROM inventory_reservation WHERE singleton),
		(SELECT coalesce(sum(reserved_bytes),0)::bigint FROM package_snapshots)
		FROM devices d WHERE d.id=$1`, f.principal.DeviceID).Scan(&device, &snapshots, &global, &allSnapshots)
	if err != nil || device != snapshots || global != allSnapshots {
		t.Fatalf("reservation accounting: device=%d snapshots=%d global=%d all=%d: %v", device, snapshots, global, allSnapshots, err)
	}
}
