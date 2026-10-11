//go:build integration

package reports

import (
	"bufio"
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"google.golang.org/protobuf/encoding/protojson"

	auditv1 "lindm/gen/lindm/audit/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/reports/reportdb"
)

func TestAuditLifecycleTargetsBackfillAndCaptureWithoutRewritingEvidence(t *testing.T) {
	s, ctx, pool, actor := reportFixture(t)
	// Exercise the real migration's backfill as well as its insert trigger.
	// Apply only our migration in the isolated schema: later migrations may be forward-only.
	migrationDB := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() {
		if err := migrationDB.Close(); err != nil {
			t.Error(err)
		}
	})
	migrations, err := goose.NewProvider(goose.DialectPostgres, migrationDB, os.DirFS("../../db/migrations"))
	if err != nil {
		t.Fatal(err)
	}
	var auditVersion int64
	for _, source := range migrations.ListSources() {
		if strings.HasSuffix(source.Path, "_audit_filters.sql") {
			auditVersion = source.Version
			break
		}
	}
	if auditVersion == 0 {
		t.Fatal("audit filter migration missing")
	}
	if _, err := migrations.ApplyVersion(ctx, auditVersion, false); err != nil {
		t.Fatal(err)
	}
	target, explicit := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO devices(id,state,hostname,enrolled_at) VALUES($1,'pending','Lifecycle-only device',$2)`, target, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	type evidence struct{ payload, hash []byte }
	original := make(map[uuid.UUID]evidence)
	var want []uuid.UUID
	seed := func() {
		t.Helper()
		for _, action := range []string{"device.enroll", "device.revoke", "device.renew", "device.activate", "device.recovery_hold", "device.recovery_authorized", "device.recovered", "provisioning.reserve", "provisioning.approve"} {
			id := uuid.New()
			if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,actor_id,action,resource_id,occurred_at) VALUES($1,$2,$3,$4,$5)`, id, actor, action, target.String(), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)); err != nil {
				t.Fatal(err)
			}
			var row evidence
			if err := pool.QueryRow(ctx, `SELECT payload,row_hash FROM report_audit_rows WHERE event_id=$1`, id).Scan(&row.payload, &row.hash); err != nil {
				t.Fatal(err)
			}
			original[id] = row
			want = append(want, id)
		}
		// Resource UUIDs for other domains and malformed legacy resources are
		// never interpreted as device identities, even for a matching device ID.
		for _, action := range []string{"device.group_set", "enrollment_grant.create", "device.unknown"} {
			if _, err := pool.Exec(ctx, `INSERT INTO audit_events(actor_id,action,resource_id) VALUES($1,$2,$3)`, actor, action, target.String()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events(actor_id,action,resource_id) VALUES($1,'device.enroll','malformed-resource')`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events(actor_id,action,resource_id,target_device_id) VALUES($1,'device.enroll',$2,$3)`, actor, target.String(), explicit); err != nil {
			t.Fatal(err)
		}
	}
	seed()
	before, err := reportdb.New(pool).GetAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrations.ApplyVersion(ctx, auditVersion, true); err != nil {
		t.Fatal(err)
	}
	after, err := reportdb.New(pool).GetAuditHead(ctx)
	if err != nil || before.Sequence != after.Sequence || !bytes.Equal(before.RowHash, after.RowHash) {
		t.Fatalf("backfill changed the original chain head: %v", err)
	}
	seed()
	head, err := reportdb.New(pool).GetAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q := devicedb.New(pool)
	listed, err := q.ListAuditEvents(ctx, devicedb.ListAuditEventsParams{SnapshotSequence: head.Sequence, ActorID: &actor, TargetDeviceID: &target, RowLimit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != len(want) {
		t.Fatalf("lifecycle target list has %d events, want %d backfilled/future events", len(listed), len(want))
	}
	for _, event := range listed {
		if !slices.Contains(want, event.ID) || event.TargetDeviceID == nil || *event.TargetDeviceID != target {
			t.Fatalf("wrong lifecycle target selection: %v", event)
		}
	}
	preferred, err := q.ListAuditEvents(ctx, devicedb.ListAuditEventsParams{SnapshotSequence: head.Sequence, ActorID: &actor, TargetDeviceID: &explicit, RowLimit: 200})
	if err != nil || len(preferred) != 2 {
		t.Fatalf("explicit structured targets did not override resource fallback in both phases: %v", err)
	}
	options, err := q.ListAuditDevices(ctx, devicedb.ListAuditDevicesParams{ID: &target, RowLimit: 2})
	if err != nil || len(options) != 1 || options[0].Hostname != "Lifecycle-only device" {
		t.Fatalf("lifecycle-only device missing from audit picker: %v", err)
	}
	request := &integrationsv1.CreateAuditExportRequest{RequestId: uuid.NewString(), AfterHash: make([]byte, 32), MaxEvents: uint32(len(want)), RetentionDays: 7,
		Reason: "retain lifecycle history for this device", Filter: &auditv1.AuditFilter{ActorId: new(actor.String()), TargetDeviceId: new(target.String())}}
	created, err := s.CreateAuditExport(ctx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	content, envelope := downloadArtifact(t, s, ctx, created.Msg.Artifact.Id)
	manifest, err := VerifyReportArtifact(bytes.NewReader(content), envelope, s.fingerprint[:], nil)
	if err != nil || manifest.GetRowCount() != uint64(len(want)) {
		t.Fatalf("lifecycle export differs from target-filtered list: %v", err)
	}
	var exported []uuid.UUID
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		record := &integrationsv1.AuditChainRecord{}
		if err := protojson.Unmarshal(scanner.Bytes(), record); err != nil {
			t.Fatal(err)
		}
		payload := &integrationsv1.AuditEventPayload{}
		if err := protojson.Unmarshal(record.Payload, payload); err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(payload.Id)
		prior, ok := original[id]
		if !ok || payload.GetTargetDeviceId() != "" || !bytes.Equal(prior.payload, record.Payload) || !bytes.Equal(prior.hash, record.RowHash) {
			t.Fatal("lifecycle target reconstruction rewrote or substituted original evidence")
		}
		exported = append(exported, id)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for i, event := range listed {
		if exported[i] != event.ID {
			t.Fatal("lifecycle list/export ordering differs")
		}
	}
}
