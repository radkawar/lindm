//go:build integration

package reports

import (
	"bufio"
	"bytes"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "lindm/gen/lindm/audit/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/auditfilter"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/reports/reportdb"
)

func TestAuditSelectionMatchesListFiltersAndSignsCapturedSelection(t *testing.T) {
	s, ctx, pool, actor := reportFixture(t)
	target := uuid.New()
	start := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	end := start.Add(7 * 24 * time.Hour)
	insert := func(action string, device uuid.UUID, stamp time.Time) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,actor_id,target_device_id,action,resource_id,occurred_at) VALUES($1,$2,$3,$4,'selection-contract',$5)`, id, actor, device, action, stamp); err != nil {
			t.Fatal(err)
		}
		return id
	}
	insert("recovery_key.reveal", target, start)
	insert("recovery_key.reveal", target, start)
	insert("recovery_key.reveal", target, start.Add(-time.Microsecond))
	insert("recovery_key.reveal", target, end)
	insert("recovery_key.reveal", uuid.New(), start)
	for range 5 {
		insert("local_admin.reveal", target, start)
	}
	filter := &auditv1.AuditFilter{ActorId: new(actor.String()), TargetDeviceId: new(target.String()),
		ActionCategory: auditv1.AuditActionCategory_AUDIT_ACTION_CATEGORY_RECOVERY_KEY_REVEALS,
		OccurredFrom:   timestamppb.New(start), OccurredUntil: timestamppb.New(end)}
	selection, err := auditfilter.Normalize(filter)
	if err != nil {
		t.Fatal(err)
	}
	head, err := reportdb.New(pool).GetAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	list, err := devicedb.New(pool).ListAuditEvents(ctx, devicedb.ListAuditEventsParams{SnapshotSequence: head.Sequence,
		ActorID: selection.ActorID, TargetDeviceID: selection.TargetDeviceID, ActionCategory: int16(filter.GetActionCategory()),
		OccurredFrom: selection.OccurredFrom, OccurredUntil: selection.OccurredUntil, RowLimit: 201})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("list selected %d rows, want two exact half-open matches", len(list))
	}
	request := &integrationsv1.CreateAuditExportRequest{RequestId: uuid.NewString(), AfterHash: make([]byte, 32), MaxEvents: 2, RetentionDays: 7, Reason: "who revealed recovery keys last week", Filter: filter}
	created, err := s.CreateAuditExport(ctx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if created.Msg.Artifact.Kind != integrationsv1.ReportKind_REPORT_KIND_AUDIT_SELECTION {
		t.Fatalf("selection mislabeled as chain: %v", created.Msg.Artifact)
	}
	replayed, err := s.CreateAuditExport(ctx, connect.NewRequest(request))
	if err != nil || !proto.Equal(created.Msg, replayed.Msg) {
		t.Fatalf("selection replay changed: %v", err)
	}
	changed := proto.CloneOf(request)
	changed.Filter.TargetDeviceId = new(uuid.NewString())
	if _, err := s.CreateAuditExport(ctx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("request digest ignored changed filter: %v", err)
	}
	// Queued selections are pinned now, not when a worker eventually runs.
	insert("recovery_key.reveal", target, start.Add(time.Hour))
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	content, envelope := downloadArtifact(t, s, ctx, created.Msg.Artifact.Id)
	manifest, err := VerifyReportArtifact(bytes.NewReader(content), envelope, s.fingerprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(manifest.AuditFilter, filter) || manifest.CapturedHeadSequence != uint64(head.Sequence) || !bytes.Equal(manifest.CapturedHeadHash, head.RowHash) || manifest.RowCount != 2 || manifest.FinalSequence != 0 || len(manifest.FinalHash) != 0 || len(manifest.AfterHash) != 0 {
		t.Fatalf("untruthful signed selection metadata: %v", manifest)
	}
	var got []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		record := &integrationsv1.AuditChainRecord{}
		if err := protojson.Unmarshal(scanner.Bytes(), record); err != nil {
			t.Fatal(err)
		}
		stored, err := reportdb.New(pool).GetAuditRow(ctx, int64(record.Sequence))
		if err != nil || !bytes.Equal(stored.Payload, record.Payload) {
			t.Fatalf("selection rewrote original hash-bound payload: %v", err)
		}
		payload := &integrationsv1.AuditEventPayload{}
		if err := protojson.Unmarshal(record.Payload, payload); err != nil {
			t.Fatal(err)
		}
		got = append(got, payload.Id)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{list[0].ID.String(), list[1].ID.String()}
	if !slices.Equal(got, want) {
		t.Fatalf("export/list selection or order differs: %v, want %v", got, want)
	}
	if err := verifyAuditRows(bytes.NewReader(content), manifest, nil); err == nil {
		t.Fatal("selected rows accepted as contiguous chain")
	}
	if _, err := VerifyReportArtifact(bytes.NewReader(content), envelope, s.fingerprint[:], manifest); err == nil {
		t.Fatal("selection accepted checkpoint input")
	}
	// A correctly signed chain still rejects a selection as its predecessor.
	chainRequest := &integrationsv1.CreateAuditExportRequest{RequestId: uuid.NewString(), AfterHash: make([]byte, 32), MaxEvents: 100, RetentionDays: 7, Reason: "preserve independent chain validation"}
	chain, err := s.CreateAuditExport(ctx, connect.NewRequest(chainRequest))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	chainBytes, chainEnvelope := downloadArtifact(t, s, ctx, chain.Msg.Artifact.Id)
	if _, err := VerifyReportArtifact(bytes.NewReader(chainBytes), chainEnvelope, s.fingerprint[:], nil); err != nil {
		t.Fatalf("legacy contiguous chain changed: %v", err)
	}
	if _, err := VerifyReportArtifact(bytes.NewReader(chainBytes), chainEnvelope, s.fingerprint[:], manifest); err == nil {
		t.Fatal("selection used as chain checkpoint")
	}
	altered := proto.CloneOf(manifest)
	altered.AuditFilter.ActorId = new(uuid.NewString())
	badEnvelope := proto.CloneOf(envelope)
	badEnvelope.Manifest, err = proto.MarshalOptions{Deterministic: true}.Marshal(altered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReportArtifact(bytes.NewReader(content), badEnvelope, s.fingerprint[:], nil); err == nil {
		t.Fatal("signed filter tampering accepted")
	}
}

func TestAuditSelectionOverflowFailsWithoutPublishingPartialRows(t *testing.T) {
	s, ctx, pool, actor := reportFixture(t)
	for range 3 {
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events(actor_id,action,resource_id) VALUES($1,'assistance.request','overflow-contract')`, actor); err != nil {
			t.Fatal(err)
		}
	}
	created, err := s.CreateAuditExport(ctx, connect.NewRequest(&integrationsv1.CreateAuditExportRequest{RequestId: uuid.NewString(), AfterHash: make([]byte, 32), MaxEvents: 2, RetentionDays: 7, Reason: "bounded remote session selection", Filter: &auditv1.AuditFilter{ActionCategory: auditv1.AuditActionCategory_AUDIT_ACTION_CATEGORY_REMOTE_SESSIONS}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	row, err := reportdb.New(pool).GetReportArtifact(ctx, uuid.MustParse(created.Msg.Artifact.Id))
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "failed" || row.FailureReason != "report_limit_exceeded" || row.ChunkCount != 0 || len(row.SignedManifest) != 0 {
		t.Fatalf("overflow masqueraded as completed evidence: %v", row)
	}
	var chunks int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM report_artifact_chunks WHERE artifact_id=$1`, row.ID).Scan(&chunks); err != nil || chunks != 0 {
		t.Fatalf("partial chunks escaped rollback: %d %v", chunks, err)
	}
	if _, err := s.DownloadReportArtifact(ctx, connect.NewRequest(&integrationsv1.DownloadReportArtifactRequest{ArtifactId: row.ID.String()})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("failed selection downloadable: %v", err)
	}
}

func TestAuditSelectionRejectsMalformedFiltersCheckpointsAndScopedAuthority(t *testing.T) {
	s, ctx, _, actor := reportFixture(t)
	base := &integrationsv1.CreateAuditExportRequest{RequestId: uuid.NewString(), AfterHash: make([]byte, 32), MaxEvents: 100, RetentionDays: 7, Reason: "explicit selected evidence", Filter: &auditv1.AuditFilter{}}
	for name, change := range map[string]func(*integrationsv1.CreateAuditExportRequest){
		"actor":    func(v *integrationsv1.CreateAuditExportRequest) { v.Filter.ActorId = new("broken") },
		"target":   func(v *integrationsv1.CreateAuditExportRequest) { v.Filter.TargetDeviceId = new("") },
		"category": func(v *integrationsv1.CreateAuditExportRequest) { v.Filter.ActionCategory = 99 },
		"time": func(v *integrationsv1.CreateAuditExportRequest) {
			v.Filter.OccurredFrom = timestamppb.New(time.Unix(2, 0))
			v.Filter.OccurredUntil = timestamppb.New(time.Unix(1, 0))
		},
		"negative timestamp nanos": func(v *integrationsv1.CreateAuditExportRequest) {
			v.Filter.OccurredFrom = &timestamppb.Timestamp{Nanos: -1}
		},
		"excess timestamp nanos": func(v *integrationsv1.CreateAuditExportRequest) {
			v.Filter.OccurredUntil = &timestamppb.Timestamp{Nanos: 1000000000}
		},
		"checkpoint sequence": func(v *integrationsv1.CreateAuditExportRequest) { v.AfterSequence = 1 },
		"checkpoint hash":     func(v *integrationsv1.CreateAuditExportRequest) { v.AfterHash[0] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			request := proto.CloneOf(base)
			change(request)
			if _, err := s.CreateAuditExport(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("invalid selection admitted: %v", err)
			}
		})
	}
	scoped := identity.WithPrincipal(ctx, identity.Principal{ID: actor, Role: identity.RoleAdmin, Bindings: []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionManageIntegrations)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}}})
	if _, err := s.CreateAuditExport(scoped, connect.NewRequest(base)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped report permission widened: %v", err)
	}
	// Present empty is selection-all, not the legacy chain mode.
	created, err := s.CreateAuditExport(ctx, connect.NewRequest(base))
	if err != nil {
		t.Fatal(err)
	}
	if created.Msg.Artifact.Kind != integrationsv1.ReportKind_REPORT_KIND_AUDIT_SELECTION {
		t.Fatal("empty filter lost presence-selected semantics")
	}
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	content, envelope := downloadArtifact(t, s, ctx, created.Msg.Artifact.Id)
	if _, err := VerifyReportArtifact(bytes.NewReader(content), envelope, s.fingerprint[:], nil); err != nil {
		t.Fatal(err)
	}
}
