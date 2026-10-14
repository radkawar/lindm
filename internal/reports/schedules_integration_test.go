// SPDX-License-Identifier: Apache-2.0

//go:build integration

package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/reports/reportdb"
)

func TestScheduledInventoryPublicationRetentionAndRevocation(t *testing.T) {
	s, ctx, pool, actor := reportFixture(t)
	if _, err := pool.Exec(ctx, `INSERT INTO devices(id,state,hostname,os_id,os_version,architecture,enrolled_at)
SELECT gen_random_uuid(),'active',repeat('x',4096),'ubuntu','24.04','amd64',now() FROM generate_series(1,130)`); err != nil {
		t.Fatal(err)
	}
	request := &integrationsv1.UpsertReportScheduleRequest{RequestId: uuid.NewString(), Reason: "scheduled inventory export", Schedule: &integrationsv1.ReportSchedule{
		Id: uuid.NewString(), Name: "Inventory daily", Kind: integrationsv1.ReportKind_REPORT_KIND_INVENTORY, Format: integrationsv1.ReportFormat_REPORT_FORMAT_JSON,
		IntervalSeconds: 86400, RetentionDays: 7, Enabled: true}}
	created, err := s.UpsertReportSchedule(ctx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.UpsertReportSchedule(ctx, connect.NewRequest(request))
	if err != nil || !proto.Equal(created.Msg, replay.Msg) {
		t.Fatalf("schedule replay changed: %v", err)
	}
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	listed, err := s.ListReportArtifacts(ctx, connect.NewRequest(&integrationsv1.ListReportArtifactsRequest{}))
	if err != nil || len(listed.Msg.Artifacts) != 1 {
		t.Fatalf("artifact listing: %v", err)
	}
	artifact := listed.Msg.Artifacts[0]
	if artifact.State != "published" || artifact.RowCount != 130 || artifact.ChunkCount < 2 {
		t.Fatalf("not atomically chunked: %v", artifact)
	}
	content, envelope := downloadArtifact(t, s, ctx, artifact.Id)
	if _, err := VerifyReportArtifact(bytes.NewReader(content), envelope, s.fingerprint[:], nil); err != nil {
		t.Fatal(err)
	}
	var devices []map[string]json.RawMessage
	if err := json.Unmarshal(content, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 130 || string(devices[0]["os_id"]) != `"ubuntu"` || string(devices[0]["os_version"]) != `"24.04"` {
		t.Fatal("report did not contain normalized inventory")
	}
	update := &integrationsv1.UpsertReportScheduleRequest{RequestId: uuid.NewString(), Reason: "switch to spreadsheet", Schedule: proto.CloneOf(created.Msg.Schedule)}
	update.Schedule.Format = integrationsv1.ReportFormat_REPORT_FORMAT_CSV
	updated, err := s.UpsertReportSchedule(ctx, connect.NewRequest(update))
	if err != nil || updated.Msg.Schedule.Revision != 2 {
		t.Fatalf("schedule revision: %v", err)
	}
	stale := proto.CloneOf(update)
	stale.RequestId = uuid.NewString()
	if _, err := s.UpsertReportSchedule(ctx, connect.NewRequest(stale)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale schedule update accepted: %v", err)
	}
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := reportdb.New(pool).ListReportArtifacts(ctx, reportdb.ListReportArtifactsParams{AfterID: uuid.Nil, RowLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if integrationsv1.ReportFormat(row.Format) != integrationsv1.ReportFormat_REPORT_FORMAT_CSV {
			continue
		}
		content, _ := downloadArtifact(t, s, ctx, row.ID.String())
		records, err := csv.NewReader(bytes.NewReader(content)).ReadAll()
		if err != nil || len(records) != 131 {
			t.Fatalf("CSV report contents: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, "UPDATE report_artifacts SET expires_at=now()-interval '1 second' WHERE id=$1", artifact.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DownloadReportArtifact(ctx, connect.NewRequest(&integrationsv1.DownloadReportArtifactRequest{ArtifactId: artifact.Id})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("expired artifact downloadable: %v", err)
	}
	if _, err := reportdb.New(pool).PruneReportArtifacts(ctx); err != nil {
		t.Fatal(err)
	}
	var chunks int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM report_artifact_chunks WHERE artifact_id=$1", artifact.Id).Scan(&chunks); err != nil || chunks != 0 {
		t.Fatalf("retention leaked chunks: %d %v", chunks, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", actor); err != nil {
		t.Fatal(err)
	}
	update.RequestId = uuid.NewString()
	update.Schedule.Revision = 2
	if _, err := s.UpsertReportSchedule(ctx, connect.NewRequest(update)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("stale session mutated revoked identity: %v", err)
	}
}

func TestScheduleSkipLockedAndArtifactLeaseFencing(t *testing.T) {
	s, ctx, pool, actor := reportFixture(t)
	q := reportdb.New(pool)
	schedule, err := q.CreateReportSchedule(ctx, reportdb.CreateReportScheduleParams{ID: uuid.New(), ActorID: actor, Name: "lease", Kind: 1, Format: 2, IntervalSeconds: 300, RetentionDays: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	})
	if _, err := tx.Exec(ctx, "SELECT id FROM report_schedules WHERE id=$1 FOR UPDATE", schedule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.QueueDueReport(ctx, reportdb.QueueDueReportParams{LeaseToken: uuid.New(), ArtifactID: uuid.New()}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("did not skip locked schedule: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	queued, err := q.QueueDueReport(ctx, reportdb.QueueDueReportParams{LeaseToken: uuid.New(), ArtifactID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.QueueDueReport(ctx, reportdb.QueueDueReportParams{LeaseToken: uuid.New(), ArtifactID: uuid.New()}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("schedule occurrence queued twice: %v", err)
	}
	first, err := q.ClaimReportArtifact(ctx, uuid.New())
	if err != nil || first.ID != queued.ID {
		t.Fatalf("claim: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE report_artifacts SET lease_until=now()-interval '1 second' WHERE id=$1", first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := q.ClaimReportArtifact(ctx, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	count, err := q.PublishReportArtifact(ctx, reportdb.PublishReportArtifactParams{ID: first.ID, LeaseToken: *first.LeaseToken})
	if err != nil || count != 0 {
		t.Fatalf("stale worker published: %d %v", count, err)
	}
	build, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.buildArtifact(ctx, reportdb.New(build), first); !errors.Is(err, errLeaseLost) {
		t.Fatalf("stale build did not fail publication: %v", err)
	}
	if err := build.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var chunks int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM report_artifact_chunks WHERE artifact_id=$1", second.ID).Scan(&chunks); err != nil || chunks != 0 {
		t.Fatalf("failed publication leaked chunks: %d %v", chunks, err)
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, actor, "integrations.manage")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.generate(ctx, second, authorization); err != nil {
		t.Fatal(err)
	}
	published, err := q.GetReportArtifact(ctx, second.ID)
	if err != nil || published.State != "published" {
		t.Fatalf("new worker could not publish: %v", err)
	}
}

func TestChunkWriterEnforcesWholeArtifactLimit(t *testing.T) {
	writer := &chunkWriter{total: maxArtifactBytes - 1}
	if n, err := writer.Write([]byte("xx")); n != 0 || !errors.Is(err, errReportLimit) {
		t.Fatalf("unbounded artifact: %d %v", n, err)
	}
	if n, err := writer.WriteString("xx"); n != 0 || !errors.Is(err, errReportLimit) {
		t.Fatalf("unbounded string artifact: %d %v", n, err)
	}
}
