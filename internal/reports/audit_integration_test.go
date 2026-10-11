//go:build integration

package reports

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/reports/reportdb"
)

func TestAuditExportIndependentVerificationAndCheckpoints(t *testing.T) {
	s, ctx, pool, actor := reportFixture(t)
	target := uuid.New()
	for i := 0; i < 5; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events(actor_id,action,resource_id,reason,target_device_id,details) VALUES($1,'report.test',$2,'independent chain evidence',$3,'{"mode":"view","duration_seconds":"900"}')`, actor, uuid.NewString(), target); err != nil {
			t.Fatal(err)
		}
	}
	request := &integrationsv1.CreateAuditExportRequest{RequestId: uuid.NewString(), AfterHash: make([]byte, 32), MaxEvents: 2, RetentionDays: 7, Reason: "archive audit evidence"}
	created, err := s.CreateAuditExport(ctx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := s.CreateAuditExport(ctx, connect.NewRequest(request))
	if err != nil || !proto.Equal(created.Msg, replayed.Msg) {
		t.Fatalf("exact replay differed: %v", err)
	}
	changed := proto.CloneOf(request)
	changed.Reason = "different intent"
	if _, err := s.CreateAuditExport(ctx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed request reused ID: %v", err)
	}
	if _, err := s.DownloadReportArtifact(ctx, connect.NewRequest(&integrationsv1.DownloadReportArtifactRequest{ArtifactId: created.Msg.Artifact.Id})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("unpublished download: %v", err)
	}
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	content, envelope := downloadArtifact(t, s, ctx, created.Msg.Artifact.Id)
	manifest := &integrationsv1.ReportManifest{}
	if err := proto.Unmarshal(envelope.Manifest, manifest); err != nil {
		t.Fatal(err)
	}
	public, ok := s.signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("fixture signer is not Ed25519")
	}
	if !ed25519.Verify(public, append([]byte("lindm-report-manifest-v1\x00"), envelope.Manifest...), envelope.Signature) {
		t.Fatal("independent signature rejected")
	}
	contentDigest := sha256.Sum256(content)
	if !bytes.Equal(contentDigest[:], manifest.ContentSha256) || manifest.ByteCount != uint64(len(content)) {
		t.Fatal("independent content manifest mismatch")
	}
	chain, err := uuid.Parse(manifest.ChainId)
	if err != nil {
		t.Fatal(err)
	}
	previous := make([]byte, 32)
	var sequence uint64
	scanner := bufio.NewScanner(bytes.NewReader(content))
	structured := false
	for scanner.Scan() {
		record := &integrationsv1.AuditChainRecord{}
		if err := protojson.Unmarshal(scanner.Bytes(), record); err != nil {
			t.Fatal(err)
		}
		sequence++
		if record.Sequence != sequence || !bytes.Equal(previous, record.PreviousHash) {
			t.Fatal("independent continuity mismatch")
		}
		var number [8]byte
		binary.BigEndian.PutUint64(number[:], sequence)
		input := append([]byte("lindm-audit-v1\x00"), chain[:]...)
		input = append(input, number[:]...)
		input = append(input, previous...)
		input = append(input, record.Payload...)
		digest := sha256.Sum256(input)
		if !bytes.Equal(digest[:], record.RowHash) {
			t.Fatal("independent row hash mismatch")
		}
		payload := new(integrationsv1.AuditEventPayload)
		if err := protojson.Unmarshal(record.GetPayload(), payload); err != nil {
			t.Fatalf("decode documented audit payload: %v", err)
		}
		if payload.GetAction() == "report.test" {
			structured = true
			if payload.GetTargetDeviceId() != target.String() || payload.GetDetails()["mode"] != "view" || payload.GetDetails()["duration_seconds"] != "900" || payload.GetReason() != "independent chain evidence" {
				t.Fatalf("structured audit fields missing from authenticated payload: %v", payload)
			}
			for _, change := range [][2]string{{target.String(), uuid.NewString()}, {"900", "901"}, {"view", "control"}} {
				tampered := proto.CloneOf(record)
				tampered.Payload = bytes.Replace(record.Payload, []byte(change[0]), []byte(change[1]), 1)
				line, err := protojson.Marshal(tampered)
				if err != nil {
					t.Fatal(err)
				}
				archive := bytes.Replace(content, scanner.Bytes(), line, 1)
				if err := verifyAuditRows(bytes.NewReader(archive), manifest, nil); err == nil || err.Error() != "reports: audit row hash mismatch" {
					t.Fatalf("structured field tampering did not fail chain verification: %v", err)
				}
			}
		}
		previous = record.RowHash
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !structured {
		t.Fatal("export omitted structured audit event")
	}
	if sequence != 2 || sequence != manifest.FinalSequence || !bytes.Equal(previous, manifest.FinalHash) {
		t.Fatal("independent final checkpoint mismatch")
	}
	if _, err := VerifyReportArtifact(bytes.NewReader(content), envelope, s.fingerprint[:], nil); err != nil {
		t.Fatal(err)
	}
	continuation := &integrationsv1.CreateAuditExportRequest{RequestId: uuid.NewString(), AfterSequence: manifest.FinalSequence, AfterHash: manifest.FinalHash, MaxEvents: 1000, RetentionDays: 7, Reason: "continue pinned checkpoint"}
	next, err := s.CreateAuditExport(ctx, connect.NewRequest(continuation))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.workOnce(ctx); err != nil {
		t.Fatal(err)
	}
	nextContent, nextEnvelope := downloadArtifact(t, s, ctx, next.Msg.Artifact.Id)
	if _, err := VerifyReportArtifact(bytes.NewReader(nextContent), nextEnvelope, s.fingerprint[:], manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReportArtifact(bytes.NewReader(nextContent), nextEnvelope, s.fingerprint[:], nil); err == nil {
		t.Fatal("accepted missing earlier checkpoint")
	}
	continuation.RequestId = uuid.NewString()
	continuation.AfterHash = bytes.Repeat([]byte{1}, 32)
	if _, err := s.CreateAuditExport(ctx, connect.NewRequest(continuation)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("accepted forged checkpoint: %v", err)
	}
}

func TestAuditCaptureRollbackSerialHeadAndImmutability(t *testing.T) {
	_, ctx, pool, actor := reportFixture(t)
	q := reportdb.New(pool)
	before, err := q.GetAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	})
	if err := reportdb.New(first).InsertReportAudit(ctx, reportdb.InsertReportAuditParams{ActorID: &actor, Action: "report.rollback", ResourceID: "rollback", Reason: "must never commit"}); err != nil {
		t.Fatal(err)
	}
	visible, err := q.GetAuditHead(ctx)
	if err != nil || visible.Sequence != before.Sequence {
		t.Fatalf("uncommitted head leaked: %v", err)
	}
	second, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	})
	inserted := make(chan error, 1)
	go func() {
		inserted <- reportdb.New(second).InsertReportAudit(ctx, reportdb.InsertReportAuditParams{ActorID: &actor, Action: "report.concurrent", ResourceID: "concurrent", Reason: "committed after rollback"})
	}()
	if err := first.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-inserted; err != nil {
		t.Fatal(err)
	}
	if err := second.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := q.GetAuditHead(ctx)
	if err != nil || after.Sequence != before.Sequence+1 {
		t.Fatalf("rollback allocated sequence gap: %v", err)
	}
	row, err := q.GetAuditRow(ctx, after.Sequence)
	if err != nil || !bytes.Equal(row.PreviousHash, before.RowHash) {
		t.Fatalf("wrong predecessor: %v", err)
	}
	for _, statement := range []string{"UPDATE report_audit_rows SET payload='tamper' WHERE sequence=1", "DELETE FROM audit_events", "TRUNCATE report_audit_rows"} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("append-only evidence allowed %q", statement)
		}
	}
}
