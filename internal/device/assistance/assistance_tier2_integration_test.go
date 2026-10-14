// SPDX-License-Identifier: Apache-2.0

//go:build integration

package assistance

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/assistancerecording"
	"lindm/internal/identity"
)

const (
	tier2On      = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	tier2Limited = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	tier2Off     = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
)

type tier2Fixture struct {
	*assistanceFixture
	recipient *assistancerecording.Recipient
}

// newTier2Fixture applies device policy with a fully permissive ceiling and
// then binds the creator's fresh authority to the named custom role.
func newTier2Fixture(t *testing.T, role string, device *agentv1.AssistancePolicy) *tier2Fixture {
	t.Helper()
	f := newAssistanceFixture(t, 0)
	seed := make([]byte, assistancerecording.PrivateKeySeedBytes)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	recipient, err := assistancerecording.NewRecipient(seed)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.AssistanceRecording, f.svc.RecordingStorage = recipient, 64<<20
	f.svc.AssistanceCeiling = assistancePolicy(testWorkflowPolicy(tier2On, tier2On))
	if _, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: device})); err != nil {
		t.Fatal(err)
	}
	permissions := func(names ...identity.Permission) []string {
		out := make([]string, len(names))
		for i, name := range names {
			out[i] = string(name)
		}
		return out
	}
	authority, err := identity.New(t.Context(), f.svc.Pool, identity.Config{Local: true, PublicURL: "https://admin.example", Policy: &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{
		{Name: "tier2", Permissions: permissions(identity.PermissionViewRemoteAssistance, identity.PermissionControlRemoteAssistance, identity.PermissionAssistanceReconnect, identity.PermissionAssistanceRecord)},
		{Name: "view-only", Permissions: permissions(identity.PermissionViewRemoteAssistance)},
		{Name: "view-record", Permissions: permissions(identity.PermissionViewRemoteAssistance, identity.PermissionAssistanceRecord)},
		{Name: "archive-reader", Permissions: permissions(identity.PermissionReadAssistanceRecordings)},
		{Name: "archive-deleter", Permissions: permissions(identity.PermissionDeleteAssistanceRecordings)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	f.svc.Identity = authority
	setAssistanceRole(t, f, role)
	return &tier2Fixture{assistanceFixture: f, recipient: recipient}
}

// archiveCtx is a separate principal whose cached and fresh authority hold
// only the named archive role, like an auditor granted retrieval.
func (f *tier2Fixture) archiveCtx(t *testing.T, role string, permission identity.Permission) context.Context {
	t.Helper()
	principal := insertPrincipal(t, f.ctx, f.conn, identity.RoleAuditor)
	if _, err := f.conn.Exec(f.ctx, "UPDATE local_accounts SET role=$2 WHERE id=$1", principal.ID, role); err != nil {
		t.Fatal(err)
	}
	principal.Bindings = []*authv1.RoleBinding{{Role: role, Permissions: []string{string(permission)}}}
	return identity.WithPrincipal(f.ctx, principal)
}

func (f *tier2Fixture) request(requested *agentv1.AssistancePolicy) *adminv1.CreateAssistanceSessionRequest {
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	request.RequestedCapabilities = requested
	return request
}

func (f *tier2Fixture) createTier2(t *testing.T, requested *agentv1.AssistancePolicy) *adminv1.AssistanceSession {
	t.Helper()
	response, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.request(requested)))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetSession()
}

// consent reports local consent with exactly grant and returns the device
// observation together with the session's directive.
func (f *tier2Fixture) consent(t *testing.T, session *adminv1.AssistanceSession, grant *agentv1.AssistancePolicy) (*agentv1.AssistanceReport, *agentv1.AssistanceDirective) {
	t.Helper()
	observation := report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint))
	observation.ControlGranted = false
	observation.RequestedCapabilities, observation.EffectiveCapabilities = proto.CloneOf(session.GetRequestedCapabilities()), proto.CloneOf(session.GetEffectiveCapabilities())
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: grant}
	for _, directive := range f.sync(t, observation) {
		if directive.GetInvitation().GetSessionId() == session.GetId() {
			return observation, directive
		}
	}
	t.Fatal("no directive for the consented session")
	return nil, nil
}

func (f *tier2Fixture) sealer(t *testing.T, directive *agentv1.AssistanceDirective) *assistancerecording.Sealer {
	t.Helper()
	authority := directive.GetInvitation().GetRecording()
	sealer, err := assistancerecording.NewSealer(authority.GetPublicKey(), authority.GetKeyId(), uuid.MustParse(authority.GetRecordingId()))
	if err != nil {
		t.Fatal(err)
	}
	return sealer
}

func seal(t *testing.T, sealer *assistancerecording.Sealer, recordingID string, final bool, plaintext string) *agentv1.AssistanceRecordingChunk {
	t.Helper()
	sequence, ciphertext, err := sealer.Seal(final, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	chunk := &agentv1.AssistanceRecordingChunk{RecordingId: recordingID, Sequence: sequence, Final: final, Ciphertext: ciphertext}
	if sequence == 0 {
		chunk.EncapsulatedKey = sealer.EncapsulatedKey()
	}
	return chunk
}

func (f *tier2Fixture) put(sessionID string, chunks ...*agentv1.AssistanceRecordingChunk) (*devicev1.PutAssistanceRecordingResponse, error) {
	response, err := f.svc.PutAssistanceRecording(f.deviceCtx(), connect.NewRequest(&devicev1.PutAssistanceRecordingRequest{SessionEpoch: f.epoch, SessionId: sessionID, Chunks: chunks}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (f *tier2Fixture) recordingAudit(t *testing.T, recordingID string) (actions []string, details []map[string]string) {
	t.Helper()
	rows, err := f.conn.Query(f.ctx, "SELECT action, details FROM audit_events WHERE resource_id=$1 ORDER BY occurred_at, action", recordingID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		var detail map[string]string
		if err := rows.Scan(&action, &detail); err != nil {
			t.Fatal(err)
		}
		actions, details = append(actions, action), append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return actions, details
}

func recordingGrant(mode agentv1.AssistancePolicyMode) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{Recording: mode, RecordingLimits: &agentv1.AssistanceRecordingPolicy{RetentionDays: 30, MaxBytes: 256 << 20}}
}

func TestAssistanceRecordingAdmissionRefusals(t *testing.T) {
	t.Run("record permission", func(t *testing.T) {
		f := newTier2Fixture(t, "view-only", testWorkflowPolicy(tier2Off, tier2On))
		_, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.request(recordingGrant(tier2Limited))))
		if code := connect.CodeOf(err); code != connect.CodeNotFound && code != connect.CodePermissionDenied {
			t.Fatalf("recording without remote_assistance.record: %v", err)
		}
	})
	t.Run("required beyond policy", func(t *testing.T) {
		f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2Limited))
		_, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.request(recordingGrant(tier2On))))
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_recording_not_permitted")
	})
	t.Run("custody absent", func(t *testing.T) {
		f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
		f.svc.AssistanceRecording = nil
		_, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.request(recordingGrant(tier2Limited))))
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_recording_unavailable")
		var count int
		if err := f.conn.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM assistance_sessions) + (SELECT count(*) FROM assistance_recordings)").Scan(&count); err != nil || count != 0 {
			t.Fatalf("refused recording persisted state: %d %v", count, err)
		}
	})
}

func TestAssistanceOptionalRecordingDeclineContinuesUnrecorded(t *testing.T) {
	f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
	session := f.createTier2(t, recordingGrant(tier2Limited))
	if session.GetRecording().GetState() != adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_PENDING || session.GetRecording().GetRequired() {
		t.Fatalf("optional recording = %v", session.GetRecording())
	}
	_, directive := f.consent(t, session, &agentv1.AssistancePolicy{})
	if directive.GetInvitation().GetRecording() == nil || directive.GetTerminate() {
		t.Fatalf("declining optional recording ended the session or changed its authority: %v", directive)
	}
	got := f.get(t, session.GetId())
	if got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_OFFERED || got.GetRecording().GetState() != adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_DECLINED {
		t.Fatalf("declined optional recording = %v", got)
	}
	sealer := f.sealer(t, directive)
	_, err := f.put(session.GetId(), seal(t, sealer, got.GetRecording().GetId(), false, "never"))
	wantReason(t, err, connect.CodeFailedPrecondition, "recording_not_active")
	if actions, _ := f.recordingAudit(t, got.GetRecording().GetId()); !slices.Equal(actions, []string{"assistance.recording.stop"}) {
		t.Fatalf("decline audit = %v", actions)
	}
}

func TestAssistanceRequiredRecordingNotGrantedEndsSession(t *testing.T) {
	f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
	session := f.createTier2(t, recordingGrant(tier2On))
	if !session.GetRecording().GetRequired() {
		t.Fatal("required recording was not marked required")
	}
	f.consent(t, session, &agentv1.AssistancePolicy{})
	got := f.get(t, session.GetId())
	if got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED || got.GetEndDetail() != "recording_not_granted" || got.GetRecording().GetState() != adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_FAILED {
		t.Fatalf("unrecorded required session = %v", got)
	}
}

func TestAssistanceRecordingIsCiphertextAtRestAndRetrievalIsSeparateAuthority(t *testing.T) {
	f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
	session := f.createTier2(t, recordingGrant(tier2On))
	_, directive := f.consent(t, session, recordingGrant(tier2On))
	recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
	sealer := f.sealer(t, directive)
	first, second := seal(t, sealer, recordingID, false, "plain-header-"), seal(t, sealer, recordingID, false, "plain-middle-")
	stored, err := f.put(session.GetId(), first, second)
	if err != nil || stored.GetStoredThrough() != 1 {
		t.Fatalf("store: %v %v", stored, err)
	}
	if again, err := f.put(session.GetId(), first); err != nil || again.GetStoredThrough() != 1 {
		t.Fatalf("identical retry: %v %v", again, err)
	}
	if _, err := f.svc.StopAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: session.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.put(session.GetId(), seal(t, sealer, recordingID, true, "plain-final")); err != nil {
		t.Fatalf("final segment within grace: %v", err)
	}
	recording := f.get(t, session.GetId()).GetRecording()
	if recording.GetState() != adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_COMPLETE || len(recording.GetCiphertextSha256()) != 64 || recording.GetSegments() != 3 || recording.GetRetainUntil() == nil {
		t.Fatalf("finalized recording = %v", recording)
	}
	rows, err := f.conn.Query(f.ctx, "SELECT ciphertext FROM assistance_recording_segments WHERE recording_id=$1", recordingID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ciphertext []byte
		if err := rows.Scan(&ciphertext); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(ciphertext, []byte("plain-")) {
			t.Fatal("recording plaintext stored at rest")
		}
	}
	rows.Close()

	open := &adminv1.OpenAssistanceRecordingRequest{RecordingId: recordingID, Reason: "complaint review"}
	auditor := identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, f.conn, identity.RoleAuditor))
	if _, err := f.svc.OpenAssistanceRecording(auditor, connect.NewRequest(open)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("auditor metadata access opened a recording: %v", err)
	}
	if _, err := f.svc.OpenAssistanceRecording(f.archiveCtx(t, "archive-deleter", identity.PermissionDeleteAssistanceRecordings), connect.NewRequest(open)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("deletion grant opened a recording: %v", err)
	}
	reader := f.archiveCtx(t, "archive-reader", identity.PermissionReadAssistanceRecordings)
	if _, err := f.svc.CreateAssistanceSession(reader, connect.NewRequest(f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, ""))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("retrieval grant allowed live assistance: %v", err)
	}
	opened, err := f.svc.OpenAssistanceRecording(reader, connect.NewRequest(open))
	if err != nil {
		t.Fatal(err)
	}
	var stream []byte
	for sequence := range uint32(3) {
		read, err := f.svc.ReadAssistanceRecording(reader, connect.NewRequest(&adminv1.ReadAssistanceRecordingRequest{RetrievalId: opened.Msg.GetRetrievalId(), Sequence: sequence}))
		if err != nil {
			t.Fatal(err)
		}
		if read.Msg.GetLast() != (sequence == 2) || !read.Msg.GetComplete() {
			t.Fatalf("segment %d flags %v", sequence, read.Msg)
		}
		stream = append(stream, read.Msg.GetData()...)
	}
	if string(stream) != "plain-header-plain-middle-plain-final" {
		t.Fatalf("retrieved stream = %q", stream)
	}
	_, err = f.svc.ReadAssistanceRecording(reader, connect.NewRequest(&adminv1.ReadAssistanceRecordingRequest{RetrievalId: opened.Msg.GetRetrievalId(), Sequence: 3}))
	wantReason(t, err, connect.CodeOutOfRange, "assistance_recording_sequence")
	_, err = f.svc.ReadAssistanceRecording(f.otherCtx, connect.NewRequest(&adminv1.ReadAssistanceRecordingRequest{RetrievalId: opened.Msg.GetRetrievalId()}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("another operator used a retrieval: %v", err)
	}
	f.advance(assistanceRetrievalLifetime)
	_, err = f.svc.ReadAssistanceRecording(reader, connect.NewRequest(&adminv1.ReadAssistanceRecordingRequest{RetrievalId: opened.Msg.GetRetrievalId()}))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_recording_retrieval_expired")

	actions, details := f.recordingAudit(t, recordingID)
	for _, want := range []string{"assistance.recording.start", "assistance.recording.stop", "assistance.recording.read"} {
		if !slices.Contains(actions, want) {
			t.Fatalf("audit %v lacks %s", actions, want)
		}
	}
	denied := 0
	for i, detail := range details {
		for key, value := range detail {
			if strings.Contains(value, "plain-") {
				t.Fatalf("audit %s leaked recording plaintext in %s", actions[i], key)
			}
		}
		if actions[i] == "assistance.recording.read" && detail["result"] == "denied" {
			denied++
		}
		if actions[i] == "assistance.recording.stop" && (detail["ciphertext_sha256"] != recording.GetCiphertextSha256() || detail["segments"] != "3") {
			t.Fatalf("stop audit lacks object identity and digest: %v", detail)
		}
	}
	if denied != 2 {
		t.Fatalf("denied retrievals audited %d times, want 2", denied)
	}
}

func TestAssistanceRecordingRejectsGapsSubstitutionAndForeignSegments(t *testing.T) {
	t.Run("gap ends required session", func(t *testing.T) {
		f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
		session := f.createTier2(t, recordingGrant(tier2On))
		_, directive := f.consent(t, session, recordingGrant(tier2On))
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		sealer := f.sealer(t, directive)
		seal(t, sealer, recordingID, false, "skipped")
		_, err := f.put(session.GetId(), seal(t, sealer, recordingID, false, "after gap"))
		wantReason(t, err, connect.CodeFailedPrecondition, "recording_sequence")
		got := f.get(t, session.GetId())
		if got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED || got.GetRecording().GetState() != adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_FAILED {
			t.Fatalf("gap left required session running: %v", got)
		}
	})
	t.Run("substitution and foreign identity", func(t *testing.T) {
		f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
		session := f.createTier2(t, recordingGrant(tier2Limited))
		_, directive := f.consent(t, session, recordingGrant(tier2Limited))
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		sealer := f.sealer(t, directive)
		if _, err := f.put(session.GetId(), seal(t, sealer, recordingID, false, "original")); err != nil {
			t.Fatal(err)
		}
		_, err := f.put(session.GetId(), seal(t, f.sealer(t, directive), recordingID, false, "replacement"))
		wantReason(t, err, connect.CodeFailedPrecondition, "recording_sequence")
		_, err = f.put(session.GetId(), seal(t, f.sealer(t, directive), uuid.NewString(), false, "foreign"))
		wantReason(t, err, connect.CodeNotFound, "recording_not_found")
		_, err = f.put(uuid.NewString(), seal(t, sealer, recordingID, false, "unknown session"))
		wantReason(t, err, connect.CodeNotFound, "recording_not_found")
		if got := f.get(t, session.GetId()); got.GetState() == adminv1.AssistanceState_ASSISTANCE_STATE_ENDED {
			t.Fatalf("optional recording failure ended the session: %v", got)
		}
	})
}

func TestAssistanceRecordingStorageQuotaAndStallFailClosed(t *testing.T) {
	t.Run("quota", func(t *testing.T) {
		f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
		f.svc.RecordingStorage = 16
		session := f.createTier2(t, recordingGrant(tier2On))
		_, directive := f.consent(t, session, recordingGrant(tier2On))
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		_, err := f.put(session.GetId(), seal(t, f.sealer(t, directive), recordingID, false, "exceeds deployment storage"))
		wantReason(t, err, connect.CodeResourceExhausted, "recording_storage_full")
		got := f.get(t, session.GetId())
		if got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED || got.GetEndDetail() != "recording_storage_failed" || got.GetRecording().GetReason() != "recording_storage_full" {
			t.Fatalf("storage failure left required recording running: %v", got)
		}
	})
	t.Run("stall", func(t *testing.T) {
		f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
		session := f.createTier2(t, recordingGrant(tier2On))
		f.consent(t, session, recordingGrant(tier2On))
		// Shorten the recording's own timeline; fresh operator authority is
		// observed from real time and must not be what ends the session.
		if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_recordings SET started_at=$2 WHERE session_id=$1", session.GetId(), f.now.Add(-assistanceRecordingStall)); err != nil {
			t.Fatal(err)
		}
		got := f.get(t, session.GetId())
		if got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED || got.GetEndDetail() != "recording_stalled" {
			t.Fatalf("stalled required recording continued: %v", got)
		}
	})
}

func TestAssistanceRecordingDeletionAndRetention(t *testing.T) {
	f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
	session := f.createTier2(t, recordingGrant(tier2Limited))
	_, directive := f.consent(t, session, recordingGrant(tier2Limited))
	recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
	deleter := f.archiveCtx(t, "archive-deleter", identity.PermissionDeleteAssistanceRecordings)
	remove := &adminv1.DeleteAssistanceRecordingRequest{RequestId: uuid.NewString(), RecordingId: recordingID, Reason: "privacy request"}
	_, err := f.svc.DeleteAssistanceRecording(deleter, connect.NewRequest(remove))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_recording_active")
	sealer := f.sealer(t, directive)
	if _, err := f.put(session.GetId(), seal(t, sealer, recordingID, true, "only segment")); err != nil {
		t.Fatal(err)
	}
	reader := f.archiveCtx(t, "archive-reader", identity.PermissionReadAssistanceRecordings)
	if _, err := f.svc.DeleteAssistanceRecording(reader, connect.NewRequest(remove)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("retrieval grant deleted a recording: %v", err)
	}
	deleted, err := f.svc.DeleteAssistanceRecording(deleter, connect.NewRequest(remove))
	if err != nil || deleted.Msg.GetRecording().GetState() != adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_DELETED {
		t.Fatalf("delete: %v %v", deleted, err)
	}
	if replay, err := f.svc.DeleteAssistanceRecording(deleter, connect.NewRequest(remove)); err != nil || replay.Msg.GetRecording().GetId() != recordingID {
		t.Fatalf("idempotent delete: %v", err)
	}
	var segments int
	var key []byte
	if err := f.conn.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM assistance_recording_segments WHERE recording_id=$1), (SELECT encapsulated_key FROM assistance_recordings WHERE id=$1)", recordingID).Scan(&segments, &key); err != nil || segments != 0 || key != nil {
		t.Fatalf("deleted recording retained content or key: %d %d %v", segments, len(key), err)
	}
	_, err = f.svc.OpenAssistanceRecording(reader, connect.NewRequest(&adminv1.OpenAssistanceRecordingRequest{RecordingId: recordingID, Reason: "after deletion"}))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_recording_unavailable")

	// Retention removes an expired archive and audits it.
	second := f.createTier2Retained(t)
	if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_recordings SET retain_until=$2 WHERE id=$1", second, f.now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.MaintainAssistance(f.ctx); err != nil {
		t.Fatal(err)
	}
	var state int16
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM assistance_recordings WHERE id=$1", second).Scan(&state); err != nil || state != recordingDeleted {
		t.Fatalf("retention state = %d %v", state, err)
	}
	if actions, _ := f.recordingAudit(t, second); !slices.Contains(actions, "assistance.recording.retention") {
		t.Fatalf("retention not audited: %v", actions)
	}
}

// createTier2Retained ends the current session and records one complete
// archive in a fresh session.
func (f *tier2Fixture) createTier2Retained(t *testing.T) string {
	t.Helper()
	for _, session := range f.listOpen(t) {
		if _, err := f.svc.StopAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: session})); err != nil {
			t.Fatal(err)
		}
	}
	session := f.createTier2(t, recordingGrant(tier2Limited))
	_, directive := f.consent(t, session, recordingGrant(tier2Limited))
	recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
	if _, err := f.put(session.GetId(), seal(t, f.sealer(t, directive), recordingID, true, "retained")); err != nil {
		t.Fatal(err)
	}
	return recordingID
}

func (f *tier2Fixture) listOpen(t *testing.T) []string {
	t.Helper()
	rows, err := f.conn.Query(f.ctx, "SELECT id::text FROM assistance_sessions WHERE state <> 6")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func reconnectGrant(mode agentv1.AssistancePolicyMode) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{Reconnect: mode, ReconnectLimits: &agentv1.AssistanceReconnectPolicy{WindowSeconds: 900, MaxReconnects: 3}}
}

// approvedWorkflow consents to a reconnect-enabled session and ends it by
// logout, leaving its workflow waiting.
func (f *tier2Fixture) approvedWorkflow(t *testing.T, mode agentv1.AssistancePolicyMode) *adminv1.AssistanceSession {
	t.Helper()
	session := f.createTier2(t, reconnectGrant(mode))
	if session.GetReconnect().GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ACTIVE {
		t.Fatalf("workflow not created: %v", session.GetReconnect())
	}
	f.consent(t, session, reconnectGrant(mode))
	f.sync(t, ended(session.GetId(), agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED))
	got := f.get(t, session.GetId())
	if got.GetReconnect().GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_WAITING || got.GetReconnect().GetExpiresAt() == nil {
		t.Fatalf("logout did not leave the workflow waiting: %v", got.GetReconnect())
	}
	return got
}

func (f *tier2Fixture) reconnect(ctx context.Context, sessionID string) (*adminv1.AssistanceSession, error) {
	response, err := f.svc.ReconnectAssistanceSession(ctx, connect.NewRequest(&adminv1.ReconnectAssistanceSessionRequest{RequestId: uuid.NewString(), SessionId: sessionID}))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetSession(), nil
}

func TestAssistanceLimitedReconnectNeedsOperatorAndFreshConsent(t *testing.T) {
	f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
	previous := f.approvedWorkflow(t, tier2Limited)
	if directives := f.sync(t); len(directives) != 0 {
		t.Fatalf("LIMITED workflow re-invited automatically: %v", directives)
	}
	_, err := f.reconnect(f.otherCtx, previous.GetId())
	wantReason(t, err, connect.CodePermissionDenied, "assistance_not_creator")
	next, err := f.reconnect(f.creatorCtx, previous.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if next.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_REQUESTED || next.GetReconnectOf() != previous.GetId() || next.GetTargetUsername() != "alice" || next.GetConsentedAt() != nil {
		t.Fatalf("reconnect invitation = %v", next)
	}
	var invitation *agentv1.AssistanceInvitation
	for _, directive := range f.sync(t) {
		if directive.GetInvitation().GetSessionId() == next.GetId() {
			invitation = directive.GetInvitation()
		}
	}
	if invitation.GetReconnectOf() != previous.GetId() || invitation.GetTargetUsername() != "alice" {
		t.Fatalf("device invitation lacks fresh-consent linkage: %v", invitation)
	}
	f.consent(t, next, reconnectGrant(tier2Limited))
	var consentAudits int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action='assistance.reconnect.consent' AND resource_id=$1", next.GetReconnect().GetId()).Scan(&consentAudits); err != nil || consentAudits != 1 {
		t.Fatalf("reconnect consent audited %d times: %v", consentAudits, err)
	}
	if _, err := f.reconnect(f.creatorCtx, previous.GetId()); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("superseded session reconnected twice: %v", err)
	}
}

func TestAssistanceReconnectRefusalsEndOrExpireTheWorkflow(t *testing.T) {
	t.Run("declined", func(t *testing.T) {
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		session := f.createTier2(t, reconnectGrant(tier2Limited))
		f.consent(t, session, reconnectGrant(tier2Limited))
		f.sync(t, ended(session.GetId(), agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED))
		if got := f.get(t, session.GetId()).GetReconnect(); got.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ENDED || got.GetEndReason() != "user_stopped" {
			t.Fatalf("local stop left workflow resumable: %v", got)
		}
		_, err := f.reconnect(f.creatorCtx, session.GetId())
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_reconnect_not_waiting")
	})
	t.Run("never approved", func(t *testing.T) {
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		session := f.createTier2(t, reconnectGrant(tier2Limited))
		f.sync(t, ended(session.GetId(), agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED))
		if got := f.get(t, session.GetId()).GetReconnect(); got.GetEndReason() != "not_approved" {
			t.Fatalf("unapproved workflow = %v", got)
		}
	})
	t.Run("device withheld", func(t *testing.T) {
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		session := f.createTier2(t, reconnectGrant(tier2Limited))
		f.consent(t, session, &agentv1.AssistancePolicy{})
		if got := f.get(t, session.GetId()).GetReconnect(); got.GetEndReason() != "not_granted" {
			t.Fatalf("workflow remembered without the device grant: %v", got)
		}
	})
	t.Run("expired", func(t *testing.T) {
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		previous := f.approvedWorkflow(t, tier2Limited)
		if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_reconnect_workflows SET expires_at=$2 WHERE id=$1", previous.GetReconnect().GetId(), f.now); err != nil {
			t.Fatal(err)
		}
		_, err := f.reconnect(f.creatorCtx, previous.GetId())
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_reconnect_expired")
		if got := f.get(t, previous.GetId()).GetReconnect(); got.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_EXPIRED {
			t.Fatalf("expired workflow = %v", got)
		}
	})
	t.Run("expired by maintenance first", func(t *testing.T) {
		// The maintenance job expires the workflow before the operator asks;
		// the refusal still names expiry (layers-ubuntu24-reconnect-11).
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		previous := f.approvedWorkflow(t, tier2Limited)
		if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_reconnect_workflows SET expires_at=$2 WHERE id=$1", previous.GetReconnect().GetId(), f.now); err != nil {
			t.Fatal(err)
		}
		if err := f.svc.MaintainAssistance(f.ctx); err != nil {
			t.Fatal(err)
		}
		if got := f.get(t, previous.GetId()).GetReconnect(); got.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_EXPIRED {
			t.Fatalf("maintenance did not expire the workflow: %v", got)
		}
		_, err := f.reconnect(f.creatorCtx, previous.GetId())
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_reconnect_expired")
	})
	t.Run("elapsed window reads as expired", func(t *testing.T) {
		// Before anything records the expiry, a read already reports it so the
		// console offers no reconnect (layers-fedora44-reconnect-14).
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		previous := f.approvedWorkflow(t, tier2Limited)
		if got := f.get(t, previous.GetId()).GetReconnect(); got.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_WAITING {
			t.Fatalf("open window not waiting: %v", got)
		}
		if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_reconnect_workflows SET expires_at=$2 WHERE id=$1", previous.GetReconnect().GetId(), f.now); err != nil {
			t.Fatal(err)
		}
		if got := f.get(t, previous.GetId()).GetReconnect(); got.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_EXPIRED || got.GetEndReason() != "window_elapsed" {
			t.Fatalf("elapsed window still offered: %v", got)
		}
	})
	t.Run("policy revoked", func(t *testing.T) {
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		previous := f.approvedWorkflow(t, tier2Limited)
		owner := f.ownerCtx
		if _, err := f.svc.UpdateAssistancePolicy(owner, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: &agentv1.AssistancePolicy{}})); err != nil {
			t.Fatal(err)
		}
		if got := f.get(t, previous.GetId()).GetReconnect(); got.GetEndReason() != "policy_changed" {
			t.Fatalf("policy revocation left workflow waiting: %v", got)
		}
		_, err := f.reconnect(f.creatorCtx, previous.GetId())
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_reconnect_not_waiting")
	})
	t.Run("operator revoked", func(t *testing.T) {
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		previous := f.approvedWorkflow(t, tier2Limited)
		setAssistanceRole(t, f.assistanceFixture, "view-only")
		if _, err := f.reconnect(f.creatorCtx, previous.GetId()); err == nil {
			t.Fatal("operator without remote_assistance.reconnect resumed the workflow")
		}
		if got := f.get(t, previous.GetId()).GetReconnect(); got.GetEndReason() != "operator_scope_lost" {
			t.Fatalf("revoked operator left workflow waiting: %v", got)
		}
	})
	t.Run("exhausted", func(t *testing.T) {
		f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2Limited, tier2Off))
		previous := f.approvedWorkflow(t, tier2Limited)
		if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_reconnect_workflows SET reconnects=max_reconnects WHERE id=$1", previous.GetReconnect().GetId()); err != nil {
			t.Fatal(err)
		}
		_, err := f.reconnect(f.creatorCtx, previous.GetId())
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_reconnect_exhausted")
	})
}

func TestAssistanceOnReconnectReinvitesAutomaticallyWithoutReusingConsent(t *testing.T) {
	f := newTier2Fixture(t, "tier2", testWorkflowPolicy(tier2On, tier2Off))
	previous := f.approvedWorkflow(t, tier2On)
	var next *agentv1.AssistanceInvitation
	for _, directive := range f.sync(t) {
		if directive.GetInvitation().GetReconnectOf() == previous.GetId() && !directive.GetTerminate() {
			next = directive.GetInvitation()
		}
	}
	if next == nil || next.GetTargetUsername() != "alice" {
		t.Fatalf("ON workflow did not remember the approved workflow: %v", next)
	}
	state := f.get(t, next.GetSessionId())
	if state.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_REQUESTED || state.GetConsentedAt() != nil || state.GetOfferFingerprint() != "" {
		t.Fatalf("automatic reconnect reused consent or media identity: %v", state)
	}
	// Nobody is signed in yet: the attempt is refunded and paced, not re-prompted.
	f.sync(t, ended(next.GetSessionId(), agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION))
	workflow := f.get(t, next.GetSessionId()).GetReconnect()
	if workflow.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_WAITING || workflow.GetReconnects() != 0 {
		t.Fatalf("absent user consumed the workflow: %v", workflow)
	}
	for _, directive := range f.sync(t) {
		if !directive.GetTerminate() {
			t.Fatalf("paced workflow re-invited immediately: %v", directive)
		}
	}
	if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_reconnect_workflows SET next_attempt_at=$2 WHERE id=$1", workflow.GetId(), f.now); err != nil {
		t.Fatal(err)
	}
	// Another account signs in: the invitation targets only alice and bob's
	// report ends it without a prompt.
	var again string
	for _, directive := range f.sync(t) {
		if !directive.GetTerminate() {
			again = directive.GetInvitation().GetSessionId()
		}
	}
	bob := report(again, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, &agentv1.AssistanceLocalSession{Username: "bob", Uid: 1001, LogindSessionId: "9", SessionType: "wayland"}, "")
	f.sync(t, bob)
	if got := f.get(t, again); got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION || got.GetLocalSession() != nil {
		t.Fatalf("changed user was prompted: %v", got)
	}
	// Revoked operator authority ends the remembered workflow.
	if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_reconnect_workflows SET next_attempt_at=$2 WHERE id=$1", workflow.GetId(), f.now); err != nil {
		t.Fatal(err)
	}
	setAssistanceRole(t, f.assistanceFixture, "view-only")
	for _, directive := range f.sync(t) {
		if !directive.GetTerminate() {
			t.Fatalf("revoked operator's workflow re-invited: %v", directive)
		}
	}
	if got := f.get(t, again).GetReconnect(); got.GetState() != adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ENDED || got.GetEndReason() != "operator_scope_lost" {
		t.Fatalf("revoked operator workflow = %v", got)
	}
	var requests int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action='assistance.reconnect.request' AND resource_id=$1 AND details->>'automatic'='true'", workflow.GetId()).Scan(&requests); err != nil || requests != 2 {
		t.Fatalf("automatic reconnect requests audited %d times: %v", requests, err)
	}
}

// The device relays sealed segments independently of the consent sync, so
// the first segment can reach the server first (layers-fedora44-tier2-08). It
// is retried, not refused, and stored once the recording starts.
func TestAssistanceRecordingSegmentBeforeConsentSyncIsRetried(t *testing.T) {
	f := newTier2Fixture(t, "view-record", testWorkflowPolicy(tier2Off, tier2On))
	session := f.createTier2(t, recordingGrant(tier2On))
	var invitation *agentv1.AssistanceDirective
	for _, directive := range f.sync(t) {
		if directive.GetInvitation().GetSessionId() == session.GetId() {
			invitation = directive
		}
	}
	if invitation.GetInvitation().GetRecording() == nil {
		t.Fatalf("invitation lacks its recording authority: %v", invitation)
	}
	sealer := f.sealer(t, invitation)
	first := seal(t, sealer, session.GetRecording().GetId(), false, "early segment")
	_, err := f.put(session.GetId(), first)
	wantReason(t, err, connect.CodeUnavailable, "recording_not_started")
	if got := f.get(t, session.GetId()); got.GetState() == adminv1.AssistanceState_ASSISTANCE_STATE_ENDED || got.GetRecording().GetSegments() != 0 {
		t.Fatalf("an early segment ended the session or was stored: %v", got)
	}
	f.consent(t, session, recordingGrant(tier2On))
	stored, err := f.put(session.GetId(), first)
	if err != nil || stored.GetStoredThrough() != 0 {
		t.Fatalf("retried segment after consent: %v %v", stored, err)
	}
}
