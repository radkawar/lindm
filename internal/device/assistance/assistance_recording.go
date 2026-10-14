// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
)

var errRecordingKeyUnavailable = errors.New("recording_key_unavailable")

// Recording contract (docs/architecture.md "Encrypted support recording").
// The server stores helper-sealed segments exactly as received. It derives a
// recording key only inside an authorized retrieval and never stores plaintext.
const (
	recordingPending    = int16(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_PENDING)
	recordingActive     = int16(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_RECORDING)
	recordingComplete   = int16(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_COMPLETE)
	recordingIncomplete = int16(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_INCOMPLETE)
	recordingFailed     = int16(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_FAILED)
	recordingDeclined   = int16(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_DECLINED)
	recordingDeleted    = int16(adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_DELETED)

	// Segments already sealed before a session ended may still arrive.
	assistanceRecordingGrace = time.Minute
	// Required recording without a durable segment for this long ends the
	// session: it never continues unrecorded.
	assistanceRecordingStall = 30 * time.Second
)

func recordingStateName(state int16) string {
	switch state {
	case recordingPending:
		return "pending"
	case recordingActive:
		return "recording"
	case recordingComplete:
		return "complete"
	case recordingIncomplete:
		return "incomplete"
	case recordingFailed:
		return "failed"
	case recordingDeclined:
		return "declined"
	case recordingDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

func assistanceRecordingMessage(row devicedb.AssistanceRecording) *adminv1.AssistanceRecording {
	message := &adminv1.AssistanceRecording{
		Id: row.ID.String(), SessionId: row.SessionID.String(), DeviceId: row.DeviceID.String(), OperatorId: row.OperatorID.String(),
		Required: row.Required, State: adminv1.AssistanceRecordingArchiveState(row.State), StoredBytes: uint64(row.StoredBytes),
		Segments: uint32(row.Segments), CreatedAt: core.ProtoTime(row.CreatedAt), StartedAt: core.ProtoTime(row.StartedAt),
		FinalizedAt: core.ProtoTime(row.FinalizedAt), RetainUntil: core.ProtoTime(row.RetainUntil), DeletedAt: core.ProtoTime(row.DeletedAt),
		DurationSeconds: recordingDuration(row), Reason: row.Reason, KeyId: row.KeyID, RetentionDays: uint32(row.RetentionDays), MaxBytes: uint64(row.MaxBytes),
	}
	if len(row.CiphertextSha256) == sha256.Size {
		message.CiphertextSha256 = hex.EncodeToString(row.CiphertextSha256)
	}
	return message
}

func recordingDuration(row devicedb.AssistanceRecording) uint32 {
	if !row.StartedAt.Valid {
		return 0
	}
	end := row.LastSegmentAt
	if !end.Valid {
		return 0
	}
	return uint32(max(0, end.Time.Sub(row.StartedAt.Time)/time.Second))
}

func updateAssistanceRecording(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceRecording) error {
	return q.UpdateAssistanceRecording(ctx, devicedb.UpdateAssistanceRecordingParams{
		ID: row.ID, State: row.State, EncapsulatedKey: row.EncapsulatedKey, Segments: row.Segments, StoredBytes: row.StoredBytes,
		HashState: row.HashState, CiphertextSha256: row.CiphertextSha256, StartedAt: row.StartedAt, LastSegmentAt: row.LastSegmentAt,
		FinalizedAt: row.FinalizedAt, RetainUntil: row.RetainUntil, DeletedAt: row.DeletedAt, Reason: row.Reason,
	})
}

// recordAssistanceRecordingAudit records object identity, digest, duration,
// size and outcome. Keys, plaintext and segment content never enter audit.
func recordAssistanceRecordingAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, row devicedb.AssistanceRecording, outcome, reason string, pairs ...string) error {
	return recordAssistanceRecordingAccess(ctx, q, actor, action, row, outcome, reason, "", pairs...)
}

// recordAssistanceRecordingAccess separates the operator-authored reason of a
// retrieval or deletion from server context.
func recordAssistanceRecordingAccess(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, row devicedb.AssistanceRecording, outcome, reason, operatorReason string, pairs ...string) error {
	digest := ""
	if len(row.CiphertextSha256) == sha256.Size {
		digest = hex.EncodeToString(row.CiphertextSha256)
	}
	details := core.AuditDetails(append([]string{
		"recording", row.ID.String(), "session", row.SessionID.String(), "operator", row.OperatorID.String(),
		"required", boolText(row.Required), "state", recordingStateName(row.State), "result", outcome, "reason", reason,
		"ciphertext_sha256", digest, "duration_seconds", strconv.FormatUint(uint64(recordingDuration(row)), 10),
		"bytes", strconv.FormatInt(row.StoredBytes, 10), "segments", strconv.Itoa(int(row.Segments)), "key", row.KeyID,
		"retention_days", strconv.Itoa(int(row.RetentionDays)),
	}, pairs...)...)
	return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: row.ID.String(), Reason: operatorReason, TargetDeviceID: &row.DeviceID,
	}, details)
}

// finalizeAssistanceRecording closes capture. A final authenticated segment
// makes it complete; a stored prefix without one is retained as incomplete.
func finalizeAssistanceRecording(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceRecording, now time.Time, complete bool, reason string) error {
	if row.State != recordingPending && row.State != recordingActive {
		return nil
	}
	switch {
	case complete:
		row.State = recordingComplete
	case row.Segments > 0:
		row.State = recordingIncomplete
	default:
		row.State = recordingFailed
	}
	row.FinalizedAt, row.Reason = core.Timestamptz(now), reason
	if row.State != recordingFailed {
		digest, err := recordingDigest(row.HashState)
		if err != nil {
			return err
		}
		row.CiphertextSha256 = digest
		row.RetainUntil = core.Timestamptz(now.Add(time.Duration(row.RetentionDays) * 24 * time.Hour))
	}
	// The running hash state is NOT NULL; finalized rows keep only the digest.
	row.HashState = []byte{}
	if err := updateAssistanceRecording(ctx, q, *row); err != nil {
		return err
	}
	return recordAssistanceRecordingAudit(ctx, q, nil, auditkind.AssistanceRecordingStop, *row, recordingStateName(row.State), reason)
}

type recordingHasher interface {
	hash.Hash
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// recordingHash resumes the running SHA-256 of a recording's ciphertext.
func recordingHash(state []byte) (recordingHasher, error) {
	h, ok := sha256.New().(recordingHasher)
	if !ok {
		return nil, errors.New("assistance: sha256 state is not serializable")
	}
	if len(state) > 0 {
		if err := h.UnmarshalBinary(state); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func recordingDigest(state []byte) ([]byte, error) {
	h, err := recordingHash(state)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// startAssistanceRecording applies the local recording decision observed
// with consent. It returns a non-empty end detail when required recording was
// not granted, so the session ends instead of continuing unrecorded.
func startAssistanceRecording(ctx context.Context, q *devicedb.Queries, session devicedb.AssistanceSession, grant *agentv1.AssistancePolicy, now time.Time) (string, error) {
	row, err := q.LockAssistanceRecordingBySession(ctx, session.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if row.State != recordingPending {
		return "", nil
	}
	if policyEnabled(grant.GetRecording()) {
		row.State, row.StartedAt = recordingActive, core.Timestamptz(now)
		if err := updateAssistanceRecording(ctx, q, row); err != nil {
			return "", err
		}
		return "", recordAssistanceRecordingAudit(ctx, q, nil, auditkind.AssistanceRecordingStart, row, "started", "", "max_bytes", strconv.FormatInt(row.MaxBytes, 10), "user", session.LocalUsername)
	}
	if row.Required {
		if err := finalizeAssistanceRecording(ctx, q, &row, now, false, "not_granted"); err != nil {
			return "", err
		}
		return "recording_not_granted", nil
	}
	row.State, row.FinalizedAt, row.Reason = recordingDeclined, core.Timestamptz(now), "user_declined"
	if err := updateAssistanceRecording(ctx, q, row); err != nil {
		return "", err
	}
	return "", recordAssistanceRecordingAudit(ctx, q, nil, auditkind.AssistanceRecordingStop, row, "declined", "user_declined")
}

// applyAssistanceRecordingReport applies a helper's content-free recording
// observation after consent. It returns a non-empty end detail when required
// recording can no longer continue.
func applyAssistanceRecordingReport(ctx context.Context, q *devicedb.Queries, session devicedb.AssistanceSession, report *agentv1.AssistanceRecordingReport, now time.Time) (string, error) {
	row, err := q.LockAssistanceRecordingBySession(ctx, session.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		if report != nil {
			return "recording_report_unauthorized", nil
		}
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if report == nil {
		return "", nil
	}
	if report.GetRecordingId() != row.ID.String() {
		return "recording_report_invalid", nil
	}
	if row.State != recordingActive {
		return "", nil
	}
	switch report.GetState() {
	case agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING:
		return "", nil
	case agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_FAILED:
		row.Reason = report.GetReason()
		if row.Segments == 0 {
			if err := finalizeAssistanceRecording(ctx, q, &row, now, false, report.GetReason()); err != nil {
				return "", err
			}
		} else if err := updateAssistanceRecording(ctx, q, row); err != nil {
			return "", err
		}
		if row.Required {
			return "recording_failed", nil
		}
	case agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_STOPPED:
		if row.Required {
			return "recording_stopped", nil
		}
	default:
		return "recording_report_invalid", nil
	}
	return "", nil
}

// endAssistanceRecording settles recording state when its session ends. An
// unstarted recording fails; an active one waits for its final segment.
func endAssistanceRecording(ctx context.Context, q *devicedb.Queries, session devicedb.AssistanceSession, now time.Time) error {
	row, err := q.LockAssistanceRecordingBySession(ctx, session.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if row.State == recordingPending {
		return finalizeAssistanceRecording(ctx, q, &row, now, false, "not_started")
	}
	return nil
}

// enforceAssistanceRecording ends an open session whose required recording
// stalled or stopped. It is part of the lazy deadline rules.
func enforceAssistanceRecording(ctx context.Context, q *devicedb.Queries, session *devicedb.AssistanceSession, now time.Time, revoked *assistanceRevocations) error {
	if session.State < assistanceOffered || session.State == assistanceEnded {
		return nil
	}
	if decodeAssistancePolicy(session.EffectiveCapabilities).GetRecording() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		return nil
	}
	row, err := q.GetAssistanceRecordingBySession(ctx, session.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !row.Required {
		return nil
	}
	detail := ""
	switch row.State {
	case recordingPending:
	case recordingActive:
		last := row.StartedAt.Time
		if row.LastSegmentAt.Valid && row.LastSegmentAt.Time.After(last) {
			last = row.LastSegmentAt.Time
		}
		if now.Sub(last) >= assistanceRecordingStall {
			detail = "recording_stalled"
		}
	default:
		detail = "recording_ended"
	}
	if detail == "" {
		return nil
	}
	return endAssistance(ctx, q, session, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, detail, false, revoked)
}

// assistanceRecordingAuthority is the invitation's immutable recording
// authority. It never changes while the session lives; a recording that can
// no longer be stored is refused at upload instead.
func (s *Service) assistanceRecordingAuthority(row devicedb.AssistanceRecording) (*agentv1.AssistanceRecordingAuthority, error) {
	if s.AssistanceRecording == nil || s.AssistanceRecording.KeyID() != row.KeyID {
		return nil, errRecordingKeyUnavailable
	}
	return &agentv1.AssistanceRecordingAuthority{
		RecordingId: row.ID.String(), Required: row.Required, PublicKey: s.AssistanceRecording.PublicKey(), KeyId: row.KeyID,
		MaxBytes: uint64(row.MaxBytes), RetentionDays: uint32(row.RetentionDays),
	}, nil
}

func recordingRejected(code connect.Code, reason string) error {
	return rpcreason.Error(code, reason)
}

// PutAssistanceRecording stores contiguous sealed segments from the device
// that owns the recording's session. Duplicates are accepted only when they
// are byte-identical; a gap, an oversize recording or exhausted storage is a
// final rejection that also ends a session whose recording is required.
func (s *Service) PutAssistanceRecording(ctx context.Context, req *connect.Request[devicev1.PutAssistanceRecordingRequest]) (*connect.Response[devicev1.PutAssistanceRecordingResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	principal, ok := core.DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || proto.Size(req.Msg) > core.MaxMessageBytes || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_recording")
	}
	chunks := req.Msg.GetChunks()
	for i := 1; i < len(chunks); i++ {
		if chunks[i].GetSequence() != chunks[i-1].GetSequence()+1 || chunks[i-1].GetFinal() {
			return nil, core.Invalid("invalid_assistance_recording")
		}
	}
	sessionID, _ := uuid.Parse(req.Msg.GetSessionId())
	recordingID, _ := uuid.Parse(chunks[0].GetRecordingId())
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	device, err := s.LockAuthority(ctx, q, principal)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if uint64(device.Generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, core.MapErr(core.ErrSessionFenced)
	}
	now := device.Now
	var revoked assistanceRevocations
	response, result := s.storeAssistanceRecording(ctx, q, principal.DeviceID, principal.GenerationID, sessionID, recordingID, chunks, now, &revoked)
	var domain *connect.Error
	if result != nil && !errors.As(result, &domain) {
		return nil, core.MapErr(result)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	s.revokeAssistance(revoked)
	if result != nil {
		return nil, result
	}
	return core.NoStore(response), nil
}

func (s *Service) storeAssistanceRecording(ctx context.Context, q *devicedb.Queries, deviceID, generation, sessionID, recordingID uuid.UUID, chunks []*agentv1.AssistanceRecordingChunk, now time.Time, revoked *assistanceRevocations) (*devicev1.PutAssistanceRecordingResponse, error) {
	session, err := q.LockAssistanceSessionForDevice(ctx, devicedb.LockAssistanceSessionForDeviceParams{ID: sessionID, DeviceID: deviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, recordingRejected(connect.CodeNotFound, "recording_not_found")
	}
	if err != nil {
		return nil, err
	}
	if session.GenerationID != generation {
		return nil, recordingRejected(connect.CodePermissionDenied, "recording_not_authorized")
	}
	if err := enforceAssistance(ctx, q, &session, now, revoked); err != nil {
		return nil, err
	}
	row, err := q.LockAssistanceRecordingBySession(ctx, session.ID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && row.ID != recordingID) {
		return nil, recordingRejected(connect.CodeNotFound, "recording_not_found")
	}
	if err != nil {
		return nil, err
	}
	if row.State == recordingPending && session.State != assistanceEnded {
		// The device relays sealed segments independently of the consent
		// sync that starts its recording, so the first segment can arrive
		// first (layers-fedora44-tier2-08 ended a required recording
		// recording_not_active one second after consent). The device keeps
		// the segments and retries; nothing is stored before the start.
		return nil, recordingRejected(connect.CodeUnavailable, "recording_not_started")
	}
	if row.State != recordingActive || (session.State == assistanceEnded && now.Sub(session.EndedAt.Time) >= assistanceRecordingGrace) {
		if session.State == assistanceEnded {
			if err := finalizeAssistanceRecording(ctx, q, &row, now, false, "final_segment_missing"); err != nil {
				return nil, err
			}
		}
		return nil, recordingRejected(connect.CodeFailedPrecondition, "recording_not_active")
	}
	if s.AssistanceRecording == nil || s.AssistanceRecording.KeyID() != row.KeyID {
		return nil, s.failAssistanceRecording(ctx, q, &session, &row, now, "recording_key_unavailable", revoked)
	}
	fail := func(code connect.Code, reason string) error {
		if err := s.failAssistanceRecording(ctx, q, &session, &row, now, reason, revoked); err != nil {
			return err
		}
		return recordingRejected(code, reason)
	}
	hash, err := recordingHash(row.HashState)
	if err != nil {
		return nil, err
	}
	var added int64
	for _, chunk := range chunks {
		sequence := int32(chunk.GetSequence())
		digest := sha256.Sum256(chunk.GetCiphertext())
		if sequence < row.Segments {
			old, err := q.GetAssistanceRecordingSegmentDigest(ctx, devicedb.GetAssistanceRecordingSegmentDigestParams{RecordingID: row.ID, Sequence: sequence})
			if err != nil {
				return nil, err
			}
			if old.Final != chunk.GetFinal() || !bytes.Equal(old.Digest, digest[:]) {
				return nil, fail(connect.CodeFailedPrecondition, "recording_sequence")
			}
			continue
		}
		if sequence != row.Segments {
			return nil, fail(connect.CodeFailedPrecondition, "recording_sequence")
		}
		size := int64(len(chunk.GetCiphertext()))
		if row.StoredBytes+size > row.MaxBytes {
			return nil, fail(connect.CodeResourceExhausted, "recording_size_limit")
		}
		if added == 0 {
			if err := q.LockAssistanceRecordingQuota(ctx); err != nil {
				return nil, err
			}
		}
		stored, err := q.AssistanceRecordingStoredBytes(ctx)
		if err != nil {
			return nil, err
		}
		if uint64(stored)+uint64(size) > s.RecordingStorage {
			return nil, fail(connect.CodeResourceExhausted, "recording_storage_full")
		}
		if sequence == 0 {
			row.EncapsulatedKey = append([]byte(nil), chunk.GetEncapsulatedKey()...)
		}
		if err := q.InsertAssistanceRecordingSegment(ctx, devicedb.InsertAssistanceRecordingSegmentParams{
			RecordingID: row.ID, Sequence: sequence, Final: chunk.GetFinal(), Ciphertext: chunk.GetCiphertext(), Digest: digest[:], StoredAt: core.Timestamptz(now),
		}); err != nil {
			return nil, err
		}
		if _, err := hash.Write(chunk.GetCiphertext()); err != nil {
			return nil, err
		}
		row.HashState, err = hash.MarshalBinary()
		if err != nil {
			return nil, err
		}
		row.Segments++
		row.StoredBytes += size
		row.LastSegmentAt = core.Timestamptz(now)
		added += size
		if err := updateAssistanceRecording(ctx, q, row); err != nil {
			return nil, err
		}
		if chunk.GetFinal() {
			if err := finalizeAssistanceRecording(ctx, q, &row, now, true, "final_segment"); err != nil {
				return nil, err
			}
			if row.Required && session.State != assistanceEnded {
				// Required recording ended while the session is open.
				if err := endAssistance(ctx, q, &session, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, "recording_ended", false, revoked); err != nil {
					return nil, err
				}
			}
			break
		}
	}
	return &devicev1.PutAssistanceRecordingResponse{StoredThrough: uint32(max(row.Segments-1, 0))}, nil
}

// failAssistanceRecording finalizes a recording that can no longer be stored
// and ends the session when that recording is required.
func (s *Service) failAssistanceRecording(ctx context.Context, q *devicedb.Queries, session *devicedb.AssistanceSession, row *devicedb.AssistanceRecording, now time.Time, reason string, revoked *assistanceRevocations) error {
	if err := finalizeAssistanceRecording(ctx, q, row, now, false, reason); err != nil {
		return err
	}
	if row.Required && session.State != assistanceEnded {
		return endAssistance(ctx, q, session, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, "recording_storage_failed", false, revoked)
	}
	return nil
}

// settleAssistanceRecording closes a recording whose session ended more than
// the grace ago without a final segment.
func settleAssistanceRecording(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceRecording, now time.Time) error {
	if row.State != recordingPending && row.State != recordingActive {
		return nil
	}
	session, err := q.GetAssistanceSession(ctx, row.SessionID)
	if err != nil {
		return err
	}
	if session.State != assistanceEnded || now.Sub(session.EndedAt.Time) < assistanceRecordingGrace {
		return nil
	}
	reason := row.Reason
	if reason == "" {
		reason = "final_segment_missing"
	}
	return finalizeAssistanceRecording(ctx, q, row, now, false, reason)
}

// deleteAssistanceRecordingContent destroys ciphertext, the encapsulated key
// and open retrievals, retaining only audit metadata.
func deleteAssistanceRecordingContent(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceRecording, now time.Time, reason string) error {
	if err := q.DeleteAssistanceRecordingSegments(ctx, row.ID); err != nil {
		return err
	}
	if err := q.DeleteAssistanceRecordingRetrievals(ctx, row.ID); err != nil {
		return err
	}
	if !row.FinalizedAt.Valid {
		row.FinalizedAt = core.Timestamptz(now)
	}
	row.State, row.DeletedAt, row.EncapsulatedKey, row.HashState, row.RetainUntil = recordingDeleted, core.Timestamptz(now), nil, []byte{}, pgtype.Timestamptz{}
	row.Reason = reason
	return updateAssistanceRecording(ctx, q, *row)
}
