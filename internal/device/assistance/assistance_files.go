// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancefiles"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
)

const assistanceFileLifetime = 5 * time.Minute

func (s *Service) assistanceFileBusy(ctx context.Context, q *devicedb.Queries, sessionID uuid.UUID, now time.Time) (bool, error) {
	file, err := q.GetActiveAssistanceFileTransfer(ctx, sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := s.enforceAssistanceFile(ctx, q, &file, now); err != nil {
		return false, err
	}
	return file.State < int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED), nil
}

func assistanceFileMetadata(file *agentv1.AssistanceFileMetadata) *agentv1.AssistanceFileMetadata {
	if file == nil {
		return nil
	}
	// Explicit fields prevent unknown protobuf fields becoming a persistence
	// channel for content or source paths.
	return &agentv1.AssistanceFileMetadata{Name: file.GetName(), Size: file.GetSize(), Sha256: file.GetSha256(), MimeType: file.GetMimeType()}
}

func assistanceFilePolicy(row devicedb.AssistanceSession, direction agentv1.AssistanceFileDirection) *agentv1.AssistanceFilePolicy {
	policy := intersectAssistancePolicy(decodeAssistancePolicy(row.EffectiveCapabilities), assistanceProjection(row).GetGrantedCapabilities().GetPolicy())
	if policy.GetFiles() < agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || direction == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER && policy.GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		return nil
	}
	return policy.GetFileLimits()
}

func assistanceFileRequest(operation devicedb.AssistanceFileTransfer) (*agentv1.AssistanceFileRequest, error) {
	request := &agentv1.AssistanceFileRequest{}
	if err := proto.Unmarshal(operation.RequestMetadata, request); err != nil {
		return nil, err
	}
	return request, nil
}

func assistanceFileReport(operation devicedb.AssistanceFileTransfer) (*agentv1.AssistanceFileReport, error) {
	report := &agentv1.AssistanceFileReport{}
	if err := proto.Unmarshal(operation.Report, report); err != nil {
		return nil, err
	}
	return report, nil
}

// The audit whitelist intentionally omits the basename as well as source paths,
// request digests and content. Machine reasons never enter top-level reason.
func recordAssistanceFileAudit(ctx context.Context, q *devicedb.Queries, operation devicedb.AssistanceFileTransfer, action auditkind.Kind, reason string) error {
	request, err := assistanceFileRequest(operation)
	if err != nil {
		return err
	}
	report, err := assistanceFileReport(operation)
	if err != nil {
		return err
	}
	if reason == "" {
		reason = "file_" + strings.ToLower(strings.TrimPrefix(report.GetState().String(), "ASSISTANCE_FILE_STATE_"))
	}
	file := report.GetFile()
	if file == nil {
		file = request.GetFile()
	}
	authorizedDigest := hex.EncodeToString(request.GetFile().GetSha256())
	digest, digestOrigin := authorizedDigest, "authorized_request"
	if report.GetFile() != nil {
		digestOrigin = "receiver_verified"
		if request.GetFile() == nil {
			digest = hex.EncodeToString(report.GetFile().GetSha256())
		}
	}
	direction := "operator_to_user"
	if operation.Direction == int16(agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER) {
		direction = "user_to_operator"
	}
	return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: &operation.OperatorID, Action: action.String(), ResourceID: operation.SessionID.String(), TargetDeviceID: &operation.DeviceID,
	}, core.AuditDetails("request", operation.RequestID.String(), "direction", direction,
		"bytes", strconv.FormatInt(operation.BytesTransferred, 10), "reserved_bytes", strconv.FormatInt(operation.ReservedBytes, 10),
		"sha256", digest, "sha256_origin", digestOrigin, "authorized_sha256", authorizedDigest, "mime_type", file.GetMimeType(),
		"max_file_bytes", strconv.FormatUint(request.GetPolicy().GetMaxFileBytes(), 10),
		"max_session_bytes", strconv.FormatUint(request.GetPolicy().GetMaxSessionBytes(), 10),
		"allowed_mime_types", strings.Join(request.GetPolicy().GetAllowedMimeTypes(), ","),
		"allowed_extensions", strings.Join(request.GetPolicy().GetAllowedExtensions(), ","),
		"result", strings.ToLower(strings.TrimPrefix(report.GetState().String(), "ASSISTANCE_FILE_STATE_")), "reason", reason))
}

func saveAssistanceFileReport(ctx context.Context, q *devicedb.Queries, operation *devicedb.AssistanceFileTransfer, report *agentv1.AssistanceFileReport, now time.Time) error {
	if operation.State >= int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED) {
		return nil
	}
	report = &agentv1.AssistanceFileReport{RequestId: report.GetRequestId(), Direction: report.GetDirection(), State: report.GetState(), BytesTransferred: report.GetBytesTransferred(), File: assistanceFileMetadata(report.GetFile()), Reason: report.GetReason()}
	if report.GetState() >= agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		report.CompletedAt = timestamppb.New(now)
		operation.CompletedAt = core.Timestamptz(now)
	}
	data, err := proto.Marshal(report)
	if err != nil {
		return err
	}
	if err := q.UpdateAssistanceFileTransfer(ctx, devicedb.UpdateAssistanceFileTransferParams{RequestID: operation.RequestID, State: int16(report.GetState()), Report: data, BytesTransferred: int64(report.GetBytesTransferred()), CompletedAt: operation.CompletedAt}); err != nil {
		return err
	}
	operation.State, operation.Report, operation.BytesTransferred = int16(report.GetState()), data, int64(report.GetBytesTransferred())
	if report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		operation.ReservedBytes = operation.BytesTransferred
	}
	if report.GetState() < agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		return nil
	}
	action := auditkind.AssistanceFileDeny
	switch report.GetState() {
	case agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED:
		action = auditkind.AssistanceFileComplete
	case agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED:
		action = auditkind.AssistanceFileCancel
	}
	return recordAssistanceFileAudit(ctx, q, *operation, action, report.GetReason())
}

func stopAssistanceFile(ctx context.Context, q *devicedb.Queries, operation *devicedb.AssistanceFileTransfer, now time.Time, reason string) error {
	return saveAssistanceFileReport(ctx, q, operation, &agentv1.AssistanceFileReport{RequestId: operation.RequestID.String(), Direction: agentv1.AssistanceFileDirection(operation.Direction), State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED, BytesTransferred: uint64(operation.BytesTransferred), Reason: reason}, now)
}

func cancelAssistanceFile(ctx context.Context, q *devicedb.Queries, sessionID uuid.UUID, now time.Time, reason string) error {
	operation, err := q.GetActiveAssistanceFileTransfer(ctx, sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return stopAssistanceFile(ctx, q, &operation, now, reason)
}

// A durable operation is never re-executed by another process incarnation. The
// original executor may have published a file before its receipt was lost.
func (s *Service) enforceAssistanceFile(ctx context.Context, q *devicedb.Queries, operation *devicedb.AssistanceFileTransfer, now time.Time) error {
	if operation.State >= int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED) {
		return nil
	}
	if !now.Before(operation.Deadline.Time) {
		return stopAssistanceFile(ctx, q, operation, now, "file_deadline")
	}
	if operation.OwnerInstance != s.runtime.assistanceInstance {
		return stopAssistanceFile(ctx, q, operation, now, "file_outcome_unknown")
	}
	return nil
}

func (s *Service) fileForAssistance(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, now time.Time) (*agentv1.AssistanceFileDirective, error) {
	if row.State != assistanceActive {
		return nil, nil
	}
	operation, err := q.GetLatestAssistanceFileTransfer(ctx, row.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.enforceAssistanceFile(ctx, q, &operation, now); err != nil {
		return nil, err
	}
	request, err := assistanceFileRequest(operation)
	if err != nil {
		return nil, err
	}
	// Complete desired state also withdraws a chooser/stream after cancellation
	// or an unknown outcome. It never reissues terminal operations as live work.
	return &agentv1.AssistanceFileDirective{Request: request, Cancel: operation.State >= int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED)}, nil
}

func (s *Service) applyAssistanceFileReport(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, report *agentv1.AssistanceFileReport, now time.Time) error {
	if report == nil {
		return nil
	}
	id, _ := uuid.Parse(report.GetRequestId())
	operation, err := q.GetAssistanceFileTransfer(ctx, id)
	if err != nil {
		return err
	}
	if operation.SessionID != row.ID || operation.DeviceID != row.DeviceID || operation.OperatorID != row.OperatorID || operation.Direction != int16(report.GetDirection()) || row.State != assistanceActive {
		return core.Invalid("assistance_file_report_identity")
	}
	if err := s.enforceAssistanceFile(ctx, q, &operation, now); err != nil {
		return err
	}
	if operation.State >= int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED) {
		// Late success cannot override cancellation, revocation or deadline.
		return nil
	}
	request, err := assistanceFileRequest(operation)
	if err != nil {
		return err
	}
	if report.GetBytesTransferred() < uint64(operation.BytesTransferred) || report.GetBytesTransferred() > uint64(operation.ReservedBytes) || int16(report.GetState()) < operation.State {
		return core.Invalid("assistance_file_report_progress")
	}
	if report.GetState() <= agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT && report.GetBytesTransferred() != 0 {
		return core.Invalid("assistance_file_before_consent")
	}
	// A valid publication warning was already processed by the narrow receipt
	// path before lifecycle handling. Unverified claims cannot use this reason.
	if report.GetReason() == "file_published_unconfirmed" {
		return core.Invalid("assistance_file_publication_invalid")
	}
	if report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED && report.GetFile() != nil {
		return core.Invalid("assistance_file_unverified_metadata")
	}
	if report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		file := report.GetFile()
		if report.GetBytesTransferred() != file.GetSize() || !assistancefiles.MetadataAllowed(request.GetPolicy(), file, true) || !assistancefiles.MetadataAllowed(assistanceFilePolicy(row, report.GetDirection()), file, true) {
			return core.Invalid("assistance_file_receipt_invalid")
		}
		if report.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER && !proto.Equal(request.GetFile(), file) {
			return core.Invalid("assistance_file_receipt_mismatch")
		}
	}
	return saveAssistanceFileReport(ctx, q, &operation, report, now)
}

// Publication can precede a failed notification/receipt while cancellation or
// session termination is racing the device report. Preserve that bounded,
// receiver-verified warning without reopening authority or accepting late success.
func recordAssistanceFilePublicationFailure(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, report *agentv1.AssistanceFileReport, now time.Time) error {
	if report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED || report.GetReason() != "file_published_unconfirmed" || report.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER || report.GetFile() == nil {
		return nil
	}
	if row.State == assistanceEnded && (!row.EndedAt.Valid || now.Sub(row.EndedAt.Time) > assistanceEndedDelivery) {
		return nil
	}
	id, err := uuid.Parse(report.GetRequestId())
	if err != nil {
		return nil
	}
	operation, err := q.GetAssistanceFileTransfer(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if operation.SessionID != row.ID || operation.DeviceID != row.DeviceID || operation.OperatorID != row.OperatorID || operation.Direction != int16(report.GetDirection()) || operation.State == int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED) || operation.State == int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED) || operation.State == int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED) {
		return nil
	}
	request, err := assistanceFileRequest(operation)
	if err != nil {
		return err
	}
	if !proto.Equal(request.GetFile(), report.GetFile()) || len(report.GetFile().GetSha256()) != 32 || report.GetBytesTransferred() != request.GetFile().GetSize() || report.GetBytesTransferred() > uint64(operation.ReservedBytes) {
		return nil
	}
	warning := &agentv1.AssistanceFileReport{RequestId: operation.RequestID.String(), Direction: report.GetDirection(), State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, BytesTransferred: report.GetBytesTransferred(), File: assistanceFileMetadata(report.GetFile()), Reason: "file_published_unconfirmed", CompletedAt: timestamppb.New(now)}
	data, err := proto.Marshal(warning)
	if err != nil {
		return err
	}
	if err := q.RecordAssistanceFilePublicationFailure(ctx, devicedb.RecordAssistanceFilePublicationFailureParams{RequestID: operation.RequestID, Report: data, BytesTransferred: int64(warning.GetBytesTransferred()), CompletedAt: core.Timestamptz(now)}); err != nil {
		return err
	}
	operation.State, operation.Report, operation.BytesTransferred = int16(warning.GetState()), data, int64(warning.GetBytesTransferred())
	return recordAssistanceFileAudit(ctx, q, operation, auditkind.AssistanceFileDeny, warning.GetReason())
}
