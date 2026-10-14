// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"context"
	"errors"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// SyncAssistance exchanges the device's complete observed session state for
// the server's complete desired state. Reports only advance sessions; the
// returned directives are the device's whole authorization.
func (s *Service) SyncAssistance(ctx context.Context, req *connect.Request[devicev1.SyncAssistanceRequest]) (*connect.Response[devicev1.SyncAssistanceResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	principal, ok := core.DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || proto.Size(req.Msg) > 256<<10 || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_sync")
	}
	seen := make(map[uuid.UUID]struct{}, len(req.Msg.GetReports()))
	for _, report := range req.Msg.GetReports() {
		id, _ := uuid.Parse(report.GetSessionId())
		if _, duplicate := seen[id]; duplicate || core.HasNUL(report.GetOfferSdp()) {
			return nil, core.Invalid("invalid_assistance_sync")
		}
		seen[id] = struct{}{}
	}
	observedID, authorization, err := s.observeAssistanceAuthority(ctx, principal.DeviceID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	var reconnect assistanceReconnectObservation
	if observedID == uuid.Nil {
		reconnect, err = s.observeAssistanceReconnect(ctx, principal.DeviceID, s.Now())
		if err != nil {
			return nil, core.MapErr(err)
		}
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if authorization != nil {
		if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionViewRemoteAssistance); err != nil {
			return nil, core.ExecutionError(err)
		}
	}
	q := devicedb.New(tx)
	device, err := s.LockAuthority(ctx, q, principal)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if uint64(device.Generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, core.MapErr(core.ErrSessionFenced)
	}
	now := device.Now
	if !core.EnrollmentIssuanceResumable(device.Certificate, now) {
		return nil, core.MapErr(core.ErrCertificateRejected)
	}
	if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{ID: principal.DeviceID, LastSeenAt: core.Timestamptz(now)}); err != nil {
		return nil, core.MapErr(err)
	}
	var revoked assistanceRevocations
	// Deadlines first: a device returning after 30 s of silence must not
	// revive its session by syncing now.
	if err := enforceOpenAssistance(ctx, q, principal.DeviceID, now, &revoked); err != nil {
		return nil, core.MapErr(err)
	}
	if err := s.refreshAssistanceAuthority(ctx, q, principal.DeviceID, observedID, authorization, now, &revoked); err != nil {
		return nil, core.MapErr(err)
	}
	for _, report := range req.Msg.GetReports() {
		id, _ := uuid.Parse(report.GetSessionId())
		row, err := q.LockAssistanceSessionForDevice(ctx, devicedb.LockAssistanceSessionForDeviceParams{ID: id, DeviceID: principal.DeviceID})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, core.MapErr(err)
		}
		if err := s.applyAssistanceReport(ctx, q, &row, report, principal.GenerationID, now, &revoked); err != nil {
			return nil, core.MapErr(err)
		}
	}
	reconnected, err := s.automaticAssistanceReconnect(ctx, tx, q, reconnect, principal.GenerationID, now, &revoked)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if err := q.TouchAssistanceDeviceSync(ctx, devicedb.TouchAssistanceDeviceSyncParams{DeviceID: principal.DeviceID, SyncedAt: core.Timestamptz(now)}); err != nil {
		return nil, core.MapErr(err)
	}
	if err := recordAssistanceEnablement(ctx, q, principal.DeviceID, req.Msg.GetPolicy(), now); err != nil {
		return nil, core.MapErr(err)
	}
	response, err := s.assistanceDirectives(ctx, q, principal, now, &revoked)
	if err != nil {
		return nil, core.MapErr(err)
	}
	// Directives are the device's whole authorization; never emit one the
	// agent contract would reject.
	if err := s.Rules.Validate(response); err != nil || proto.Size(response) > 256<<10 {
		return nil, rpcreason.Error(connect.CodeInternal, "assistance_directive_invalid")
	}
	if authorization != nil {
		if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionViewRemoteAssistance); err != nil {
			return nil, core.ExecutionError(err)
		}
	}
	if reconnected {
		// The remembered workflow's operator is fenced like a creator.
		if err := s.Identity.LockAuthorization(ctx, tx, reconnect.authorization, identity.PermissionViewRemoteAssistance); err != nil {
			return nil, core.ExecutionError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	s.revokeAssistance(revoked)
	return core.NoStore(response), nil
}

// assistanceDirectives ends every open session the device may no longer hold
// and returns the desired state for the rest, including recently ended
// sessions the device has not confirmed.
func (s *Service) assistanceDirectives(ctx context.Context, q *devicedb.Queries, principal core.DevicePrincipal, now time.Time, revoked *assistanceRevocations) (*devicev1.SyncAssistanceResponse, error) {
	rows, err := q.ListAssistanceDirectiveSessions(ctx, devicedb.ListAssistanceDirectiveSessionsParams{DeviceID: principal.DeviceID, EndedAfter: core.Timestamptz(now.Add(-assistanceEndedDelivery))})
	if err != nil {
		return nil, err
	}
	response := &devicev1.SyncAssistanceResponse{}
	for i := range rows {
		row := &rows[i]
		if row.State != assistanceEnded {
			detail := ""
			switch {
			case s.Assistance == nil:
				detail = "assistance_unconfigured"
			case row.GenerationID != principal.GenerationID:
				detail = "generation_changed"
			}
			if detail != "" {
				if err := endAssistance(ctx, q, row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, detail, false, revoked); err != nil {
					return nil, err
				}
			}
		}
		if s.Assistance == nil {
			continue
		}
		if row.State == assistanceEnded {
			// Ended sessions may have ended on another path or replica; the
			// relay revocation is idempotent.
			*revoked = append(*revoked, *row)
		}
		directive, err := s.assistanceWorkDirective(ctx, q, row, now, revoked)
		if err != nil {
			return nil, err
		}
		response.Directives = append(response.Directives, directive)
	}
	return response, nil
}

func (s *Service) assistanceWorkDirective(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceSession, now time.Time, revoked *assistanceRevocations) (*agentv1.AssistanceDirective, error) {
	var authority *agentv1.AssistanceRecordingAuthority
	recording, err := q.GetAssistanceRecordingBySession(ctx, row.ID)
	switch {
	case err == nil:
		authority, err = s.assistanceRecordingAuthority(recording)
		if errors.Is(err, errRecordingKeyUnavailable) {
			// A replaced or removed deployment key cannot receive this
			// recording; the session ends rather than capturing unencrypted.
			authority, err = nil, nil
			if row.State != assistanceEnded {
				if err := endAssistance(ctx, q, row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, "recording_key_unavailable", false, revoked); err != nil {
					return nil, err
				}
			}
		}
		if err != nil {
			return nil, err
		}
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	directive, err := s.assistanceDirective(*row, authority)
	if err != nil {
		return nil, err
	}
	if err := unattendedInvitation(ctx, q, *row, directive.GetInvitation()); err != nil {
		return nil, err
	}
	directive.Command, err = s.commandForAssistance(ctx, q, *row, now)
	if err != nil {
		return nil, err
	}
	directive.FileTransfer, err = s.fileForAssistance(ctx, q, *row, now)
	if err != nil {
		return nil, err
	}
	return directive, nil
}

// applyAssistanceReport advances one locked session from a device report.
// Stale or regressing phases are ignored; protocol violations end the session.
func (s *Service) applyAssistanceReport(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceSession, report *agentv1.AssistanceReport, generation uuid.UUID, now time.Time, revoked *assistanceRevocations) error {
	if err := enforceAssistance(ctx, q, row, now, revoked); err != nil {
		return err
	}
	if row.GenerationID != generation {
		return nil
	}
	if err := recordAssistanceFilePublicationFailure(ctx, q, *row, report.GetFileTransfer(), now); err != nil {
		return err
	}
	if row.State == assistanceEnded {
		if report.GetPhase() == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED && !row.DeviceEnded {
			return q.ConfirmAssistanceDeviceEnded(ctx, row.ID)
		}
		return nil
	}
	end := func(cause agentv1.AssistanceEndCause, detail string, deviceEnded bool) error {
		return endAssistance(ctx, q, row, now, nil, cause, detail, deviceEnded, revoked)
	}
	phase := report.GetPhase()
	if s.Assistance == nil {
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "assistance_unconfigured", phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED)
	}
	switch phase {
	case agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING:
		return nil
	case agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED:
		if err := end(report.GetEndCause(), report.GetEndDetail(), true); err != nil {
			return err
		}
		return unattendedDeviceRefusal(ctx, q, *row, now, revoked)
	}
	local := report.GetLocalSession()
	switch {
	case local == nil:
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_missing", false)
	case row.TargetUsername != "" && local.GetUsername() != row.TargetUsername:
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION, "target_user_mismatch", false)
	case row.State == assistanceRequested:
		if detail, err := bindAssistanceLocalSession(ctx, q, row, local, now); err != nil {
			return err
		} else if detail != "" {
			return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION, detail, false)
		}
	case local.GetUsername() != row.LocalUsername || int64(local.GetUid()) != row.LocalUid || local.GetLogindSessionId() != row.LocalLogindSession || local.GetSessionType() != row.LocalSessionType:
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_changed", false)
	}
	if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED {
		return nil
	}
	consented := row.State == assistancePrompted
	if row.State == assistancePrompted {
		fingerprint, err := AssistanceSDP(report.GetOfferSdp(), s.Assistance.RelayAddress())
		if err != nil {
			return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, err.Error(), false)
		}
		control := report.GetControlGranted() && row.Mode == int16(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL)
		if err := q.OfferAssistanceSession(ctx, devicedb.OfferAssistanceSessionParams{ID: row.ID, ConsentedAt: core.Timestamptz(now), ControlGranted: control, OfferSdp: report.GetOfferSdp(), OfferFingerprint: fingerprint}); err != nil {
			return err
		}
		row.State, row.ConsentedAt, row.ControlGranted, row.OfferSdp, row.OfferFingerprint = assistanceOffered, core.Timestamptz(now), control, report.GetOfferSdp(), fingerprint
	}
	if err := s.applyAssistanceProjection(ctx, q, row, report, now, revoked); err != nil {
		return err
	}
	if row.State == assistanceEnded {
		return nil
	}
	if consented {
		if detail, err := consentAssistance(ctx, q, *row, report.GetGrantedCapabilities(), now); err != nil {
			return err
		} else if detail != "" {
			return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, detail, false)
		}
	}
	if detail, err := applyUnattendedReport(ctx, q, *row, report.GetUnattended(), assistanceProjection(*row).GetGrantedCapabilities().GetPolicy(), now, revoked); err != nil {
		return err
	} else if detail != "" {
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, detail, false)
	}
	if row.State == assistanceEnded {
		return nil
	}
	if detail, err := applyAssistanceRecordingReport(ctx, q, *row, report.GetRecording(), now); err != nil {
		return err
	} else if detail != "" {
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, detail, false)
	}
	if phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		return nil
	}
	switch row.State {
	case assistanceAnswered:
		if err := q.StartAssistanceSession(ctx, devicedb.StartAssistanceSessionParams{ID: row.ID, StartedAt: core.Timestamptz(now)}); err != nil {
			return err
		}
		row.State, row.StartedAt = assistanceActive, core.Timestamptz(now)
		if err := recordAssistanceAudit(ctx, q, nil, auditkind.AssistanceStart, *row, "", "control_granted", boolText(row.ControlGranted)); err != nil {
			return err
		}
	case assistanceOffered:
		// Connected without the operator's authenticated answer.
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "active_before_answer", false)
	}
	err := s.completeAssistanceCommand(ctx, q, *row, report.GetCommandResult(), now)
	var domain *connect.Error
	if errors.Is(err, pgx.ErrNoRows) || errors.As(err, &domain) {
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "command_result_invalid", false)
	}
	if err != nil {
		return err
	}
	err = s.applyAssistanceFileReport(ctx, q, *row, report.GetFileTransfer(), now)
	if errors.Is(err, pgx.ErrNoRows) || errors.As(err, &domain) {
		if auditErr := auditAssistanceFileDenied(ctx, q, row.OperatorID, row.ID.String(), report.GetFileTransfer().GetRequestId(), "file_report_invalid", nil); auditErr != nil {
			return auditErr
		}
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "file_report_invalid", false)
	}
	return err
}

// bindAssistanceLocalSession binds a requested session to the reported local
// login and audits the prompt. An unattended connection reaches only the
// opted-in account's own UID; a recycled name or changed account returns a
// refusal detail instead.
func bindAssistanceLocalSession(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceSession, local *agentv1.AssistanceLocalSession, now time.Time) (string, error) {
	params := devicedb.BindAssistanceLocalSessionParams{
		ID: row.ID, PromptedAt: core.Timestamptz(now), LocalUsername: local.GetUsername(), LocalUid: int64(local.GetUid()),
		LocalLogindSession: local.GetLogindSessionId(), LocalSessionType: local.GetSessionType(), LocalDesktop: local.GetDesktop(),
	}
	if row.UnattendedEnrollmentID != nil {
		enrollment, err := q.LockAssistanceUnattendedEnrollment(ctx, *row.UnattendedEnrollmentID)
		if err != nil {
			return "", err
		}
		if enrollment.Uid != int64(local.GetUid()) || enrollment.Username != local.GetUsername() {
			return "unattended_uid_changed", nil
		}
	}
	if err := q.BindAssistanceLocalSession(ctx, params); err != nil {
		return "", err
	}
	row.State, row.PromptedAt = assistancePrompted, params.PromptedAt
	row.LocalUsername, row.LocalUid, row.LocalLogindSession, row.LocalSessionType, row.LocalDesktop = params.LocalUsername, params.LocalUid, params.LocalLogindSession, params.LocalSessionType, params.LocalDesktop
	return "", recordAssistanceAudit(ctx, q, nil, auditkind.AssistancePrompt, *row, "", append(assistanceLocalAudit(*row), "desktop", row.LocalDesktop)...)
}

// consentAssistance audits the local consent and applies its recording and
// reconnect decisions. A non-empty detail ends the session: required
// recording that was not granted never continues unrecorded. The helper's
// desktop qualification profile and portal interface versions are audited
// with the grant they admitted.
func consentAssistance(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, granted *agentv1.AssistanceCapabilities, now time.Time) (string, error) {
	grant := granted.GetPolicy()
	details := append([]string{"operator", row.OperatorID.String(), "control_granted", boolText(row.ControlGranted), "result", "accepted"}, assistancePolicyAudit(decodeAssistancePolicy(row.EffectiveCapabilities))...)
	details = append(details, assistanceLocalAudit(row)...)
	details = append(details, "elevation_granted", assistancePolicyModeName(grant.GetElevation()), "annotation_granted", assistancePolicyModeName(grant.GetAnnotation()), "audio_granted", assistancePolicyModeName(grant.GetAudio()), "unattended_opt_in_offered", assistancePolicyModeName(grant.GetUnattended()))
	details = append(details, "clipboard_granted", assistancePolicyModeName(grant.GetClipboard()), "keyboard_granted", assistancePolicyModeName(grant.GetKeyboard()), "display_granted", assistancePolicyModeName(grant.GetDisplay()), "messages_granted", assistancePolicyModeName(grant.GetMessages()), "files_granted", assistancePolicyModeName(grant.GetFiles()), "reconnect_granted", assistancePolicyModeName(grant.GetReconnect()), "recording_granted", assistancePolicyModeName(grant.GetRecording()), "desktop", row.LocalDesktop, "desktop_profile", granted.GetDesktopProfile(), "portal_versions", granted.GetPortalVersions(), "offer", row.OfferFingerprint)
	if row.UnattendedGrantID != nil {
		// No local click consented: the banner and the restored persistent
		// grant start an unattended connection.
		if err := recordUnattendedStart(ctx, q, row); err != nil {
			return "", err
		}
	} else if err := recordAssistanceAudit(ctx, q, nil, auditkind.AssistanceConsent, row, "", details...); err != nil {
		return "", err
	}
	if err := approveAssistanceReconnect(ctx, q, row, grant, now); err != nil {
		return "", err
	}
	return startAssistanceRecording(ctx, q, row, grant, now)
}

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
