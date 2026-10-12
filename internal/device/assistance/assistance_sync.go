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

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
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
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
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
	if err := q.TouchAssistanceDeviceSync(ctx, devicedb.TouchAssistanceDeviceSyncParams{DeviceID: principal.DeviceID, SyncedAt: core.Timestamptz(now)}); err != nil {
		return nil, core.MapErr(err)
	}
	if err := recordAssistancePolicy(ctx, q, principal.DeviceID, req.Msg.GetPolicy(), now); err != nil {
		return nil, core.MapErr(err)
	}
	rows, err := q.ListAssistanceDirectiveSessions(ctx, devicedb.ListAssistanceDirectiveSessionsParams{DeviceID: principal.DeviceID, EndedAfter: core.Timestamptz(now.Add(-assistanceEndedDelivery))})
	if err != nil {
		return nil, core.MapErr(err)
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
				if err := endAssistance(ctx, q, row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, detail, false, &revoked); err != nil {
					return nil, core.MapErr(err)
				}
			}
		}
		if s.Assistance == nil {
			continue
		}
		if row.State == assistanceEnded {
			// Ended sessions may have ended on another path or replica; the
			// relay revocation is idempotent.
			revoked = append(revoked, *row)
		}
		directive, err := s.assistanceDirective(*row)
		if err != nil {
			return nil, core.MapErr(err)
		}
		response.Directives = append(response.Directives, directive)
	}
	// Directives are the device's whole authorization; never emit one the
	// agent contract would reject.
	if err := s.Rules.Validate(response); err != nil {
		return nil, rpcreason.Error(connect.CodeInternal, "assistance_directive_invalid")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	s.revokeAssistance(revoked)
	return core.NoStore(response), nil
}

// applyAssistanceReport advances one locked session from a device report.
// Stale or regressing phases are ignored; protocol violations end the session.
func (s *Service) applyAssistanceReport(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceSession, report *agentv1.AssistanceReport, generation uuid.UUID, now time.Time, revoked *assistanceRevocations) error {
	if err := enforceAssistance(ctx, q, row, now, revoked); err != nil {
		return err
	}
	if row.State == assistanceEnded {
		if report.GetPhase() == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED && !row.DeviceEnded {
			return q.ConfirmAssistanceDeviceEnded(ctx, row.ID)
		}
		return nil
	}
	if row.GenerationID != generation {
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
		return end(report.GetEndCause(), report.GetEndDetail(), true)
	}
	local := report.GetLocalSession()
	switch {
	case local == nil:
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_missing", false)
	case row.TargetUsername != "" && local.GetUsername() != row.TargetUsername:
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION, "target_user_mismatch", false)
	case row.State == assistanceRequested:
		params := devicedb.BindAssistanceLocalSessionParams{
			ID: row.ID, PromptedAt: core.Timestamptz(now), LocalUsername: local.GetUsername(), LocalUid: int64(local.GetUid()),
			LocalLogindSession: local.GetLogindSessionId(), LocalSessionType: local.GetSessionType(), LocalDesktop: local.GetDesktop(),
		}
		if err := q.BindAssistanceLocalSession(ctx, params); err != nil {
			return err
		}
		row.State, row.PromptedAt = assistancePrompted, params.PromptedAt
		row.LocalUsername, row.LocalUid, row.LocalLogindSession, row.LocalSessionType, row.LocalDesktop = params.LocalUsername, params.LocalUid, params.LocalLogindSession, params.LocalSessionType, params.LocalDesktop
		if err := recordAssistanceAudit(ctx, q, nil, auditkind.AssistancePrompt, *row, "", append(assistanceLocalAudit(*row), "desktop", row.LocalDesktop)...); err != nil {
			return err
		}
	case local.GetUsername() != row.LocalUsername || int64(local.GetUid()) != row.LocalUid || local.GetLogindSessionId() != row.LocalLogindSession || local.GetSessionType() != row.LocalSessionType:
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_changed", false)
	}
	if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED {
		return nil
	}
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
		details := append([]string{"control_granted", boolText(control)}, assistanceLocalAudit(*row)...)
		if err := recordAssistanceAudit(ctx, q, nil, auditkind.AssistanceConsent, *row, "", append(details, "offer", fingerprint)...); err != nil {
			return err
		}
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
		return recordAssistanceAudit(ctx, q, nil, auditkind.AssistanceStart, *row, "", "control_granted", boolText(row.ControlGranted))
	case assistanceOffered:
		// Connected without the operator's authenticated answer.
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "active_before_answer", false)
	}
	return nil
}

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
