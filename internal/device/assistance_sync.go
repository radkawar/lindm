package device

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
)

// SyncAssistance exchanges the device's complete observed session state for
// the server's complete desired state. Reports only advance sessions; the
// returned directives are the device's whole authorization.
func (s *Service) SyncAssistance(ctx context.Context, req *connect.Request[devicev1.SyncAssistanceRequest]) (*connect.Response[devicev1.SyncAssistanceResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_assistance_sync")
	}
	seen := make(map[uuid.UUID]struct{}, len(req.Msg.GetReports()))
	for _, report := range req.Msg.GetReports() {
		id, _ := uuid.Parse(report.GetSessionId())
		if _, duplicate := seen[id]; duplicate || hasNUL(report.GetOfferSdp()) {
			return nil, invalid("invalid_assistance_sync")
		}
		seen[id] = struct{}{}
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	now := device.now
	if !enrollmentIssuanceResumable(device.certificate, now) {
		return nil, mapErr(errCertificateRejected)
	}
	if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{ID: principal.DeviceID, LastSeenAt: timestamptz(now)}); err != nil {
		return nil, mapErr(err)
	}
	var revoked assistanceRevocations
	// Deadlines first: a device returning after 30 s of silence must not
	// revive its session by syncing now.
	if err := enforceOpenAssistance(ctx, q, principal.DeviceID, now, &revoked); err != nil {
		return nil, mapErr(err)
	}
	for _, report := range req.Msg.GetReports() {
		id, _ := uuid.Parse(report.GetSessionId())
		row, err := q.LockAssistanceSessionForDevice(ctx, devicedb.LockAssistanceSessionForDeviceParams{ID: id, DeviceID: principal.DeviceID})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, mapErr(err)
		}
		if err := s.applyAssistanceReport(ctx, q, &row, report, principal.GenerationID, now, &revoked); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := q.TouchAssistanceDeviceSync(ctx, devicedb.TouchAssistanceDeviceSyncParams{DeviceID: principal.DeviceID, SyncedAt: timestamptz(now)}); err != nil {
		return nil, mapErr(err)
	}
	rows, err := q.ListAssistanceDirectiveSessions(ctx, devicedb.ListAssistanceDirectiveSessionsParams{DeviceID: principal.DeviceID, EndedAfter: timestamptz(now.Add(-assistanceEndedDelivery))})
	if err != nil {
		return nil, mapErr(err)
	}
	response := &devicev1.SyncAssistanceResponse{}
	for i := range rows {
		row := &rows[i]
		if row.State != assistanceEnded {
			detail := ""
			switch {
			case s.assistance == nil:
				detail = "assistance_unconfigured"
			case row.GenerationID != principal.GenerationID:
				detail = "generation_changed"
			}
			if detail != "" {
				if err := endAssistance(ctx, q, row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, detail, false, &revoked); err != nil {
					return nil, mapErr(err)
				}
			}
		}
		if s.assistance == nil {
			continue
		}
		if row.State == assistanceEnded {
			// Ended sessions may have ended on another path or replica; the
			// relay revocation is idempotent.
			revoked = append(revoked, *row)
		}
		directive, err := s.assistanceDirective(*row)
		if err != nil {
			return nil, mapErr(err)
		}
		response.Directives = append(response.Directives, directive)
	}
	// Directives are the device's whole authorization; never emit one the
	// agent contract would reject.
	if err := s.rules.Validate(response); err != nil {
		return nil, rpcError(connect.CodeInternal, "assistance_directive_invalid")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	s.revokeAssistance(revoked)
	return noStore(response), nil
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
	if s.assistance == nil {
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
			ID: row.ID, PromptedAt: timestamptz(now), LocalUsername: local.GetUsername(), LocalUid: int64(local.GetUid()),
			LocalLogindSession: local.GetLogindSessionId(), LocalSessionType: local.GetSessionType(), LocalDesktop: local.GetDesktop(),
		}
		if err := q.BindAssistanceLocalSession(ctx, params); err != nil {
			return err
		}
		row.State, row.PromptedAt = assistancePrompted, params.PromptedAt
		row.LocalUsername, row.LocalUid, row.LocalLogindSession, row.LocalSessionType, row.LocalDesktop = params.LocalUsername, params.LocalUid, params.LocalLogindSession, params.LocalSessionType, params.LocalDesktop
		if err := dispatchAudit(ctx, q, nil, "assistance.prompt", row.ID, assistanceAudit(append(assistanceLocalAudit(*row), "desktop", row.LocalDesktop)...)); err != nil {
			return err
		}
	case local.GetUsername() != row.LocalUsername || int64(local.GetUid()) != row.LocalUid || local.GetLogindSessionId() != row.LocalLogindSession || local.GetSessionType() != row.LocalSessionType:
		return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_changed", false)
	}
	if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED {
		return nil
	}
	if row.State == assistancePrompted {
		fingerprint, err := assistanceSDP(report.GetOfferSdp(), s.assistance.RelayAddress())
		if err != nil {
			return end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, err.Error(), false)
		}
		control := report.GetControlGranted() && row.Mode == int16(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL)
		if err := q.OfferAssistanceSession(ctx, devicedb.OfferAssistanceSessionParams{ID: row.ID, ConsentedAt: timestamptz(now), ControlGranted: control, OfferSdp: report.GetOfferSdp(), OfferFingerprint: fingerprint}); err != nil {
			return err
		}
		row.State, row.ConsentedAt, row.ControlGranted, row.OfferSdp, row.OfferFingerprint = assistanceOffered, timestamptz(now), control, report.GetOfferSdp(), fingerprint
		details := append([]string{"mode", assistanceModeName(row.Mode), "control_granted", boolText(control)}, assistanceLocalAudit(*row)...)
		if err := dispatchAudit(ctx, q, nil, "assistance.consent", row.ID, assistanceAudit(append(details, "offer", fingerprint)...)); err != nil {
			return err
		}
	}
	if phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		return nil
	}
	switch row.State {
	case assistanceAnswered:
		if err := q.StartAssistanceSession(ctx, devicedb.StartAssistanceSessionParams{ID: row.ID, StartedAt: timestamptz(now)}); err != nil {
			return err
		}
		row.State, row.StartedAt = assistanceActive, timestamptz(now)
		return dispatchAudit(ctx, q, nil, "assistance.start", row.ID, assistanceAudit("control_granted", boolText(row.ControlGranted)))
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
