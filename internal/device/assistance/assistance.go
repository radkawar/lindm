package assistance

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistrelay"
	"lindm/internal/device/devicedb"
)

// Remote assistance lifecycle contract (docs/architecture.md §9). Deadlines
// are enforced lazily whenever a session row is read or synced.
const (
	assistanceConsentWindow   = 120 * time.Second
	assistanceDefaultDuration = 1800 * time.Second
	assistanceUnreachable     = 30 * time.Second
	assistanceOnlineWindow    = 2 * time.Minute
	assistanceEndedDelivery   = 2 * time.Minute

	assistanceRequested = int16(adminv1.AssistanceState_ASSISTANCE_STATE_REQUESTED)
	assistancePrompted  = int16(adminv1.AssistanceState_ASSISTANCE_STATE_PROMPTED)
	assistanceOffered   = int16(adminv1.AssistanceState_ASSISTANCE_STATE_OFFERED)
	assistanceAnswered  = int16(adminv1.AssistanceState_ASSISTANCE_STATE_ANSWERED)
	assistanceActive    = int16(adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE)
	assistanceEnded     = int16(adminv1.AssistanceState_ASSISTANCE_STATE_ENDED)
)

var (
	ErrAssistanceFingerprint = errors.New("assistance_fingerprint")
	ErrAssistanceNonRelay    = errors.New("assistance_non_relay")
)

// assistanceRevocations collects sessions ended inside a transaction. The relay
// learns about them only after commit, so a rolled-back end never revokes a
// live session's relay credentials.
type assistanceRevocations []devicedb.AssistanceSession

func (s *Service) revokeAssistance(revoked assistanceRevocations) {
	if s.Assistance == nil {
		return
	}
	for _, row := range revoked {
		s.Assistance.End(row.ID, row.EndsAt.Time)
	}
}

// endAssistance ends an open session in the caller's transaction, audits the
// end, and updates row in place. actor is nil for device and deadline ends.
func endAssistance(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceSession, now time.Time, actor *uuid.UUID, cause agentv1.AssistanceEndCause, detail string, deviceEnded bool, revoked *assistanceRevocations) error {
	if row.State == assistanceEnded {
		return nil
	}
	if err := q.EndAssistanceSession(ctx, devicedb.EndAssistanceSessionParams{ID: row.ID, EndedAt: core.Timestamptz(now), EndCause: int16(cause), EndDetail: detail, DeviceEnded: deviceEnded}); err != nil {
		return err
	}
	row.State, row.EndedAt, row.EndCause, row.EndDetail, row.DeviceEnded = assistanceEnded, core.Timestamptz(now), int16(cause), detail, deviceEnded
	row.OfferSdp, row.AnswerSdp = "", ""
	*revoked = append(*revoked, *row)
	return recordAssistanceAudit(ctx, q, actor, auditkind.AssistanceEnd, *row, "", "cause", assistanceCauseName(cause), "detail", detail)
}

// enforceAssistance applies the server-side deadlines to an open session:
// hard expiry, consent timeout and the 30 s device-unreachable rule.
func enforceAssistance(ctx context.Context, q *devicedb.Queries, row *devicedb.AssistanceSession, now time.Time, revoked *assistanceRevocations) error {
	switch {
	case row.State == assistanceEnded:
		return nil
	case !now.Before(row.EndsAt.Time):
		return endAssistance(ctx, q, row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED, "", false, revoked)
	case row.State <= assistancePrompted && !now.Before(row.ConsentDeadline.Time):
		return endAssistance(ctx, q, row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT, "", false, revoked)
	case row.State >= assistancePrompted && (!row.DeviceSyncedAt.Valid || now.Sub(row.DeviceSyncedAt.Time) >= assistanceUnreachable):
		return endAssistance(ctx, q, row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "device_unreachable", false, revoked)
	}
	return nil
}

// enforceOpenAssistance applies deadlines to the device's open session, if any.
func enforceOpenAssistance(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, now time.Time, revoked *assistanceRevocations) error {
	row, err := q.LockOpenAssistanceSession(ctx, deviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	return enforceAssistance(ctx, q, &row, now, revoked)
}

func assistanceMessage(row devicedb.AssistanceSession) *adminv1.AssistanceSession {
	session := &adminv1.AssistanceSession{
		Id:                row.ID.String(),
		DeviceId:          row.DeviceID.String(),
		OperatorId:        row.OperatorID.String(),
		OperatorDisplay:   row.OperatorDisplay,
		Mode:              agentv1.AssistanceMode(row.Mode),
		Reason:            row.Reason,
		State:             adminv1.AssistanceState(row.State),
		CreatedAt:         core.ProtoTime(row.CreatedAt),
		ConsentDeadline:   core.ProtoTime(row.ConsentDeadline),
		EndsAt:            core.ProtoTime(row.EndsAt),
		ConsentedAt:       core.ProtoTime(row.ConsentedAt),
		StartedAt:         core.ProtoTime(row.StartedAt),
		EndedAt:           core.ProtoTime(row.EndedAt),
		EndCause:          agentv1.AssistanceEndCause(row.EndCause),
		EndDetail:         row.EndDetail,
		ControlGranted:    row.ControlGranted,
		OfferFingerprint:  row.OfferFingerprint,
		AnswerFingerprint: row.AnswerFingerprint,
		TargetUsername:    row.TargetUsername,
	}
	if row.LocalLogindSession != "" {
		session.LocalSession = &agentv1.AssistanceLocalSession{
			Username:        row.LocalUsername,
			Uid:             uint32(row.LocalUid),
			LogindSessionId: row.LocalLogindSession,
			SessionType:     row.LocalSessionType,
			Desktop:         row.LocalDesktop,
		}
	}
	return session
}

func (s *Service) assistanceDirective(row devicedb.AssistanceSession) (*agentv1.AssistanceDirective, error) {
	ice, err := s.Assistance.ICEServer(row.ID, assistrelay.RoleDevice, row.EndsAt.Time)
	if err != nil {
		return nil, err
	}
	directive := &agentv1.AssistanceDirective{Invitation: &agentv1.AssistanceInvitation{
		SessionId:       row.ID.String(),
		Mode:            agentv1.AssistanceMode(row.Mode),
		Reason:          row.Reason,
		OperatorDisplay: row.OperatorDisplay,
		ConsentDeadline: timestamppb.New(row.ConsentDeadline.Time),
		EndsAt:          timestamppb.New(row.EndsAt.Time),
		TargetUsername:  row.TargetUsername,
		IceServers:      []*agentv1.AssistanceIceServer{ice},
	}}
	switch row.State {
	case assistanceAnswered, assistanceActive:
		directive.AnswerSdp = row.AnswerSdp
	case assistanceEnded:
		directive.Terminate = true
		directive.TerminateCause = agentv1.AssistanceEndCause(row.EndCause)
	}
	return directive, nil
}

// assistanceSDP checks a complete non-trickle SDP: exactly one distinct
// SHA-256 DTLS fingerprint (browsers repeat it per media section) and only
// relay candidates on this relay's address. It returns the normalized
// fingerprint "sha-256 AB:CD:…".
func AssistanceSDP(sdp string, relay netip.Addr) (string, error) {
	fingerprint := ""
	candidates := 0
	for raw := range strings.SplitSeq(sdp, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if value, ok := strings.CutPrefix(line, "a=fingerprint:"); ok {
			algorithm, digest, ok := strings.Cut(strings.TrimSpace(value), " ")
			digest = strings.ToUpper(strings.TrimSpace(digest))
			if !ok || !strings.EqualFold(algorithm, "sha-256") || !sha256Fingerprint(digest) || (fingerprint != "" && fingerprint != digest) {
				return "", ErrAssistanceFingerprint
			}
			fingerprint = digest
			continue
		}
		if value, ok := strings.CutPrefix(line, "a=candidate:"); ok {
			// foundation component transport priority address port "typ" type …
			fields := strings.Fields(value)
			if len(fields) < 8 || fields[6] != "typ" || fields[7] != "relay" {
				return "", ErrAssistanceNonRelay
			}
			address, err := netip.ParseAddr(fields[4])
			if err != nil || address.Unmap() != relay {
				return "", ErrAssistanceNonRelay
			}
			candidates++
		}
	}
	if fingerprint == "" {
		return "", ErrAssistanceFingerprint
	}
	if candidates == 0 {
		return "", ErrAssistanceNonRelay
	}
	return "sha-256 " + fingerprint, nil
}

func sha256Fingerprint(value string) bool {
	if len(value) != 32*3-1 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// recordAssistanceAudit separates operator-authored reasons from server context.
// Callers never pass SDP, relay credentials or other secrets.
func recordAssistanceAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, row devicedb.AssistanceSession, reason string, pairs ...string) error {
	details := core.AuditDetails(pairs...)
	details["mode"] = assistanceModeName(row.Mode)
	details["duration_seconds"] = strconv.FormatInt(int64(row.EndsAt.Time.Sub(row.CreatedAt.Time)/time.Second), 10)
	return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: row.ID.String(),
		Reason: reason, TargetDeviceID: &row.DeviceID,
	}, details)
}

func assistanceModeName(mode int16) string {
	if mode == int16(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL) {
		return "control"
	}
	return "view"
}

func assistanceCauseName(cause agentv1.AssistanceEndCause) string {
	return strings.ToLower(strings.TrimPrefix(cause.String(), "ASSISTANCE_END_CAUSE_"))
}

func assistanceLocalAudit(row devicedb.AssistanceSession) []string {
	return []string{"user", row.LocalUsername, "uid", strconv.FormatInt(row.LocalUid, 10), "session", row.LocalLogindSession, "type", row.LocalSessionType}
}
