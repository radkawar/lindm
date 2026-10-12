package assistance

import (
	"context"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// GetAssistanceReadiness tells a requesting operator, before they write a
// reason, whether a request could reach a person on the device, from the
// policy the device reports and its session inventory.
func (s *Service) GetAssistanceReadiness(ctx context.Context, req *connect.Request[adminv1.GetAssistanceReadinessRequest]) (*connect.Response[adminv1.GetAssistanceReadinessResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionRunRemoteAssistance)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_readiness")
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	var readiness *adminv1.AssistanceReadiness
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionRunRemoteAssistance, deviceID); err != nil {
			return core.MapErr(err)
		}
		now := s.Now()
		// A deadline-due session must not read as busy.
		if err := enforceOpenAssistance(ctx, q, deviceID, now, revoked); err != nil {
			return err
		}
		row, err := q.GetAssistanceReadiness(ctx, deviceID)
		if err != nil {
			return core.MapErr(core.NotFoundIfMissing(err))
		}
		readiness = assistanceReadiness(row, s.Assistance != nil, now)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.GetAssistanceReadinessResponse{Readiness: readiness}), nil
}

// assistanceReadiness orders blockers from the most to the least lasting, so
// the operator learns first what waiting cannot fix: a device that has assistance
// turned off is reported as such even while it is offline.
func assistanceReadiness(row devicedb.GetAssistanceReadinessRow, configured bool, now time.Time) *adminv1.AssistanceReadiness {
	readiness := &adminv1.AssistanceReadiness{
		Policy:  agentv1.AssistancePolicy(row.ReportedPolicy.Int16),
		Desktop: desktopEvidence(row.InventoryDetails),
	}
	if !row.ReportedPolicy.Valid {
		readiness.Policy = agentv1.AssistancePolicy_ASSISTANCE_POLICY_UNSPECIFIED
	}
	if readiness.Desktop != adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_UNSPECIFIED && row.InventoryFinishedAt.Valid {
		readiness.InventoryObservedAt = timestamppb.New(row.InventoryFinishedAt.Time)
	}
	if row.LastSeenAt.Valid {
		readiness.LastSeenAt = timestamppb.New(row.LastSeenAt.Time)
	}
	switch {
	case !configured:
		readiness.State = adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_UNCONFIGURED
	case row.State != core.StateActive || row.CurrentGenerationID == nil:
		readiness.State = adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_NOT_ENROLLED
	case readiness.Policy == agentv1.AssistancePolicy_ASSISTANCE_POLICY_DISABLED:
		readiness.State = adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_DISABLED
	case readiness.Desktop == adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_ABSENT:
		readiness.State = adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_NO_DESKTOP
	case !row.LastSeenAt.Valid || now.Sub(row.LastSeenAt.Time) > assistanceOnlineWindow:
		readiness.State = adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_OFFLINE
	case row.OpenSessionID != nil:
		readiness.State = adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_BUSY
		readiness.OpenSessionId = row.OpenSessionID.String()
	default:
		readiness.State = adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_READY
	}
	return readiness
}

// refuseUnreachable is CreateAssistanceSession's pre-start refusal: a request
// the device is known to decline is never recorded as a session.
func refuseUnreachable(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID) error {
	row, err := q.GetAssistanceReadiness(ctx, deviceID)
	if err != nil {
		return err
	}
	if row.ReportedPolicy.Valid && agentv1.AssistancePolicy(row.ReportedPolicy.Int16) == agentv1.AssistancePolicy_ASSISTANCE_POLICY_DISABLED {
		return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_disabled")
	}
	if desktopEvidence(row.InventoryDetails) == adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_ABSENT {
		return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_no_desktop")
	}
	return nil
}

// desktopEvidence reads the latest session inventory. Any local X11 or Wayland
// session, a login screen included, means the host has a desktop; a successful
// collection with none means a headless host. Anything else stays unknown, so
// the device itself decides.
func desktopEvidence(details []byte) adminv1.AssistanceDesktop {
	native := new(inventoryv1.NativeDetails)
	if len(details) == 0 || proto.Unmarshal(details, native) != nil {
		return adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_UNSPECIFIED
	}
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	active := native.GetSessions().GetActiveSessions()
	if active.GetStatus() != success {
		return adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_UNSPECIFIED
	}
	unknown := false
	for _, session := range active.GetSessions() {
		kind, remote := session.GetSessionType(), session.GetRemote()
		if kind.GetStatus() != success || remote.GetStatus() != success {
			unknown = true
			continue
		}
		if (kind.GetValue() == "wayland" || kind.GetValue() == "x11") && !remote.GetValue() {
			return adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_PRESENT
		}
	}
	if unknown {
		return adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_UNSPECIFIED
	}
	return adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_ABSENT
}

// recordAssistancePolicy keeps the device's reported setting; an agent that
// does not report one leaves the server's view unknown rather than stale.
func recordAssistancePolicy(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, policy agentv1.AssistancePolicy, now time.Time) error {
	if policy == agentv1.AssistancePolicy_ASSISTANCE_POLICY_UNSPECIFIED {
		return q.ClearAssistanceDevicePolicy(ctx, deviceID)
	}
	return q.SetAssistanceDevicePolicy(ctx, devicedb.SetAssistanceDevicePolicyParams{DeviceID: deviceID, Policy: int16(policy), ChangedAt: core.Timestamptz(now)})
}
