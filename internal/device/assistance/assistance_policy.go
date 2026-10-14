// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"bytes"
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func assistanceMode(mode agentv1.AssistancePolicyMode) agentv1.AssistancePolicyMode {
	if mode != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED && mode != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		return agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	}
	return mode
}

func assistancePolicy(p *agentv1.AssistancePolicy) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{Clipboard: assistanceMode(p.GetClipboard()), Keyboard: assistanceMode(p.GetKeyboard()), Display: assistanceMode(p.GetDisplay()), Messages: assistanceMode(p.GetMessages())}
}

func intersectAssistancePolicy(a, b *agentv1.AssistancePolicy) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{
		Clipboard: min(assistanceMode(a.GetClipboard()), assistanceMode(b.GetClipboard())),
		Keyboard:  min(assistanceMode(a.GetKeyboard()), assistanceMode(b.GetKeyboard())),
		Display:   min(assistanceMode(a.GetDisplay()), assistanceMode(b.GetDisplay())),
		Messages:  min(assistanceMode(a.GetMessages()), assistanceMode(b.GetMessages())),
	}
}

func decodeAssistancePolicy(data []byte) *agentv1.AssistancePolicy {
	p := &agentv1.AssistancePolicy{}
	if proto.Unmarshal(data, p) != nil {
		return assistancePolicy(nil)
	}
	return assistancePolicy(p)
}

func assistanceProjection(row devicedb.AssistanceSession) *agentv1.AssistanceReport {
	p := &agentv1.AssistanceReport{}
	if proto.Unmarshal(row.CapabilityProjection, p) != nil {
		return &agentv1.AssistanceReport{}
	}
	return p
}

func loadAssistancePolicy(ctx context.Context, q *devicedb.Queries, id uuid.UUID) (*agentv1.AssistancePolicy, error) {
	data, err := q.GetAssistancePolicy(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return assistancePolicy(nil), nil
	}
	if err != nil {
		return nil, err
	}
	return decodeAssistancePolicy(data), nil
}

// Both permissions use the same freshly observed principal and policy/bindings
// fence. Control never borrows view's scope, and no capability grants view.
func scopeAssistanceMode(ctx context.Context, q *devicedb.Queries, principal identity.Principal, deviceID uuid.UUID, mode agentv1.AssistanceMode) error {
	if mode != agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW && mode != agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		return rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
	}
	for _, permission := range [...]identity.Permission{identity.PermissionViewRemoteAssistance, identity.PermissionControlRemoteAssistance} {
		if permission == identity.PermissionControlRemoteAssistance && mode == agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW {
			continue
		}
		if !identity.Authorize(principal, permission) {
			return rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
		}
		if err := core.RequireDeviceScope(ctx, q, principal, permission, deviceID); err != nil {
			return core.MapErr(err)
		}
	}
	return nil
}

// All capability scopes are checked against the same fresh, transaction-fenced
// principal. A view grant's wider device scope never widens another permission.
func scopeAssistanceCapabilities(ctx context.Context, q *devicedb.Queries, principal identity.Principal, deviceID uuid.UUID, mode agentv1.AssistanceMode, policy *agentv1.AssistancePolicy) error {
	if err := scopeAssistanceMode(ctx, q, principal, deviceID, mode); err != nil {
		return err
	}
	for _, capability := range [...]struct {
		mode       agentv1.AssistancePolicyMode
		permission identity.Permission
	}{
		{policy.GetClipboard(), identity.PermissionAssistanceClipboard},
		{policy.GetKeyboard(), identity.PermissionAssistanceKeyboard},
		{policy.GetDisplay(), identity.PermissionAssistanceDisplay},
		{policy.GetMessages(), identity.PermissionAssistanceMessage},
	} {
		if assistanceMode(capability.mode) > agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
			if err := core.RequireDeviceScope(ctx, q, principal, capability.permission, deviceID); err != nil {
				return core.MapErr(err)
			}
		}
	}
	return nil
}

func (s *Service) GetAssistancePolicy(ctx context.Context, req *connect.Request[adminv1.GetAssistancePolicyRequest]) (*connect.Response[adminv1.GetAssistancePolicyResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_policy")
	}
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	var policy *agentv1.AssistancePolicy
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, _ *assistanceRevocations) error {
		if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id); err != nil {
			return core.MapErr(err)
		}
		var err error
		policy, err = loadAssistancePolicy(ctx, q, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.GetAssistancePolicyResponse{Policy: intersectAssistancePolicy(policy, s.AssistanceCeiling), Ceiling: assistancePolicy(s.AssistanceCeiling)}), nil
}

func (s *Service) UpdateAssistancePolicy(ctx context.Context, req *connect.Request[adminv1.UpdateAssistancePolicyRequest]) (*connect.Response[adminv1.UpdateAssistancePolicyResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionManageAssistancePolicy)
	if err != nil {
		if req != nil && req.Msg != nil {
			err = s.assistancePolicyDenied(ctx, req.Msg.GetDeviceId(), req.Msg.GetRequestId(), err)
		}
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_policy")
	}
	if s.Identity == nil || s.Assistance == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unconfigured")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageAssistancePolicy)
	if err != nil {
		return nil, s.assistancePolicyDenied(ctx, req.Msg.GetDeviceId(), req.Msg.GetRequestId(), core.ExecutionError(err))
	}
	policy := assistancePolicy(req.Msg.GetPolicy())
	digest, err := core.ActionDigest(req.Msg)
	if err != nil {
		return nil, core.MapErr(err)
	}
	data, err := proto.Marshal(policy)
	if err != nil {
		return nil, core.MapErr(err)
	}
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	err = s.assistanceTx(ctx, authorization, identity.PermissionManageAssistancePolicy, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		if _, err := core.LockMutableDevice(ctx, q, authorization.Principal(), identity.PermissionManageAssistancePolicy, id); err != nil {
			denied := core.MapErr(err)
			if connect.CodeOf(denied) == connect.CodeNotFound || connect.CodeOf(denied) == connect.CodePermissionDenied {
				return auditAssistancePolicyDenied(ctx, q, actor.ID, id.String(), requestID.String(), s.AssistanceCeiling, denied)
			}
			return denied
		}
		auditPolicy := func(result, reason string) error {
			effective := policy
			if result == "denied" {
				current, err := loadAssistancePolicy(ctx, q, id)
				if err != nil {
					return err
				}
				effective = intersectAssistancePolicy(current, s.AssistanceCeiling)
			}
			return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
				ID: uuid.New(), ActorID: &actor.ID, Action: auditkind.AssistancePolicy.String(), ResourceID: id.String(), TargetDeviceID: &id,
			}, core.AuditDetails(append([]string{"request", requestID.String(), "result", result, "reason", reason}, assistancePolicyAudit(effective)...)...))
		}
		if !proto.Equal(policy, intersectAssistancePolicy(policy, s.AssistanceCeiling)) {
			if err := auditPolicy("denied", "policy_ceiling"); err != nil {
				return err
			}
			return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_policy_ceiling")
		}
		old, err := q.GetAssistancePolicyRequest(ctx, requestID)
		if err == nil {
			if old.OperatorID != actor.ID || old.DeviceID != id || !bytes.Equal(old.RequestDigest, digest) {
				if err := auditPolicy("denied", "request_conflict"); err != nil {
					return err
				}
				return core.ErrIdempotencyConflict
			}
			policy = decodeAssistancePolicy(old.Policy)
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.InsertAssistancePolicyRequest(ctx, devicedb.InsertAssistancePolicyRequestParams{RequestID: requestID, DeviceID: id, OperatorID: actor.ID, RequestDigest: digest, Policy: data}); err != nil {
			return err
		}
		if err := q.PutAssistancePolicy(ctx, devicedb.PutAssistancePolicyParams{DeviceID: id, Policy: data}); err != nil {
			return err
		}
		row, err := q.LockOpenAssistanceSession(ctx, id)
		if err == nil {
			effective := decodeAssistancePolicy(row.EffectiveCapabilities)
			if !proto.Equal(effective, intersectAssistancePolicy(effective, policy)) {
				if err := endAssistance(ctx, q, &row, s.Now(), &actor.ID, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "policy_changed", false, revoked); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return auditPolicy("updated", "policy_updated")
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.UpdateAssistancePolicyResponse{Policy: policy, Ceiling: assistancePolicy(s.AssistanceCeiling)}), nil
}
