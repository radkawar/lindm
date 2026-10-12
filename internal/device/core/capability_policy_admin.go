package core

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// maxCapabilityGroupPolicies matches the organization document ceiling of one
// deployment and 100 group policies; it bounds every per-device evaluation.
const maxCapabilityGroupPolicies = 100

var (
	errCapabilityRevisionConflict = rpcreason.Error(connect.CodeAborted, "capability_policy_revision_conflict")
	errCapabilityRequestConflict  = rpcreason.Error(connect.CodeAlreadyExists, "capability_policy_request_conflict")
	errCapabilityGroupNotFound    = rpcreason.Error(connect.CodeNotFound, "capability_policy_group_not_found")
	errCapabilityFirewallSettings = rpcreason.Error(connect.CodeFailedPrecondition, "capability_firewall_settings_required")
	errCapabilityCapacity         = rpcreason.Error(connect.CodeResourceExhausted, "capability_policy_capacity")
)

// ListCapabilityPolicies returns the deployment policy, every group policy and
// whether the current delegation lets the online plan signer issue them.
func (s *Service) ListCapabilityPolicies(ctx context.Context, _ *connect.Request[adminv1.ListCapabilityPoliciesRequest]) (*connect.Response[adminv1.ListCapabilityPoliciesResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	rows, err := devicedb.New(s.Pool).ListCapabilityPolicies(ctx)
	if err != nil {
		return nil, MapErr(err)
	}
	response := &adminv1.ListCapabilityPoliciesResponse{}
	for _, row := range rows {
		policy, err := capabilityPolicyMessage(row)
		if err != nil {
			return nil, MapErr(err)
		}
		if row.ScopeKind == capabilityScopeDeployment {
			response.Deployment = policy
		} else {
			response.Groups = append(response.Groups, policy)
		}
	}
	if response.Deployment == nil {
		return nil, MapErr(ErrInternalState)
	}
	if response.IssuanceUnavailableReason, err = s.CapabilityIssuanceReason(ctx); err != nil {
		return nil, ExecutionError(err)
	}
	return NoStore(response), nil
}

func capabilityPolicyMessage(row devicedb.ListCapabilityPoliciesRow) (*adminv1.CapabilityPolicy, error) {
	capabilities, err := storedCapabilities(row.Capabilities)
	if err != nil {
		return nil, err
	}
	firewall, err := storedFirewall(row.Firewall)
	if err != nil {
		return nil, err
	}
	policy := &adminv1.CapabilityPolicy{
		Scope: capabilityScope(row.ScopeKind, row.GroupID), Capabilities: capabilities, SysctlKeys: row.SysctlKeys, Firewall: firewall,
		Revision: uint64(row.Revision), UpdatedAt: ProtoTime(row.UpdatedAt), UpdatedBy: row.UpdatedBy, ScopeName: row.StaticGroupName,
	}
	if row.ScopeKind == capabilityScopeDynamic {
		group := new(adminv1.DynamicTargetGroup)
		if err := proto.Unmarshal(row.DynamicGroupDefinition, group); err != nil {
			return nil, ErrInternalState
		}
		policy.ScopeName = group.GetName()
	}
	return policy, nil
}

// SetCapabilityPolicy replaces one scope's complete policy under optimistic
// concurrency. FIREWALL anywhere requires deployment firewall settings, and
// those settings cannot be removed while any scope grants FIREWALL. An empty
// group policy is removed. Devices pick up the change on their next capability
// poll, which signs a new version only when their effective grant changed.
func (s *Service) SetCapabilityPolicy(ctx context.Context, req *connect.Request[adminv1.SetCapabilityPolicyRequest]) (*connect.Response[adminv1.SetCapabilityPolicyResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	permission := identity.PermissionManageExecutionTrust
	actor, err := s.RequireUnrestricted(ctx, permission)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil || HasNUL(req.Msg.GetReason()) || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_capability_policy_request")
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return nil, ExecutionError(err)
	}
	if err := RequireUnrestrictedPrincipal(authorization.Principal(), permission); err != nil {
		return nil, err
	}
	digest, err := ActionDigest(req.Msg)
	if err != nil {
		return nil, MapErr(err)
	}
	requestID := uuid.MustParse(req.Msg.GetRequestId())
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, ExecutionError(err)
	}
	q := devicedb.New(tx)
	deployment, err := q.LockDeploymentCapabilityPolicy(ctx)
	if err != nil {
		return nil, MapErr(err)
	}
	receipt, err := q.GetCapabilityPolicyRequest(ctx, devicedb.GetCapabilityPolicyRequestParams{ActorID: actor.ID, RequestID: requestID})
	switch {
	case err == nil:
		if !DigestEqual(receipt.Digest, digest) {
			return nil, errCapabilityRequestConflict
		}
		replayed := new(adminv1.SetCapabilityPolicyResponse)
		if err := proto.Unmarshal(receipt.Response, replayed); err != nil {
			return nil, MapErr(ErrInternalState)
		}
		return NoStore(replayed), nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, MapErr(err)
	}
	response, err := s.setCapabilityPolicy(ctx, q, actor.ID, deployment, req.Msg, requestID, digest)
	if err != nil {
		return nil, MapErr(err)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, ExecutionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}

// lockCapabilityScope resolves the requested scope to its stored kind, group
// and audit label, holding an existing group against concurrent deletion.
func lockCapabilityScope(ctx context.Context, q *devicedb.Queries, scope *adminv1.CapabilityPolicyScope) (int16, uuid.UUID, string, error) {
	var err error
	kind, group := capabilityScopeDeployment, uuid.Nil
	switch value := scope.GetScope().(type) {
	case *adminv1.CapabilityPolicyScope_StaticGroupId:
		kind, group = capabilityScopeStatic, uuid.MustParse(value.StaticGroupId)
		_, err = q.LockDeviceGroup(ctx, group)
	case *adminv1.CapabilityPolicyScope_DynamicGroupId:
		kind, group = capabilityScopeDynamic, uuid.MustParse(value.DynamicGroupId)
		_, err = q.LockCapabilityDynamicGroup(ctx, group)
	default:
		return kind, group, "deployment", nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, uuid.Nil, "", errCapabilityGroupNotFound
	}
	label := "static_group:" + group.String()
	if kind == capabilityScopeDynamic {
		label = "dynamic_group:" + group.String()
	}
	return kind, group, label, err
}

func (s *Service) setCapabilityPolicy(ctx context.Context, q *devicedb.Queries, actorID uuid.UUID, deployment devicedb.LockDeploymentCapabilityPolicyRow, msg *adminv1.SetCapabilityPolicyRequest, requestID uuid.UUID, digest []byte) (*adminv1.SetCapabilityPolicyResponse, error) {
	kind, group, label, err := lockCapabilityScope(ctx, q, msg.GetScope())
	if err != nil {
		return nil, err
	}
	var before []int16
	var revision int64
	current, err := q.GetScopeCapabilityPolicy(ctx, devicedb.GetScopeCapabilityPolicyParams{ScopeKind: kind, GroupID: group})
	switch {
	case err == nil:
		before, revision = current.Capabilities, current.Revision
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	if uint64(revision) != msg.GetExpectedRevision() {
		return nil, errCapabilityRevisionConflict
	}
	capabilities := make([]int16, 0, len(msg.GetCapabilities()))
	for _, capability := range msg.GetCapabilities() {
		capabilities = append(capabilities, int16(capability))
	}
	slices.Sort(capabilities)
	keys := append([]string{}, msg.GetSysctlKeys()...)
	slices.Sort(keys)
	firewallGranted := slices.Contains(capabilities, int16(agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL))
	firewall := []byte{}
	if kind == capabilityScopeDeployment {
		if msg.GetFirewall() != nil {
			if firewall, err = (proto.MarshalOptions{Deterministic: true}).Marshal(msg.GetFirewall()); err != nil {
				return nil, err
			}
		} else if firewallGranted {
			return nil, errCapabilityFirewallSettings
		} else if granted, err := q.GroupCapabilityPoliciesGrant(ctx, int16(agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL)); err != nil {
			return nil, err
		} else if granted {
			return nil, errCapabilityFirewallSettings
		}
	} else if firewallGranted && len(deployment.Firewall) == 0 {
		return nil, errCapabilityFirewallSettings
	}
	now, err := DispatchClock(ctx, q)
	if err != nil {
		return nil, err
	}
	next, err := q.NextCapabilityPolicyRevision(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case kind != capabilityScopeDeployment && len(capabilities) == 0:
		if revision != 0 {
			if removed, err := q.DeleteGroupCapabilityPolicy(ctx, devicedb.DeleteGroupCapabilityPolicyParams{ScopeKind: kind, GroupID: group, ExpectedRevision: revision}); err != nil {
				return nil, err
			} else if removed != 1 {
				return nil, errCapabilityRevisionConflict
			}
		}
	case revision == 0:
		count, err := q.CountGroupCapabilityPolicies(ctx)
		if err != nil {
			return nil, err
		}
		if count >= maxCapabilityGroupPolicies {
			return nil, errCapabilityCapacity
		}
		params := devicedb.InsertGroupCapabilityPolicyParams{ScopeKind: kind, Capabilities: capabilities, SysctlKeys: keys, Revision: next, UpdatedAt: Timestamptz(now), UpdatedBy: &actorID}
		if kind == capabilityScopeStatic {
			params.StaticGroupID = &group
		} else {
			params.DynamicGroupID = &group
		}
		if err := q.InsertGroupCapabilityPolicy(ctx, params); err != nil {
			return nil, err
		}
	default:
		if updated, err := q.UpdateCapabilityPolicy(ctx, devicedb.UpdateCapabilityPolicyParams{
			Capabilities: capabilities, SysctlKeys: keys, Firewall: firewall, Revision: next, UpdatedAt: Timestamptz(now), UpdatedBy: &actorID,
			ScopeKind: kind, GroupID: group, ExpectedRevision: revision,
		}); err != nil {
			return nil, err
		} else if updated != 1 {
			return nil, errCapabilityRevisionConflict
		}
	}
	response := &adminv1.SetCapabilityPolicyResponse{Policy: &adminv1.CapabilityPolicy{Scope: msg.GetScope()}}
	rows, err := q.ListCapabilityPolicies(ctx)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.ScopeKind == kind && row.GroupID == group {
			if response.Policy, err = capabilityPolicyMessage(row); err != nil {
				return nil, err
			}
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(response)
	if err != nil {
		return nil, err
	}
	if err := q.InsertCapabilityPolicyRequest(ctx, devicedb.InsertCapabilityPolicyRequestParams{ActorID: actorID, RequestID: requestID, Digest: digest, Response: encoded, CreatedAt: Timestamptz(now)}); err != nil {
		return nil, err
	}
	// The audit append holds the deployment-wide chain head until commit, so it
	// is the transaction's last statement.
	return response, InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: &actorID, Action: auditkind.CapabilityPolicySet.String(), ResourceID: label, Reason: msg.GetReason(),
	}, AuditDetails(
		"scope", label,
		"before", capabilityList(before),
		"after", capabilityList(capabilities),
		"sysctl_keys", strconv.Itoa(len(keys)),
		"firewall_settings", strconv.FormatBool(len(firewall) != 0),
	))
}

// capabilityList renders stored catalogue numbers as sorted names; "none" for
// an empty set, so audit details always carry both sides.
func capabilityList(values []int16) string {
	if len(values) == 0 {
		return "none"
	}
	names := make([]string, 0, len(values))
	for _, value := range values {
		names = append(names, CapabilityName(agentv1.ManagementCapability(value)))
	}
	return strings.Join(names, ",")
}
