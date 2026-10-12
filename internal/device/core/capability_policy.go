package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

// Persisted capability_policies.scope_kind values.
const (
	capabilityScopeDeployment int16 = 1
	capabilityScopeStatic     int16 = 2
	capabilityScopeDynamic    int16 = 3
)

// Capability policy issuance reasons shared by the device poll, the device page
// and the settings list.
const (
	CapabilityPolicyNotDelegated      = "capability_policy_not_delegated"
	capabilityAuthorityUnconfigured   = "execution_authority_unconfigured"
	capabilitySigningUnconfigured     = "execution_signing_unconfigured"
	capabilitySigningRejected         = "execution_signing_rejected"
	capabilityPolicyVersionsExhausted = "capability_policy_versions_exhausted"
)

const (
	// capabilityPolicyMaxVersionJump bounds how far one device-reported
	// applied version can move the next issued version.
	capabilityPolicyMaxVersionJump = 1 << 20
	// capabilityPolicyReissueInterval rate limits re-issues of unchanged
	// content that only a device-reported version requests.
	capabilityPolicyReissueInterval = time.Minute
)

// CapabilityName is the lowercase catalogue suffix, for example packages or
// custom_file_roots. It names refusals and audit details.
func CapabilityName(capability agentv1.ManagementCapability) string {
	return strings.ToLower(strings.TrimPrefix(capability.String(), "MANAGEMENT_CAPABILITY_"))
}

// CapabilityNotEnabledReason is the BLOCKED disposition reason for an executor
// refusal naming a capability that is not effective on the device. Rows with
// this prefix are dispatched again when the device's grant or reported
// capability status changes.
func CapabilityNotEnabledReason(capability agentv1.ManagementCapability) string {
	return "capability_" + CapabilityName(capability) + "_not_enabled"
}

// capabilityGrant is one device's effective server grant: the deployment
// policy united with every group policy whose group contains the device.
// Capabilities and sysctl keys are sorted and unique, so equal grants encode
// identically.
type capabilityGrant struct {
	capabilities []agentv1.ManagementCapability
	sysctlKeys   []string
	firewall     *agentv1.CapabilityFirewallSettings
	sources      map[agentv1.ManagementCapability][]*adminv1.CapabilityPolicyScope
}

func capabilityScope(kind int16, group uuid.UUID) *adminv1.CapabilityPolicyScope {
	switch kind {
	case capabilityScopeStatic:
		return &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_StaticGroupId{StaticGroupId: group.String()}}
	case capabilityScopeDynamic:
		return &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_DynamicGroupId{DynamicGroupId: group.String()}}
	default:
		return &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}}
	}
}

func storedCapabilities(values []int16) ([]agentv1.ManagementCapability, error) {
	out := make([]agentv1.ManagementCapability, 0, len(values))
	for _, value := range values {
		capability := agentv1.ManagementCapability(value)
		if capability < agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES || capability > agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_SETTINGS {
			return nil, ErrInternalState
		}
		out = append(out, capability)
	}
	return out, nil
}

func storedFirewall(encoded []byte) (*agentv1.CapabilityFirewallSettings, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	settings := new(agentv1.CapabilityFirewallSettings)
	if err := proto.Unmarshal(encoded, settings); err != nil {
		return nil, ErrInternalState
	}
	return settings, nil
}

// effectiveCapabilities evaluates the device's grant inside tx. Static group
// membership is read from the snapshot; dynamic membership uses the targeting
// evaluation, where only a definite inclusion grants (stale inventory does not).
func (s *Service) effectiveCapabilities(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, deviceID uuid.UUID) (*capabilityGrant, error) {
	rows, err := q.ListDeviceCapabilityPolicyCandidates(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	var dynamic []uuid.UUID
	for _, row := range rows {
		if row.ScopeKind == capabilityScopeDynamic {
			dynamic = append(dynamic, row.GroupID)
		}
	}
	members, err := s.Targeting.DynamicGroupsContaining(ctx, tx, deviceID, dynamic)
	if err != nil {
		return nil, err
	}
	grant := &capabilityGrant{sources: make(map[agentv1.ManagementCapability][]*adminv1.CapabilityPolicyScope)}
	keys := make(map[string]bool)
	deployment := false
	for _, row := range rows {
		if row.ScopeKind == capabilityScopeDynamic && !slices.Contains(members, row.GroupID) {
			continue
		}
		capabilities, err := storedCapabilities(row.Capabilities)
		if err != nil {
			return nil, err
		}
		if row.ScopeKind == capabilityScopeDeployment {
			deployment = true
			if grant.firewall, err = storedFirewall(row.Firewall); err != nil {
				return nil, err
			}
		}
		for _, capability := range capabilities {
			if grant.sources[capability] == nil {
				grant.capabilities = append(grant.capabilities, capability)
			}
			grant.sources[capability] = append(grant.sources[capability], capabilityScope(row.ScopeKind, row.GroupID))
		}
		for _, key := range row.SysctlKeys {
			if !keys[key] {
				keys[key] = true
				grant.sysctlKeys = append(grant.sysctlKeys, key)
			}
		}
	}
	if !deployment {
		return nil, ErrInternalState
	}
	slices.Sort(grant.capabilities)
	slices.Sort(grant.sysctlKeys)
	// Firewall settings are deployment-only and accompany exactly a granted
	// firewall; SetCapabilityPolicy keeps every FIREWALL grant backed by them.
	if grant.sources[agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL] == nil {
		grant.firewall = nil
	} else if grant.firewall == nil {
		return nil, ErrInternalState
	}
	return grant, nil
}

// policy is the unsigned content; version and issuance time are set by mint.
func (g *capabilityGrant) policy(deploymentID, deviceID, generationID uuid.UUID) *agentv1.AgentCapabilityPolicy {
	return &agentv1.AgentCapabilityPolicy{
		FormatVersion: 1, DeploymentId: deploymentID.String(), DeviceId: deviceID.String(), EnrollmentGeneration: generationID.String(),
		Capabilities: g.capabilities, SysctlKeys: g.sysctlKeys, Firewall: g.firewall,
	}
}

func capabilityContentDigest(policy *agentv1.AgentCapabilityPolicy) ([]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(policy)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("lindm.capability-policy.content.v1\x00"), encoded...))
	return sum[:], nil
}

// capabilityIssuance reports why the online plan signer cannot issue capability
// policies under snapshot, or "" when the delegation authorizes it.
func (s *Service) capabilityIssuance(snapshot *executionauthority.Snapshot) string {
	switch {
	case s.Execution == nil || snapshot == nil || snapshot.Delegation == nil:
		return capabilityAuthorityUnconfigured
	case s.Signing == nil:
		return capabilitySigningUnconfigured
	case !DeviceActionSignerDelegated(snapshot.Delegation, s.Signing.PlanKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, trust.CapabilityPolicyCapability):
		return CapabilityPolicyNotDelegated
	}
	return ""
}

// CapabilityIssuanceReason reads the current delegation outside any transaction.
func (s *Service) CapabilityIssuanceReason(ctx context.Context) (string, error) {
	if s.Execution == nil {
		return capabilityAuthorityUnconfigured, nil
	}
	snapshot, err := s.Execution.Get(ctx)
	if err != nil {
		return "", err
	}
	return s.capabilityIssuance(snapshot), nil
}

// GetCapabilityPolicy returns the current signed capability policy of the
// caller's enrollment generation. It signs a new version only when the
// effective grant changed, the stored envelope no longer verifies under the
// current delegation, or the device reports a version this server never
// issued (restored database). The request cursor is an untrusted hint.
func (s *Service) GetCapabilityPolicy(ctx context.Context, req *connect.Request[devicev1.GetCapabilityPolicyRequest]) (*connect.Response[devicev1.GetCapabilityPolicyResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	principal, ok := DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil {
		return nil, Invalid("invalid_capability_policy_cursor")
	}
	if err := s.Rules.Validate(req.Msg); err != nil {
		return nil, Invalid("invalid_capability_policy_cursor")
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Authority share lock first, then the device row: the same order as
	// resource dispatch. The device lock serializes this generation's versions.
	var snapshot *executionauthority.Snapshot
	var verifier *trust.ExecutionVerifier
	if s.Execution != nil {
		if snapshot, verifier, err = s.Execution.CurrentInTransaction(ctx, tx); err != nil {
			return nil, ExecutionError(err)
		}
	}
	q := devicedb.New(tx)
	authority, err := s.LockAuthority(ctx, q, principal)
	if err != nil {
		return nil, MapErr(err)
	}
	if uint64(authority.Generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, MapErr(ErrSessionFenced)
	}
	response, err := s.currentCapabilityPolicy(ctx, tx, q, principal, snapshot, verifier, req.Msg, authority.Now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}

func (s *Service) currentCapabilityPolicy(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, principal DevicePrincipal, snapshot *executionauthority.Snapshot, verifier *trust.ExecutionVerifier, cursor *devicev1.GetCapabilityPolicyRequest, now time.Time) (*devicev1.GetCapabilityPolicyResponse, error) {
	if reason := s.capabilityIssuance(snapshot); reason != "" {
		return &devicev1.GetCapabilityPolicyResponse{UnavailableReason: reason}, nil
	}
	grant, err := s.effectiveCapabilities(ctx, tx, q, principal.DeviceID)
	if err != nil {
		return nil, MapErr(err)
	}
	policy := grant.policy(s.DeploymentID, principal.DeviceID, principal.GenerationID)
	content, err := capabilityContentDigest(policy)
	if err != nil {
		return nil, MapErr(err)
	}
	latest, err := q.LatestDeviceCapabilityPolicy(ctx, devicedb.LatestDeviceCapabilityPolicyParams{DeviceID: principal.DeviceID, GenerationID: principal.GenerationID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, MapErr(err)
	}
	// applied_version is an untrusted hint. It only matters after a server
	// restore, when the device holds a version the server never issued: the
	// next version must then exceed it or the executor refuses it as a
	// rollback. The jump is bounded and cursor-only re-issues are rate
	// limited, so a compromised device can neither exhaust the version space
	// (and with it future revocations) nor force a signature on every poll.
	var stored uint64
	if err == nil {
		stored = uint64(latest.Version)
	}
	ahead := cursor.GetAppliedVersion() > stored && cursor.GetAppliedVersion()-stored <= capabilityPolicyMaxVersionJump
	if ahead && err == nil && now.Sub(latest.IssuedAt.Time) < capabilityPolicyReissueInterval {
		ahead = false
	}
	current := err == nil && bytes.Equal(latest.ContentSha256, content) && !ahead
	if current {
		// A rotated plan key or a newly expired delegation makes the device
		// treat the accepted policy as inert; re-sign rather than serve it.
		_, verifyErr := verifier.VerifyCapabilityPolicy(ctx, snapshot.Root, snapshot.Delegation, latest.Envelope, now)
		current = verifyErr == nil
	}
	if !current {
		next := stored
		if ahead {
			next = cursor.GetAppliedVersion()
		}
		if next >= math.MaxInt64 {
			return &devicev1.GetCapabilityPolicyResponse{UnavailableReason: capabilityPolicyVersionsExhausted}, nil
		}
		policy.Version, policy.IssuedAt = next+1, timestamppb.New(now)
		envelope, err := s.Authority.Sign(ctx, policy, s.Signing.PlanKey)
		if err != nil {
			return &devicev1.GetCapabilityPolicyResponse{UnavailableReason: capabilitySigningRejected}, nil
		}
		if _, err := verifier.VerifyCapabilityPolicy(ctx, snapshot.Root, snapshot.Delegation, envelope, now); err != nil {
			return &devicev1.GetCapabilityPolicyResponse{UnavailableReason: capabilitySigningRejected}, nil
		}
		latest = devicedb.LatestDeviceCapabilityPolicyRow{Version: int64(policy.Version), ContentSha256: content, Envelope: envelope, IssuedAt: Timestamptz(now)}
		if err := s.storeCapabilityPolicy(ctx, q, principal, latest); err != nil {
			return nil, MapErr(err)
		}
	}
	response := &devicev1.GetCapabilityPolicyResponse{Version: uint64(latest.Version)}
	if digest := sha256.Sum256(latest.Envelope); !bytes.Equal(digest[:], cursor.GetAppliedSha256()) {
		response.PolicyEnvelope = latest.Envelope
	}
	return response, nil
}

// storeCapabilityPolicy records a newly signed version. A changed grant also
// releases rows the executor refused for a capability that was not enabled.
// The audit append holds the deployment-wide chain head until commit, so it
// is the last statement.
func (s *Service) storeCapabilityPolicy(ctx context.Context, q *devicedb.Queries, principal DevicePrincipal, row devicedb.LatestDeviceCapabilityPolicyRow) error {
	if err := q.InsertDeviceCapabilityPolicy(ctx, devicedb.InsertDeviceCapabilityPolicyParams{
		DeviceID: principal.DeviceID, GenerationID: principal.GenerationID, Version: row.Version,
		ContentSha256: row.ContentSha256, Envelope: row.Envelope, IssuedAt: row.IssuedAt,
	}); err != nil {
		return err
	}
	if err := q.PruneDeviceCapabilityPolicies(ctx, devicedb.PruneDeviceCapabilityPoliciesParams{DeviceID: principal.DeviceID, GenerationID: principal.GenerationID, Latest: row.Version}); err != nil {
		return err
	}
	if _, err := q.ReleaseCapabilityHolds(ctx, principal.GenerationID); err != nil {
		return err
	}
	return InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), Action: auditkind.CapabilityPolicyIssue.String(), ResourceID: principal.DeviceID.String(), TargetDeviceID: &principal.DeviceID,
	}, AuditDetails("enrollment_generation", principal.GenerationID.String(), "version", strconv.FormatInt(row.Version, 10)))
}

// DeviceCapabilityState is the device page view inside the caller's snapshot
// transaction (which may be read-only). host is the generation's latest
// accepted host observation, nil when none exists.
func (s *Service) DeviceCapabilityState(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, deviceID, generationID uuid.UUID, host *devicedb.GetHostObservationRow) (*adminv1.DeviceCapabilityState, error) {
	grant, err := s.effectiveCapabilities(ctx, tx, q, deviceID)
	if err != nil {
		return nil, err
	}
	state := &adminv1.DeviceCapabilityState{}
	for _, capability := range grant.capabilities {
		state.Granted = append(state.Granted, &adminv1.DeviceCapabilityGrant{Capability: capability, Sources: grant.sources[capability]})
	}
	latest, err := q.LatestDeviceCapabilityPolicy(ctx, devicedb.LatestDeviceCapabilityPolicyParams{DeviceID: deviceID, GenerationID: generationID})
	switch {
	case err == nil:
		state.IssuedVersion = uint64(latest.Version)
		state.IssuedAt = ProtoTime(latest.IssuedAt)
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	if state.IssuanceUnavailableReason, err = s.CapabilityIssuanceReason(ctx); err != nil {
		return nil, err
	}
	if host != nil && len(host.Details) != 0 {
		details := new(inventoryv1.NativeDetails)
		if err := proto.Unmarshal(host.Details, details); err != nil {
			return nil, ErrInternalState
		}
		if reported := details.GetCapabilityPolicy(); reported != nil {
			state.Reported = reported
			state.ReportedAt = ProtoTime(host.FinishedAt)
		}
	}
	return state, nil
}
