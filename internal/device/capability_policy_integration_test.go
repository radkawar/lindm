// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"context"
	"crypto/sha256"
	"math"
	"slices"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

var (
	deploymentScope = &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}}
	seededDefault   = []agentv1.ManagementCapability{1, 2, 4, 6}
)

func staticScope(id string) *adminv1.CapabilityPolicyScope {
	return &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_StaticGroupId{StaticGroupId: id}}
}

func dynamicScope(id string) *adminv1.CapabilityPolicyScope {
	return &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_DynamicGroupId{DynamicGroupId: id}}
}

func newCapabilityFixture(t *testing.T, delegated bool) *deviceActionFixture {
	t.Helper()
	capabilities := []string{"device.restart.v1"}
	if delegated {
		capabilities = append(capabilities, trust.CapabilityPolicyCapability)
	}
	return newDeviceActionFixtureCapabilities(t, capabilities)
}

func setCapabilities(ctx context.Context, svc *Service, scope *adminv1.CapabilityPolicyScope, revision uint64, capabilities ...agentv1.ManagementCapability) (*adminv1.CapabilityPolicy, error) {
	request := &adminv1.SetCapabilityPolicyRequest{RequestId: uuid.NewString(), Scope: scope, Capabilities: capabilities, ExpectedRevision: revision, Reason: "capability policy contract"}
	if slices.Contains(capabilities, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_SETTINGS) {
		request.SysctlKeys = []string{"net.ipv4.ip_forward"}
	}
	response, err := svc.SetCapabilityPolicy(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetPolicy(), nil
}

func listCapabilities(t *testing.T, ctx context.Context, svc *Service) *adminv1.ListCapabilityPoliciesResponse {
	t.Helper()
	response, err := svc.ListCapabilityPolicies(ctx, connect.NewRequest(&adminv1.ListCapabilityPoliciesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

func requireReason(t *testing.T, err error, code connect.Code, reason string) {
	t.Helper()
	if connect.CodeOf(err) != code || rpcreason.Get(err) != reason {
		t.Fatalf("error %v, want %s %s", err, code, reason)
	}
}

func firewallSettings(t *testing.T) *agentv1.CapabilityFirewallSettings {
	t.Helper()
	guard := &agentv1.ConnectivityGuardConfig{ConfirmationPublicKey: make([]byte, 32)}
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		for _, verdict := range []agentv1.ConnectivityProbeVerdict{agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW, agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY} {
			guard.Probes = append(guard.Probes, &agentv1.ConnectivityProbeTarget{
				Id: uuid.NewString(), Address: address, Port: 443, Expected: verdict, SourceAddress: address, SourcePort: 40000,
				Direction: agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT, Protocol: agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP,
				Receiver: &agentv1.ConnectivityProbePeer{Origin: "https://probe.example", PublicKey: make([]byte, 32)},
			})
		}
	}
	settings := &agentv1.CapabilityFirewallSettings{ManagementEndpoints: []*agentv1.NativeFirewallEndpoint{{Address: "192.0.2.1", Port: 18445}}, ConnectivityGuard: guard}
	if err := protovalidate.Validate(settings); err != nil {
		t.Fatal(err)
	}
	return settings
}

func auditCount(t *testing.T, f *deviceActionFixture, action string) int {
	t.Helper()
	var count int
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action=$1", action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestCapabilityPolicyAdminContract(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newCapabilityFixture(t, true)
	listed := listCapabilities(t, f.ownerCtx, f.svc)
	deployment := listed.GetDeployment()
	if !slices.Equal(deployment.GetCapabilities(), seededDefault) || deployment.GetRevision() != 1 || deployment.GetUpdatedBy() != "" || len(listed.GetGroups()) != 0 || listed.GetIssuanceUnavailableReason() != "" {
		t.Fatalf("install default %v", listed)
	}
	operator := identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, f.conn, identity.RoleOperator))
	if _, err := setCapabilities(operator, f.svc, deploymentScope, 1, 1); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("operator changed capabilities: %v", err)
	}
	_, err := setCapabilities(f.ownerCtx, f.svc, deploymentScope, 2, 1)
	requireReason(t, err, connect.CodeAborted, "capability_policy_revision_conflict")
	_, err = setCapabilities(f.ownerCtx, f.svc, deploymentScope, 1, 1, 5)
	requireReason(t, err, connect.CodeFailedPrecondition, "capability_firewall_settings_required")
	_, err = setCapabilities(f.ownerCtx, f.svc, staticScope(uuid.NewString()), 0, 3)
	requireReason(t, err, connect.CodeNotFound, "capability_policy_group_not_found")
	if _, err := setCapabilities(f.ownerCtx, f.svc, deploymentScope, 1, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PASSWORD_POLICY); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("local-only capability accepted: %v", err)
	}
	if auditCount(t, f, "capability_policy.set") != 0 {
		t.Fatal("refused changes were audited")
	}

	request := &adminv1.SetCapabilityPolicyRequest{RequestId: uuid.NewString(), Scope: deploymentScope, Capabilities: []agentv1.ManagementCapability{6, 3, 2, 1, 4}, ExpectedRevision: 1, Reason: "enable module blocklist"}
	first, err := f.svc.SetCapabilityPolicy(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	policy := first.Msg.GetPolicy()
	if !slices.Equal(policy.GetCapabilities(), []agentv1.ManagementCapability{1, 2, 3, 4, 6}) || policy.GetRevision() <= 1 || policy.GetUpdatedBy() == "" || policy.GetUpdatedAt() == nil {
		t.Fatalf("stored policy %v", policy)
	}
	replay, err := f.svc.SetCapabilityPolicy(f.ownerCtx, connect.NewRequest(proto.CloneOf(request)))
	if err != nil || !proto.Equal(replay.Msg, first.Msg) {
		t.Fatalf("exact replay %v %v", replay, err)
	}
	changed := proto.CloneOf(request)
	changed.Reason = "different body"
	_, err = f.svc.SetCapabilityPolicy(f.ownerCtx, connect.NewRequest(changed))
	requireReason(t, err, connect.CodeAlreadyExists, "capability_policy_request_conflict")
	var scope, before, after, keys, firewall, reason string
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT details->>'scope', details->>'before', details->>'after', details->>'sysctl_keys', details->>'firewall_settings', reason FROM audit_events WHERE action='capability_policy.set'").Scan(&scope, &before, &after, &keys, &firewall, &reason); err != nil {
		t.Fatal(err)
	}
	if scope != "deployment" || before != "packages,files,local_accounts,os_updates" || after != "packages,files,kernel_module_blocklist,local_accounts,os_updates" || keys != "0" || firewall != "false" || reason != "enable module blocklist" {
		t.Fatalf("audit scope=%s before=%s after=%s keys=%s firewall=%s reason=%s", scope, before, after, keys, firewall, reason)
	}

	// Firewall needs deployment settings, which then cannot be dropped while
	// any scope still grants the firewall.
	groupID := uuid.NewString()
	if _, err := f.svc.SetDeviceGroup(f.ownerCtx, connect.NewRequest(&adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: groupID, Name: "Firewalled", DeviceIds: []string{f.deviceID}, Reason: "capability group"})); err != nil {
		t.Fatal(err)
	}
	_, err = setCapabilities(f.ownerCtx, f.svc, staticScope(groupID), 0, 5)
	requireReason(t, err, connect.CodeFailedPrecondition, "capability_firewall_settings_required")
	settings := firewallSettings(t)
	withFirewall, err := f.svc.SetCapabilityPolicy(f.ownerCtx, connect.NewRequest(&adminv1.SetCapabilityPolicyRequest{RequestId: uuid.NewString(), Scope: deploymentScope, Capabilities: policy.GetCapabilities(), Firewall: settings, ExpectedRevision: policy.GetRevision(), Reason: "firewall settings"}))
	if err != nil || !proto.Equal(withFirewall.Msg.GetPolicy().GetFirewall(), settings) {
		t.Fatalf("firewall settings %v %v", withFirewall, err)
	}
	group, err := setCapabilities(f.ownerCtx, f.svc, staticScope(groupID), 0, 5)
	if err != nil || group.GetScopeName() != "Firewalled" {
		t.Fatalf("group firewall %v %v", group, err)
	}
	_, err = setCapabilities(f.ownerCtx, f.svc, deploymentScope, withFirewall.Msg.GetPolicy().GetRevision(), 1)
	requireReason(t, err, connect.CodeFailedPrecondition, "capability_firewall_settings_required")
	if listed := listCapabilities(t, f.ownerCtx, f.svc); len(listed.GetGroups()) != 1 || !proto.Equal(listed.GetGroups()[0], group) {
		t.Fatalf("group list %v", listed.GetGroups())
	}
	// An empty group policy is removed; its old revision is never reused.
	if _, err := setCapabilities(f.ownerCtx, f.svc, staticScope(groupID), group.GetRevision()); err != nil {
		t.Fatal(err)
	}
	if listed := listCapabilities(t, f.ownerCtx, f.svc); len(listed.GetGroups()) != 0 {
		t.Fatalf("removed group policy listed %v", listed.GetGroups())
	}
	_, err = setCapabilities(f.ownerCtx, f.svc, staticScope(groupID), group.GetRevision(), 5)
	requireReason(t, err, connect.CodeAborted, "capability_policy_revision_conflict")
	if auditCount(t, f, "capability_policy.set") != 4 {
		t.Fatalf("audited %d changes, want 4", auditCount(t, f, "capability_policy.set"))
	}
}

func capabilityPoll(t *testing.T, f *deviceActionFixture, epoch, applied uint64, sha []byte) *devicev1.GetCapabilityPolicyResponse {
	t.Helper()
	response, err := f.svc.GetCapabilityPolicy(f.deviceCtx(), connect.NewRequest(&devicev1.GetCapabilityPolicyRequest{SessionEpoch: epoch, AppliedVersion: applied, AppliedSha256: sha}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

func verifiedCapabilityPolicy(t *testing.T, f *deviceActionFixture, envelope []byte) *agentv1.AgentCapabilityPolicy {
	t.Helper()
	snapshot, err := f.svc.Execution.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.svc.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	_, verifier, err := f.svc.Execution.CurrentInTransaction(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := verifier.VerifyCapabilityPolicy(t.Context(), snapshot.Root, snapshot.Delegation, envelope, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if policy.GetDeviceId() != f.deviceID || policy.GetEnrollmentGeneration() != f.generation {
		t.Fatal("policy bound another device or generation")
	}
	return policy
}

func TestCapabilityPolicyIssuanceUnionAndVersions(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newCapabilityFixture(t, true)
	if _, err := f.svc.GetCapabilityPolicy(f.deviceCtx(), connect.NewRequest(&devicev1.GetCapabilityPolicyRequest{SessionEpoch: 2})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("stale session epoch admitted: %v", err)
	}
	first := capabilityPoll(t, f, 1, 0, nil)
	policy := verifiedCapabilityPolicy(t, f, first.GetPolicyEnvelope())
	if first.GetVersion() != 1 || policy.GetVersion() != 1 || !slices.Equal(policy.GetCapabilities(), seededDefault) || policy.GetFirewall() != nil {
		t.Fatalf("first policy %v", policy)
	}
	digest := sha256.Sum256(first.GetPolicyEnvelope())
	if again := capabilityPoll(t, f, 1, 1, digest[:]); again.GetVersion() != 1 || len(again.GetPolicyEnvelope()) != 0 {
		t.Fatalf("applied device received %v", again)
	}
	if again := capabilityPoll(t, f, 1, 0, nil); again.GetVersion() != 1 || string(again.GetPolicyEnvelope()) != string(first.GetPolicyEnvelope()) {
		t.Fatal("unchanged grant was re-signed")
	}
	if auditCount(t, f, "capability_policy.issue") != 1 {
		t.Fatal("unchanged poll audited an issue")
	}

	staticID, dynamicID, otherID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for id, devices := range map[string][]string{staticID: {f.deviceID}, otherID: nil} {
		if _, err := f.svc.SetDeviceGroup(f.ownerCtx, connect.NewRequest(&adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: id, Name: "group " + id[:8], DeviceIds: devices, Reason: "capability group"})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.svc.PutDynamicGroup(f.ownerCtx, connect.NewRequest(&adminv1.PutDynamicGroupRequest{RequestId: uuid.NewString(), Reason: "debian hosts", Group: &adminv1.DynamicTargetGroup{GroupId: dynamicID, Name: "Debian", Expression: &adminv1.TargetExpression{InventoryMaxAgeSeconds: 3600, Nodes: []*adminv1.TargetNode{{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: &adminv1.DeviceFilter{OsId: "debian"}}}}}}})); err != nil {
		t.Fatal(err)
	}
	if _, err := setCapabilities(f.ownerCtx, f.svc, staticScope(otherID), 0, 3); err != nil {
		t.Fatal(err)
	}
	if again := capabilityPoll(t, f, 1, 1, digest[:]); again.GetVersion() != 1 || len(again.GetPolicyEnvelope()) != 0 {
		t.Fatal("a group without the device changed its grant")
	}
	if _, err := setCapabilities(f.ownerCtx, f.svc, staticScope(staticID), 0, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := setCapabilities(f.ownerCtx, f.svc, dynamicScope(dynamicID), 0, 7); err != nil {
		t.Fatal(err)
	}
	next := capabilityPoll(t, f, 1, 1, digest[:])
	policy = verifiedCapabilityPolicy(t, f, next.GetPolicyEnvelope())
	if next.GetVersion() != 2 || policy.GetVersion() != 2 || !slices.Equal(policy.GetCapabilities(), []agentv1.ManagementCapability{1, 2, 3, 4, 6, 7}) || !slices.Equal(policy.GetSysctlKeys(), []string{"net.ipv4.ip_forward"}) {
		t.Fatalf("union policy %v", policy)
	}
	// A version reported within a minute of the last issue never forces a
	// re-signature of unchanged content.
	if again := capabilityPoll(t, f, 1, 9, nil); again.GetVersion() != 2 {
		t.Fatalf("rate-limited cursor re-issued version %d", again.GetVersion())
	}
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE device_capability_policies SET issued_at = issued_at - interval '2 minutes'"); err != nil {
		t.Fatal(err)
	}
	// A version beyond the bounded jump (a compromised network process
	// trying to exhaust the version space) is ignored.
	if again := capabilityPoll(t, f, 1, math.MaxInt64-1, nil); again.GetVersion() != 2 {
		t.Fatalf("unbounded cursor moved the version to %d", again.GetVersion())
	}
	// A device reporting a version this server never issued (restored
	// database) receives a strictly higher version.
	ahead := capabilityPoll(t, f, 1, 9, nil)
	if policy := verifiedCapabilityPolicy(t, f, ahead.GetPolicyEnvelope()); ahead.GetVersion() != 10 || policy.GetVersion() != 10 {
		t.Fatalf("restored-server version %d", ahead.GetVersion())
	}
	// An empty effective set is still signed: it revokes remote grants.
	deployment := listCapabilities(t, f.ownerCtx, f.svc).GetDeployment()
	if _, err := setCapabilities(f.ownerCtx, f.svc, deploymentScope, deployment.GetRevision()); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []*adminv1.CapabilityPolicyScope{staticScope(staticID), dynamicScope(dynamicID)} {
		for _, group := range listCapabilities(t, f.ownerCtx, f.svc).GetGroups() {
			if proto.Equal(group.GetScope(), scope) {
				if _, err := setCapabilities(f.ownerCtx, f.svc, scope, group.GetRevision()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	empty := capabilityPoll(t, f, 1, 10, nil)
	if policy := verifiedCapabilityPolicy(t, f, empty.GetPolicyEnvelope()); empty.GetVersion() != 11 || len(policy.GetCapabilities()) != 0 {
		t.Fatalf("revoking policy %v", policy)
	}
	if auditCount(t, f, "capability_policy.issue") != 4 {
		t.Fatalf("audited %d issues, want 4", auditCount(t, f, "capability_policy.issue"))
	}
}

func TestCapabilityPolicyRequiresDelegation(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newCapabilityFixture(t, false)
	response := capabilityPoll(t, f, 1, 0, nil)
	if len(response.GetPolicyEnvelope()) != 0 || response.GetVersion() != 0 || response.GetUnavailableReason() != "capability_policy_not_delegated" {
		t.Fatalf("undelegated issuance %v", response)
	}
	if reason := listCapabilities(t, f.ownerCtx, f.svc).GetIssuanceUnavailableReason(); reason != "capability_policy_not_delegated" {
		t.Fatalf("settings reason %q", reason)
	}
	var rows int
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM device_capability_policies").Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("stored %d undelegated policies: %v", rows, err)
	}

	bare := newEnrolled(t, 0)
	unconfigured, err := bare.svc.GetCapabilityPolicy(bare.deviceCtx(), connect.NewRequest(&devicev1.GetCapabilityPolicyRequest{SessionEpoch: 1}))
	if err != nil || unconfigured.Msg.GetUnavailableReason() != "execution_authority_unconfigured" {
		t.Fatalf("unconfigured issuance %v %v", unconfigured, err)
	}
}

func TestDeviceCapabilityState(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newCapabilityFixture(t, true)
	groupID := uuid.NewString()
	if _, err := f.svc.SetDeviceGroup(f.ownerCtx, connect.NewRequest(&adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: groupID, Name: "Workstations", DeviceIds: []string{f.deviceID}, Reason: "capability group"})); err != nil {
		t.Fatal(err)
	}
	if _, err := setCapabilities(f.ownerCtx, f.svc, staticScope(groupID), 0, 1, 3); err != nil {
		t.Fatal(err)
	}
	issued := capabilityPoll(t, f, 1, 0, nil)
	reported := &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE, AppliedVersion: issued.GetVersion(), AcceptedAt: timestamppb.Now(), Capabilities: []*agentv1.CapabilityObservation{
		{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, Status: agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED},
		{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_MODULE_BLOCKLIST, Status: agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE, Detail: "platform_not_qualified"},
	}}
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE enrollment_generations SET last_host_admission_at=clock_timestamp()-interval '5 minutes' WHERE id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	report := hostObservation(f.generation, 2, "capability-state")
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.CapabilityPolicy = reported
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	response, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	state := response.Msg.GetCapabilities()
	if state.GetIssuedVersion() != issued.GetVersion() || state.GetIssuedAt() == nil || state.GetIssuanceUnavailableReason() != "" {
		t.Fatalf("issuance state %v", state)
	}
	if !proto.Equal(state.GetReported(), reported) || !state.GetReportedAt().AsTime().Equal(report.Observation.GetFinishedAt().AsTime().Truncate(time.Microsecond)) {
		t.Fatalf("reported state %v at %v", state.GetReported(), state.GetReportedAt())
	}
	sources := make(map[agentv1.ManagementCapability][]*adminv1.CapabilityPolicyScope)
	for _, grant := range state.GetGranted() {
		sources[grant.GetCapability()] = grant.GetSources()
	}
	if len(sources) != 5 || len(sources[1]) != 2 || !proto.Equal(sources[1][1], staticScope(groupID)) || len(sources[3]) != 1 || !proto.Equal(sources[3][0], staticScope(groupID)) || !proto.Equal(sources[6][0], deploymentScope) {
		t.Fatalf("grant sources %v", state.GetGranted())
	}
}

// Rows the executor refused for a capability are dispatched again only when
// the device's grant or its reported capability status changes.
func TestCapabilityRefusalHoldsAreRedispatched(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixtureWithDelegationAge(t, time.Hour, "systemd.service.v1", trust.CapabilityPolicyCapability)
	f.assign(t, nil)
	refuse := func() string {
		t.Helper()
		work := f.work(t)
		if work == nil {
			t.Fatal("refused row was not dispatched again")
		}
		request := &devicev1.ReportResourceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), CertificatePem: f.certificate}
		intent := f.intent(t, work)
		now := time.Now().UTC().Add(-time.Second)
		stamp := timestamppb.New(now)
		digest := sha256.Sum256(work.GetIntentEnvelope())
		attestation := &agentv1.ResourceExecutionAttestation{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SessionEpoch: 1, ActionRevision: 1, Nonce: work.GetResultNonce(), IssuedAt: stamp, ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: &agentv1.ResourceExecutionStatus{
			ActionId: work.GetActionId(), IntentSha256: digest[:], State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED,
			Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION, AcceptedAt: stamp, CompletedAt: stamp,
			AdmissionRefusal: &agentv1.ResourceAdmissionRefusal{Ref: proto.CloneOf(intent.GetDesired().GetRef()), Operation: intent.GetOperation(), Reason: agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED, Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), NativeEvidenceUnavailable: true},
		}}
		request.AttestationEnvelope = f.sign(t, attestation, f.key)
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request)); err != nil {
			t.Fatal(err)
		}
		return intent.GetDesired().GetRef().GetCanonicalKey()
	}
	held := func(key string) (int16, string) {
		t.Helper()
		var disposition int16
		var reason string
		if err := f.pool.QueryRow(t.Context(), "SELECT disposition, reason FROM resource_assignment_resources WHERE canonical_key=$1", key).Scan(&disposition, &reason); err != nil {
			t.Fatal(err)
		}
		return disposition, reason
	}
	poll := func() {
		t.Helper()
		if _, err := f.service.GetCapabilityPolicy(f.deviceCtx, connect.NewRequest(&devicev1.GetCapabilityPolicyRequest{SessionEpoch: 1})); err != nil {
			t.Fatal(err)
		}
	}
	observe := func(sequence uint64, status agentv1.CapabilityStatus) {
		t.Helper()
		if _, err := f.pool.Exec(t.Context(), "UPDATE enrollment_generations SET last_host_admission_at=clock_timestamp()-interval '5 minutes' WHERE id=$1", f.principal.GenerationID); err != nil {
			t.Fatal(err)
		}
		report := hostObservation(f.principal.GenerationID.String(), sequence, "capability-holds")
		report.Observation.Details = nativeDetailsFixture()
		report.Observation.Details.CapabilityPolicy = &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE, AppliedVersion: 1, Capabilities: []*agentv1.CapabilityObservation{{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, Status: status}}}
		if _, err := f.service.ReportHostObservation(f.deviceCtx, connect.NewRequest(report)); err != nil {
			t.Fatal(err)
		}
	}

	// First issuance is a grant change.
	key := refuse()
	if disposition, reason := held(key); disposition != 5 || reason != "capability_packages_not_enabled" {
		t.Fatalf("refusal recorded as %d %s", disposition, reason)
	}
	if f.work(t) != nil {
		t.Fatal("capability hold was dispatched without a change")
	}
	poll()
	if disposition, _ := held(key); disposition != 1 {
		t.Fatal("newly issued grant did not release the hold")
	}
	refuse()
	poll()
	if disposition, _ := held(key); disposition != 5 {
		t.Fatal("unchanged grant released the hold")
	}
	observe(1, agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED)
	if disposition, _ := held(key); disposition != 1 {
		t.Fatal("first reported capability status did not release the hold")
	}
	refuse()
	observe(2, agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED)
	if disposition, _ := held(key); disposition != 5 {
		t.Fatal("identical reported status released the hold")
	}
	observe(3, agentv1.CapabilityStatus_CAPABILITY_STATUS_LOCAL)
	if disposition, _ := held(key); disposition != 1 {
		t.Fatal("changed reported status did not release the hold")
	}
}
