// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/capabilitypolicy"
	"lindm/internal/agent/config"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/agent/packageprovider"
	"lindm/internal/agent/sshprovider"
	"lindm/internal/platform"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

// capabilityFixture is an enrolled executor whose PLAN key is delegated the
// capability-policy capability, on a fixed Ubuntu 24.04 host.
type capabilityFixture struct {
	*resourceFixture
	restoreReady atomic.Bool
	enables      atomic.Int32
	enableErr    error
}

func newCapabilityFixture(t *testing.T, local *agentv1.AgentConfig) *capabilityFixture {
	t.Helper()
	release, ok := platform.Lookup("ubuntu-24.04")
	if !ok {
		t.Fatal("registry lacks ubuntu-24.04")
	}
	c := &capabilityFixture{}
	f := &resourceFixture{now: time.Date(2031, 9, 1, 0, 0, 0, 0, time.UTC), boot: uuid.NewString(), planKey: testKey(t), startKey: testKey(t), capabilityGate: true}
	c.resourceFixture = f
	f.wall.Store(f.now.UnixNano())
	f.bootClock.Store(uint64(time.Hour))
	f.fix = newFixture(t, f.now)
	f.native = &boundaryNative{observation: &resourcev1.SystemdServiceObservation{}, finished: make(chan struct{})}
	directory := protectedDir(t)
	if local == nil {
		local = new(agentv1.AgentConfig)
	}
	host := capabilitypolicy.Host{
		Release: release, Architecture: "x86_64",
		Interfaces:           func() ([]capabilitypolicy.Interface, error) { return nil, nil },
		ReadVendorKey:        func(string) ([]byte, error) { return nil, errors.New("no vendor key in tests") },
		FirewallRestoreReady: c.restoreReady.Load,
	}
	opts := append(f.options(),
		WithCapabilityPolicy(&config.Document{Proto: local, StateDirectory: directory}),
		WithCapabilityHost(func(context.Context) (capabilitypolicy.Host, error) { return host, nil }),
		WithUnitEnabler(func(_ context.Context, unit string) error {
			if unit != firewallRestoreUnit {
				t.Errorf("enabled unexpected unit %q", unit)
			}
			c.enables.Add(1)
			if c.enableErr != nil {
				return c.enableErr
			}
			c.restoreReady.Store(true)
			return nil
		}),
	)
	svc, err := New(t.Context(), directory, append([]Option{WithClock(func() time.Time { return f.now })}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	f.svc = svc
	prepare(t, f.svc, f.fix, "lg1_test-grant-secret-with-32-characters-minimum", false)
	device, generation := uuid.New(), uuid.New()
	cert := f.fix.leaf(t, publicOf(durable(t, f.svc).GetIdentityPrivateKey()), device, generation, f.now.Add(-time.Minute), f.now.Add(24*time.Hour))
	if _, err := f.svc.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: cert})); err != nil {
		t.Fatal(err)
	}
	pending := session(t, f.svc).GetPending()
	if _, err := f.svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: pending.GetRequestId(), ServerEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	c.delegate(t, 1, true)
	return c
}

func (c *capabilityFixture) delegate(t *testing.T, version uint64, policy bool) {
	t.Helper()
	plan, start := delegate(t, c.planKey), delegate(t, c.startKey)
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	plan.Capabilities = []string{"systemd.service.v1", "managed.file.v1", "local.account.v1"}
	start.Capabilities = slices.Clone(plan.Capabilities)
	if policy {
		plan.Capabilities = append(plan.Capabilities, trust.CapabilityPolicyCapability)
	}
	doc := delegationDocument(c.fix.deploy.String(), 1, version, 0, c.now, plan, start)
	callTrust(t, c.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, c.svc.authority, doc, c.fix.rootKey)})
}

func (c *capabilityFixture) policy(t *testing.T, version uint64, capabilities ...agentv1.ManagementCapability) *agentv1.AgentCapabilityPolicy {
	t.Helper()
	state := durable(t, c.svc)
	return &agentv1.AgentCapabilityPolicy{
		FormatVersion: 1, DeploymentId: c.fix.deploy.String(), DeviceId: state.GetDeviceId(), EnrollmentGeneration: state.GetEnrollmentGeneration(),
		Version: version, IssuedAt: protoTimestamp(c.now), Capabilities: capabilities,
	}
}

func (c *capabilityFixture) sign(t *testing.T, policy *agentv1.AgentCapabilityPolicy, key ed25519.PrivateKey) []byte {
	t.Helper()
	return mustSign(t, c.svc.authority, policy, key)
}

func (c *capabilityFixture) update(envelope []byte) (*agentv1.CapabilityPolicyObservation, error) {
	response, err := c.svc.UpdateCapabilityPolicy(context.Background(), connect.NewRequest(&agentv1.UpdateCapabilityPolicyRequest{PolicyEnvelope: envelope}))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetObservation(), nil
}

func (c *capabilityFixture) observe(t *testing.T) *agentv1.CapabilityPolicyObservation {
	t.Helper()
	response, err := c.svc.GetCapabilityPolicy(t.Context(), connect.NewRequest(&agentv1.GetCapabilityPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetObservation()
}

func capabilityStatus(observation *agentv1.CapabilityPolicyObservation, capability agentv1.ManagementCapability) *agentv1.CapabilityObservation {
	for _, status := range observation.GetCapabilities() {
		if status.GetCapability() == capability {
			return status
		}
	}
	return nil
}

func motdIntent(t *testing.T, c *capabilityFixture, path string) *agentv1.ResourceExecutionIntent {
	t.Helper()
	intent := c.intent(t, 1)
	desired := &resourcev1.ResourceDesiredState{State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: path, Presence: resourcev1.Presence_PRESENCE_PRESENT, Content: []byte("managed by lindm\n")}}}
	ref, err := resource.CanonicalRef(desired)
	if err != nil {
		t.Fatal(err)
	}
	desired.Ref = ref
	intent.Desired = desired
	return intent
}

func TestCapabilityPolicyAcceptReplayRollbackAndRestart(t *testing.T) {
	c := newCapabilityFixture(t, nil)
	if got := c.observe(t); got.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_NONE || got.GetAppliedVersion() != 0 || len(got.GetCapabilities()) != 9 {
		t.Fatalf("initial observation = %v", got)
	}
	files := agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES
	v2 := c.sign(t, c.policy(t, 2, files), c.planKey)
	accepted, err := c.update(v2)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(v2)
	if accepted.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE || accepted.GetAppliedVersion() != 2 || !slices.Equal(accepted.GetAppliedSha256(), digest[:]) || capabilityStatus(accepted, files).GetStatus() != agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED {
		t.Fatalf("accepted observation = %v", accepted)
	}
	record, err := capabilitypolicy.LoadRecord(c.svc.directory)
	if err != nil || !record.GetActive() || record.GetPolicy().GetVersion() != 2 {
		t.Fatalf("record = %v err = %v", record, err)
	}
	// Exact retransmission is idempotent and never rewrites acceptance.
	c.wall.Store(c.now.Add(time.Minute).UnixNano())
	if replay, err := c.update(v2); err != nil || !proto.Equal(replay, accepted) {
		t.Fatalf("replay = %v err = %v", replay, err)
	}
	after, err := capabilitypolicy.LoadRecord(c.svc.directory)
	if err != nil || !proto.Equal(after, record) {
		t.Fatal("exact replay rewrote the accepted record")
	}
	for name, envelope := range map[string][]byte{
		"older version":          c.sign(t, c.policy(t, 1, files), c.planKey),
		"same version new bytes": c.sign(t, c.policy(t, 2), c.planKey),
	} {
		if _, err := c.update(envelope); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	// Restart re-verifies and reinstalls the same effective providers.
	directory := c.svc.directory
	local, detect, enable := c.svc.capabilityLocal, c.svc.detectHost, c.svc.enableUnit
	if err := c.svc.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := New(t.Context(), directory, append(c.options(), WithCapabilityPolicy(local), WithCapabilityHost(detect), WithUnitEnabler(enable))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	c.svc = next
	if got := c.observe(t); got.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE || got.GetAppliedVersion() != 2 || !slices.Contains(c.svc.currentProviders().native.Files.GetAllowedRoots(), "/etc/motd.d") {
		t.Fatalf("restart lost the policy: %v", got)
	}
}

func TestCapabilityPolicyRejectsForeignBindingAndUndelegatedSigner(t *testing.T) {
	c := newCapabilityFixture(t, nil)
	files := agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES
	for name, policy := range map[string]func(*agentv1.AgentCapabilityPolicy){
		"other device":     func(p *agentv1.AgentCapabilityPolicy) { p.DeviceId = uuid.NewString() },
		"other generation": func(p *agentv1.AgentCapabilityPolicy) { p.EnrollmentGeneration = uuid.NewString() },
		"other deployment": func(p *agentv1.AgentCapabilityPolicy) { p.DeploymentId = uuid.NewString() },
	} {
		document := c.policy(t, 1, files)
		policy(document)
		if _, err := c.update(c.sign(t, document, c.planKey)); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := c.update(c.sign(t, c.policy(t, 1, files), c.startKey)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("START key policy: err = %v", err)
	}
	if record, err := capabilitypolicy.LoadRecord(c.svc.directory); err != nil || record != nil {
		t.Fatalf("rejected policy persisted: %v %v", record, err)
	}
}

func TestCapabilityPolicyRefusedLocally(t *testing.T) {
	c := newCapabilityFixture(t, &agentv1.AgentConfig{CapabilityPolicy: &agentv1.CapabilityPolicyConfig{RefuseRemote: true}})
	if _, err := c.update(c.sign(t, c.policy(t, 1, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES), c.planKey)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("refuse_remote accepted a policy: %v", err)
	}
	if got := c.observe(t); got.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_REFUSED_LOCALLY {
		t.Fatalf("state = %v", got.GetState())
	}
	if record, _ := capabilitypolicy.LoadRecord(c.svc.directory); record != nil {
		t.Fatal("refused policy persisted")
	}
}

func TestCapabilityPolicyBecomesInertWhenDelegationRevokesSigner(t *testing.T) {
	c := newCapabilityFixture(t, nil)
	files := agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES
	if _, err := c.update(c.sign(t, c.policy(t, 1, files), c.planKey)); err != nil {
		t.Fatal(err)
	}
	if c.svc.currentProviders().native.Files == nil {
		t.Fatal("FILES grant did not install the file provider")
	}
	c.delegate(t, 2, false)
	got := c.observe(t)
	if got.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_INERT || capabilityStatus(got, files).GetStatus() != agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED {
		t.Fatalf("observation after revocation = %v", got)
	}
	if record, err := capabilitypolicy.LoadRecord(c.svc.directory); err != nil || record.GetActive() {
		t.Fatalf("record stayed active: %v %v", record, err)
	}
	if c.svc.currentProviders().native.Files != nil {
		t.Fatal("revoked signer kept its remote file provider")
	}
	// A newer policy is refused until the owner delegates the capability again.
	if _, err := c.update(c.sign(t, c.policy(t, 2, files), c.planKey)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("undelegated signer accepted: %v", err)
	}
	c.delegate(t, 3, true)
	if got, err := c.update(c.sign(t, c.policy(t, 2, files), c.planKey)); err != nil || got.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE {
		t.Fatalf("reissued policy = %v err = %v", got, err)
	}
}

func TestCapabilityPolicySwapsProvidersWithoutTouchingOpenedSnapshots(t *testing.T) {
	c := newCapabilityFixture(t, nil)
	before := c.svc.currentProviders()
	if before.native.Files != nil || before.native.Accounts != nil {
		t.Fatal("stock executor enabled providers")
	}
	if _, err := c.update(c.sign(t, c.policy(t, 1, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_LOCAL_ACCOUNTS), c.planKey)); err != nil {
		t.Fatal(err)
	}
	after := c.svc.currentProviders()
	if after == before || !slices.Equal(after.native.Files.GetAllowedRoots(), []string{"/etc/issue.d", "/etc/motd.d"}) || after.native.Accounts == nil {
		t.Fatalf("effective providers = %v", after.config)
	}
	// An action that opened with the earlier snapshot keeps it unchanged.
	if before.native.Files != nil || before.native.Accounts != nil {
		t.Fatal("policy change mutated an opened provider snapshot")
	}
	if _, err := c.update(c.sign(t, c.policy(t, 2), c.planKey)); err != nil {
		t.Fatal(err)
	}
	if revoked := c.svc.currentProviders(); revoked.native.Files != nil || revoked.native.Accounts != nil || after.native.Files == nil {
		t.Fatal("empty policy did not revoke, or revocation mutated the opened snapshot")
	}
}

func TestCapabilityPolicyFirewallEnablesRestoreUnit(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "enabled"},
		{name: "enable fails", err: errors.New("systemd refused")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCapabilityFixture(t, nil)
			c.svc.mu.Lock()
			detect := c.svc.detectHost
			c.svc.detectHost = func(ctx context.Context) (capabilitypolicy.Host, error) {
				host, err := detect(ctx)
				host.Interfaces = func() ([]capabilitypolicy.Interface, error) {
					return []capabilitypolicy.Interface{{Name: "enp1s0", PermanentMAC: "52:54:00:12:34:56"}, {Name: "lo", Loopback: true}}, nil
				}
				return host, err
			}
			c.svc.mu.Unlock()
			c.enableErr = tc.err
			policy := c.policy(t, 1, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL)
			policy.Firewall = &agentv1.CapabilityFirewallSettings{
				ManagementEndpoints: []*agentv1.NativeFirewallEndpoint{{Address: "192.0.2.10", Port: 443}},
				ConnectivityGuard:   capabilityGuardConfig(),
			}
			observation, err := c.update(c.sign(t, policy, c.planKey))
			if err != nil {
				t.Fatal(err)
			}
			if c.enables.Load() != 1 {
				t.Fatalf("restore unit enables = %d", c.enables.Load())
			}
			status := capabilityStatus(observation, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL)
			if tc.err != nil && (status.GetStatus() != agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE || status.GetDetail() != capabilitypolicy.DetailFirewallRestoreUnitDisable) {
				t.Fatalf("failed enable status = %v", status)
			}
			if tc.err == nil && (status.GetStatus() != agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED || c.svc.currentProviders().native.Firewall == nil) {
				t.Fatalf("enabled unit still reported disabled: %v", status)
			}
		})
	}
}

func TestCapabilityGateRefusesBeforeNativeObservation(t *testing.T) {
	c := newCapabilityFixture(t, nil)
	var opens atomic.Int32
	c.svc.mu.Lock()
	c.svc.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
		opens.Add(1)
		return nil, errors.New("fixture native must not open")
	}
	c.svc.mu.Unlock()
	for _, tc := range []struct {
		path string
		want agentv1.ManagementCapability
	}{
		{"/etc/motd.d/50-lindm", agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES},
		{"/opt/example/lindm.conf", agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_CUSTOM_FILE_ROOTS},
	} {
		prepared, _ := c.prepare(t, motdIntent(t, c, tc.path))
		status := prepared.GetStatus()
		refusal := status.GetAdmissionRefusal()
		if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION ||
			refusal.GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED || refusal.GetCapability() != tc.want || !refusal.GetNativeEvidenceUnavailable() {
			t.Fatalf("%s: refusal = %v", tc.path, status)
		}
		if _, attested := attestResource(t, c.resourceFixture, status); !proto.Equal(attested.GetStatus(), status) {
			t.Fatal("signed history lost the capability refusal")
		}
	}
	// Package preparation intents are refused before anything is staged.
	intent := c.intent(t, 1)
	intent.Preparation = &agentv1.ResourceExecutionPreparation{Deadline: protoTimestamp(c.now.Add(4 * time.Minute)), MaxCacheBytes: 1 << 20}
	intent.Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/example/amd64"}, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "example", Architecture: "amd64"}, Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Exact{Exact: &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: "1.0-1"}}}, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "apt/" + uuid.NewString()}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA}}}
	plan, start := delegate(t, c.planKey), delegate(t, c.startKey)
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	plan.Capabilities, start.Capabilities = []string{"package.native.v1", trust.CapabilityPolicyCapability}, []string{"package.native.v1"}
	callTrust(t, c.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, c.svc.authority, delegationDocument(c.fix.deploy.String(), 1, 2, 0, c.now, plan, start), c.fix.rootKey)})
	intent.DelegationVersion = 2
	prepared, _ := c.prepare(t, intent)
	if refusal := prepared.GetStatus().GetAdmissionRefusal(); refusal.GetCapability() != agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES || prepared.GetStatus().GetPreparationOutcome() != nil {
		t.Fatalf("package preparation refusal = %v", prepared.GetStatus())
	}
	if opens.Load() != 0 || c.native.applies.Load() != 0 {
		t.Fatal("capability refusal opened or touched a native provider")
	}
	// Granting FILES admits the standard-root file to native preflight.
	c.delegate(t, 3, true)
	if _, err := c.update(c.sign(t, c.policy(t, 1, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FILES), c.planKey)); err != nil {
		t.Fatal(err)
	}
	granted := motdIntent(t, c, "/etc/motd.d/50-lindm")
	granted.DelegationVersion = 3
	if _, err := c.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: mustSign(t, c.svc.authority, granted, c.planKey)})); err == nil || opens.Load() != 1 {
		t.Fatalf("granted capability did not reach the provider: opens=%d err=%v", opens.Load(), err)
	}
}

func TestAdoptionRequiredRefusalCarriesDetail(t *testing.T) {
	for name, cause := range map[string]error{
		"file":    fileprovider.ErrAdoptionRequired,
		"account": accountprovider.ErrAdoptionRequired,
		"package": packageprovider.ErrAdoptionRequired,
		"ssh":     admissiondetail.Wrap(sshprovider.ErrAdoptionRequired, "existing_banner_file"),
	} {
		t.Run(name, func(t *testing.T) {
			f := newResourceFixture(t, false)
			native := &admissionRefusingNative{nativeResource: f.native, refusal: cause}
			f.svc.mu.Lock()
			f.svc.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
				return native, nil
			}
			f.svc.mu.Unlock()
			prepared, _ := f.prepare(t, f.intent(t, 1))
			status := prepared.GetStatus()
			refusal := status.GetAdmissionRefusal()
			if refusal.GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_ADOPTION_REQUIRED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION || refusal.GetCapability() != 0 || refusal.GetDetail() != admissiondetail.Of(cause) {
				t.Fatalf("refusal = %v", status)
			}
		})
	}
	// A detail on an ordinary precondition is preserved too.
	f := newResourceFixture(t, false)
	native := &admissionRefusingNative{nativeResource: f.native, refusal: admissiondetail.Wrap(sshprovider.ErrConflict, "reserved_drop_in")}
	f.svc.mu.Lock()
	f.svc.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
		return native, nil
	}
	f.svc.mu.Unlock()
	prepared, _ := f.prepare(t, f.intent(t, 1))
	if refusal := prepared.GetStatus().GetAdmissionRefusal(); refusal.GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION || refusal.GetDetail() != "reserved_drop_in" {
		t.Fatalf("precondition refusal = %v", refusal)
	}
}

func TestPreparationFailureClassifiesEveryUnsupported(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want agentv1.ResourceExecutionFailure
	}{
		"package unsupported": {packageprovider.ErrUnsupported, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED},
		"file unsupported":    {fileprovider.ErrUnsupported, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED},
		"package busy":        {packageprovider.ErrBusy, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY},
		"package conflict":    {packageprovider.ErrConflict, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION},
		"unclassified":        {errors.New("other"), agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION},
	} {
		if got := preparationFailure(tc.err); got != tc.want {
			t.Fatalf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestResourcePreparationPackageUnsupportedIsUnsupported(t *testing.T) {
	f, n, intent := newPreparationFixture(t)
	_, envelope := f.prepare(t, intent)
	n.planErr.Store(&packageUnsupported)
	response, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
	if err != nil {
		t.Fatal(err)
	}
	status := response.Msg.GetStatus()
	if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED || n.applies.Load() != 0 {
		t.Fatalf("unsupported staging = %v", status)
	}
}

var packageUnsupported = packageprovider.ErrUnsupported

func capabilityGuardConfig() *agentv1.ConnectivityGuardConfig {
	guard := &agentv1.ConnectivityGuardConfig{ConfirmationPublicKey: make([]byte, 32)}
	receiver := &agentv1.ConnectivityProbePeer{Origin: "https://probe.example.test", PublicKey: make([]byte, 32)}
	for _, address := range []string{"192.0.2.20", "2001:db8::20"} {
		for _, verdict := range []agentv1.ConnectivityProbeVerdict{agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW, agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY} {
			source := "192.0.2.30"
			if address != "192.0.2.20" {
				source = "2001:db8::30"
			}
			guard.Probes = append(guard.Probes, &agentv1.ConnectivityProbeTarget{
				Id: uuid.NewString(), Address: address, Port: 443, Expected: verdict, SourceAddress: source, SourcePort: 40000,
				Direction: agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT, Protocol: agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP,
				Receiver: proto.CloneOf(receiver),
			})
		}
	}
	return guard
}

// An effect-free staging refusal keeps the provider's closed actionable detail
// in the signed preparation outcome, so the server can name the cause.
func TestResourcePreparationFailureCarriesDetail(t *testing.T) {
	for _, tc := range []struct {
		err     error
		failure agentv1.ResourceExecutionFailure
		detail  string
	}{
		{admissiondetail.Wrap(fmt.Errorf("%w: installed provenance unknown", packageprovider.ErrConflict), "existing_package_unverified"), agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION, "existing_package_unverified"},
		{admissiondetail.Wrap(fmt.Errorf("%w: native dnf5 5.4.6.0 or newer required", packageprovider.ErrUnsupported), "native_tool_outdated"), agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED, "native_tool_outdated"},
		{packageprovider.ErrConflict, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION, ""},
	} {
		f, n, intent := newPreparationFixture(t)
		_, envelope := f.prepare(t, intent)
		n.planErr.Store(&tc.err)
		response, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
		if err != nil {
			t.Fatal(err)
		}
		status := response.Msg.GetStatus()
		if status.GetFailure() != tc.failure || status.GetPreparationOutcome().GetFailure() != tc.failure || status.GetPreparationOutcome().GetDetail() != tc.detail || n.applies.Load() != 0 {
			t.Fatalf("%v: staging outcome = %v", tc.err, status)
		}
		if _, attested := attestResource(t, f, status); !proto.Equal(attested.GetStatus(), status) {
			t.Fatalf("%v: signed history lost the preparation detail", tc.err)
		}
	}
}
