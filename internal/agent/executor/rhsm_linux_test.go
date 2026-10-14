// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/capabilitypolicy"
	"lindm/internal/agent/rhsm"
	"lindm/internal/platform"
	"lindm/internal/trust"
)

func TestEntitlementCapabilityRefusalKeepsSignedRegistrationRemedy(t *testing.T) {
	c := newCapabilityFixture(t, nil)
	key, err := os.ReadFile("../rhsm/testdata/redhat-release2.asc")
	if err != nil {
		t.Fatal(err)
	}
	row, _ := platform.Lookup("rhel-9")
	var opens atomic.Int32
	c.svc.mu.Lock()
	c.svc.detectHost = func(context.Context) (capabilitypolicy.Host, error) {
		return capabilitypolicy.Host{Release: row, Architecture: "x86_64", ReadVendorKey: func(string) ([]byte, error) { return key, nil }}, nil
	}
	c.svc.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
		opens.Add(1)
		t.Fatal("unregistered package opened a native provider")
		return nil, nil
	}
	c.svc.mu.Unlock()
	plan, start := delegate(t, c.planKey), delegate(t, c.startKey)
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	plan.Capabilities, start.Capabilities = []string{"package.native.v1", trust.CapabilityPolicyCapability}, []string{"package.native.v1"}
	callTrust(t, c.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, c.svc.authority, delegationDocument(c.fix.deploy.String(), 1, 2, 0, c.now, plan, start), c.fix.rootKey)})
	if _, err := c.update(c.sign(t, c.policy(t, 1, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES), c.planKey)); err != nil {
		t.Fatal(err)
	}
	intent := c.intent(t, 1)
	intent.DelegationVersion = 2
	intent.Preparation = &agentv1.ResourceExecutionPreparation{Deadline: protoTimestamp(c.now.Add(4 * time.Minute)), MaxCacheBytes: 1 << 20}
	intent.Desired = &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "rpm/example/x86_64"},
		State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{
			Package:  &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: "example", Architecture: "x86_64"},
			Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Any{Any: new(resourcev1.AnyApprovedVersion)},
			Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "rpm/" + row.VendorRepositories[0].RepositoryID},
			Removal:    resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA,
		}},
	}
	prepared, _ := c.prepare(t, intent)
	status := prepared.GetStatus()
	refusal := status.GetAdmissionRefusal()
	if refusal.GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED || refusal.GetCapability() != agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES || refusal.GetDetail() != capabilitypolicy.DetailRHSMRegistrationRequired || !refusal.GetNativeEvidenceUnavailable() || status.GetPreparationOutcome() != nil || opens.Load() != 0 {
		t.Fatalf("entitlement remedy or effect-free gate lost: %v", status)
	}
	if _, attested := attestResource(t, c.resourceFixture, status); !proto.Equal(attested.GetStatus(), status) {
		t.Fatal("signed refusal dropped local registration remedy")
	}
}

// No native registration is claimed here: the host seam changes prerequisite
// evidence while the real signed-policy storage/reverification path stays fixed.
func TestEntitledPrerequisiteRefreshKeepsSameSignedAuthority(t *testing.T) {
	c := newCapabilityFixture(t, nil)
	key, err := os.ReadFile("../rhsm/testdata/redhat-release2.asc")
	if err != nil {
		t.Fatal(err)
	}
	row, _ := platform.Lookup("rhel-9")
	var keyReady atomic.Bool
	var entitlementReads atomic.Int32
	c.svc.mu.Lock()
	c.svc.detectHost = func(context.Context) (capabilitypolicy.Host, error) {
		return capabilitypolicy.Host{
			Release: row, Architecture: "x86_64",
			ReadVendorKey: func(string) ([]byte, error) {
				if !keyReady.Load() {
					return nil, os.ErrNotExist
				}
				return key, nil
			},
			ReadEntitledConfig: func(platform.VendorRepository, string) error {
				entitlementReads.Add(1)
				return rhsm.ErrRegistrationRequired
			},
		}, nil
	}
	c.svc.mu.Unlock()
	packages := agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES
	envelope := c.sign(t, c.policy(t, 1, packages), c.planKey)
	accepted, err := c.update(envelope)
	if err != nil {
		t.Fatal(err)
	}
	assertSameAuthority := func(observation *agentv1.CapabilityPolicyObservation, detail string) {
		t.Helper()
		status := capabilityStatus(observation, packages)
		if observation.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE ||
			observation.GetAppliedVersion() != accepted.GetAppliedVersion() ||
			!proto.Equal(observation.GetAcceptedAt(), accepted.GetAcceptedAt()) ||
			string(observation.GetAppliedSha256()) != string(accepted.GetAppliedSha256()) ||
			status.GetStatus() != agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE || status.GetDetail() != detail {
			t.Fatalf("prerequisite refresh changed authority or retained stale evidence: %v", observation)
		}
	}
	assertSameAuthority(accepted, capabilitypolicy.DetailVendorKeyUnrecognized)
	keyReady.Store(true)
	assertSameAuthority(c.observe(t), capabilitypolicy.DetailRHSMRegistrationRequired)
	if entitlementReads.Load() == 0 {
		t.Fatal("management observation did not re-read local entitlement")
	}
	// Exact policy retransmission also refreshes evidence, without changing
	// acceptance time/version or persisting a fresh capability record.
	keyReady.Store(false)
	replayed, err := c.update(envelope)
	if err != nil {
		t.Fatal(err)
	}
	assertSameAuthority(replayed, capabilitypolicy.DetailVendorKeyUnrecognized)
	// Admission refreshes before the effect-free package gate, even if no
	// management observation has occurred since local state changed.
	before := entitlementReads.Load()
	keyReady.Store(true)
	desired := &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE},
		State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{
			Repository: &resourcev1.ResourceRef{CanonicalKey: "rpm/" + row.VendorRepositories[0].RepositoryID},
		}},
	}
	c.svc.mu.Lock()
	gateErr := c.svc.requiredCapability(t.Context(), desired)
	c.svc.mu.Unlock()
	if admissiondetail.Of(gateErr) != capabilitypolicy.DetailRHSMRegistrationRequired || entitlementReads.Load() <= before {
		t.Fatalf("admission reused frozen prerequisite evidence: %v", gateErr)
	}
	// An inert policy cannot become active because local prerequisites change.
	c.delegate(t, 2, false)
	before = entitlementReads.Load()
	inert := c.observe(t)
	if inert.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_INERT ||
		capabilityStatus(inert, packages).GetStatus() != agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED ||
		entitlementReads.Load() != before {
		t.Fatalf("local prerequisite refresh reactivated revoked authority: %v", inert)
	}
}
