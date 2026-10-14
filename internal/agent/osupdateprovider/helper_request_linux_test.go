// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdateprovider

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// journalLedger is a ledger in the exact shape the journal stores: claimed
// over the observed baseline (creation) or applied over the last effect.
func journalLedger(p *Provider, state agentv1.ResourceOwnershipState, baseline, last *agentv1.ResourceOwnershipSnapshot) *agentv1.ResourceOwnershipLedger {
	ledger := &agentv1.ResourceOwnershipLedger{
		FormatVersion: 1, InstallationId: uuid.NewString(), DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(),
		Ref: osUpdateRef(), Owner: proto.CloneOf(p.config.Ownership), Revision: 1, State: state, Baseline: proto.CloneOf(baseline),
		OwnerIntentEnvelope: []byte("signed intent"), ClaimActionId: uuid.NewString(),
	}
	if last != nil {
		ledger.Revision = 3
		ledger.LastApplied = proto.CloneOf(last)
		ledger.OwnedDimensions = ownedDimensions()
	}
	return ledger
}

// requireHelperAdmits applies every check the transport to the root helper
// performs on the request (encodeRecord in LaunchResource, readRecord and the
// ExecuteNative preconditions in RunResource) and on its reported after-image.
func requireHelperAdmits(t *testing.T, plan *resourcev1.ResourcePlan, before, target, after *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger) {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	request := &agentv1.NativeResourceTransactionRequest{Plan: plan, Before: before, Target: target, Ownership: ledger, ActionId: uuid.NewString(), Nonce: nonce}
	if err := validateMessage(request); err != nil {
		t.Fatalf("native helper rejects the update policy request: %v", err)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(agentv1.NativeResourceTransactionRequest)
	if err := proto.Unmarshal(encoded, decoded); err != nil || validateMessage(decoded) != nil || !proto.Equal(decoded, request) {
		t.Fatalf("helper request does not survive its protected record: %v", err)
	}
	if err := resource.ValidatePlan(decoded.GetPlan()); err != nil {
		t.Fatalf("helper rejects the plan: %v", err)
	}
	if err := validateDesired(resource.PlanDesired(decoded.GetPlan())); err != nil {
		t.Fatalf("helper rejects the planned desired state: %v", err)
	}
	if !proto.Equal(decoded.GetOwnership().GetRef(), osUpdateRef()) || !sameObserved(decoded.GetBefore().GetObservation(), decoded.GetPlan().GetBefore()) {
		t.Fatal("helper request is not bound to its plan")
	}
	for _, observation := range []*resourcev1.ResourceObservation{decoded.GetBefore().GetObservation(), decoded.GetTarget().GetObservation()} {
		if err := resource.ValidateObservation(observation); err != nil {
			t.Fatalf("helper rejects a carried observation: %v", err)
		}
	}
	sum := sha256.Sum256(encoded)
	result := &agentv1.NativeHelperResult{RequestSha256: sum[:], Nonce: nonce, Outcome: agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_SUCCEEDED, After: after}
	if err := validateMessage(result); err != nil {
		t.Fatalf("helper cannot report the update policy after-image: %v", err)
	}
}

// The Fedora lane found the helper request CEL closed to this kind: every
// effect then failed after the ledger entered UNKNOWN. These requests are the
// exact ones Apply sends.
func TestHelperAdmitsCreationAndReleaseRequests(t *testing.T) {
	for _, backend := range []struct {
		update  resourcev1.OSUpdateBackend
		native  resourcev1.Backend
		version string
		product *resourcev1.PlatformProduct
	}{
		{resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES, resourcev1.Backend_BACKEND_APT, "unattended-upgrades 2.9.1+nmu4ubuntu1", &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "amd64"}},
		{resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC, resourcev1.Backend_BACKEND_DNF5, "dnf5-plugin-automatic 5.2.17.0-1.fc44", &resourcev1.PlatformProduct{OsId: "fedora", Product: "Fedora Linux", Version: "44", Architecture: "x86_64"}},
		{resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, resourcev1.Backend_BACKEND_DNF4, "dnf-automatic 4.14.0-25.el9", &resourcev1.PlatformProduct{OsId: "rhel", Product: "Red Hat Enterprise Linux", Version: "9.8", Architecture: "x86_64"}},
		{resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, resourcev1.Backend_BACKEND_DNF4, "dnf-automatic 4.20.0-11.el10", &resourcev1.PlatformProduct{OsId: "rhel", Product: "Red Hat Enterprise Linux", Version: "10.2", Architecture: "x86_64"}},
	} {
		t.Run(backend.product.GetOsId()+" "+backend.product.GetVersion(), func(t *testing.T) {
			p := fixtureProvider(t)
			p.update = backend.update
			p.backend = &resourcev1.BackendSelection{Backend: backend.native, NativeVersion: backend.version, ProviderVersion: "1", Product: backend.product}
			p.config.Platform = backend.product
			desired := fixtureDesired()
			baseline := fixtureSnapshot(t, p, nil, false, "")
			plan, target, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, baseline, nil)
			if err != nil {
				t.Fatal(err)
			}
			applied := convergedSnapshot(t, p, desired)
			requireHelperAdmits(t, plan, baseline, target, applied, journalLedger(p, agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED, baseline, nil))

			ledger := journalLedger(p, agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, baseline, applied)
			plan, target, err = p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, applied, ledger)
			if err != nil {
				t.Fatal(err)
			}
			requireHelperAdmits(t, plan, applied, target, baseline, ledger)
		})
	}
}

func TestOnlyQualifiedMutableProductsHaveABackend(t *testing.T) {
	for _, test := range []struct {
		os, version string
		want        resourcev1.OSUpdateBackend
	}{
		{"ubuntu", "24.04", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES},
		{"fedora", "44", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC},
		{"fedora", "43", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC},
		{"rhel", "9.8", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC},
		{"rhel", "10.2", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC},
		{"arch", "", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN},
		{"opensuse-tumbleweed", "20261007", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER},
		{"ubuntu", "22.04", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES},
		{"almalinux", "9.8", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC},
		{"rocky", "10.2", resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC},
		{"opensuse-leap", "16.0", 0},
		{"rhel", "8.10", 0},
		{"rhel", "100.1", 0},
		{"fedora", "42", 0},
		{"debian", "13", 0},
		{"debian", "12", 0},
		{"almalinux", "8.10", 0},
	} {
		got, _, ok := productBackend(&resourcev1.PlatformProduct{OsId: test.os, Version: test.version})
		if ok != (test.want != 0) || got != test.want {
			t.Fatalf("%s %s backend = %v %v, want %v", test.os, test.version, got, ok, test.want)
		}
	}
}
