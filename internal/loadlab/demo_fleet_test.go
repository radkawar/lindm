// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/orgapply"
	"lindm/internal/resource"
)

func fleetTestDevice(t *testing.T) (*demoDevice, []*resourcev1.ResourceDesiredState, *resourcev1.ObservationMetadata) {
	t.Helper()
	source := filepath.Join("..", "..")
	body, err := os.ReadFile(filepath.Join(source, "lab", "demo", "org.json"))
	if err != nil {
		t.Fatal(err)
	}
	organization, err := orgapply.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	devices, err := demoDevices(source)
	if err != nil {
		t.Fatal(err)
	}
	var device *demoDevice
	for _, candidate := range devices {
		if candidate.hostname == "fleet-pilot-01" {
			device = candidate
		}
	}
	if device == nil {
		t.Fatal("missing isolated fleet pilot")
	}
	policy := &agentv1.AgentCapabilityPolicy{FormatVersion: 1, DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(), Version: 1, IssuedAt: timestamppb.Now()}
	for _, entry := range organization.GetCapabilityPolicies() {
		request := entry.GetRequest()
		if request.GetScope().GetDeployment() {
			policy.Capabilities = append(policy.Capabilities, request.GetCapabilities()...)
			policy.SysctlKeys = append(policy.SysctlKeys, request.GetSysctlKeys()...)
			policy.Firewall = proto.CloneOf(request.GetFirewall())
		} else if request.GetScope().GetStaticGroupId() == "fecd06a9-ce59-4fdf-ae82-722527f58b77" {
			policy.Capabilities = append(policy.Capabilities, request.GetCapabilities()...)
		}
	}
	if err := device.agent.accept(device.release, &agentv1.CapabilityPolicyRecord{FormatVersion: 1, PolicyEnvelope: []byte("synthetic envelope"), Policy: policy, AcceptedAt: timestamppb.Now(), Active: true}); err != nil {
		t.Fatal(err)
	}
	zoneID := uuid.NewString()
	repository := "apt/" + device.agent.effective.Config.GetPackageProvider().GetSources()[0].GetRepository().GetRepositoryId()
	var updates *resourcev1.OSUpdateDesired
	for _, profile := range organization.GetProfiles() {
		for _, item := range profile.GetSpec().GetResources() {
			if item.GetDesired().GetOsUpdate() != nil {
				updates = proto.CloneOf(item.GetDesired().GetOsUpdate())
			}
		}
	}
	if updates == nil {
		t.Fatal("missing update policy fixture")
	}
	wanted := []*resourcev1.ResourceDesiredState{
		{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/curl"}, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "curl"}, Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: repository}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA}}},
		{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}, State: &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String("Authorized use only. Contact IT for help.")}}},
		{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, CanonicalKey: zoneID}, State: &resourcev1.ResourceDesiredState_FirewallZone{FirewallZone: &resourcev1.FirewallZoneDesired{ZoneId: zoneID, Presence: resourcev1.Presence_PRESENCE_PRESENT, SourceNetworks: []*resourcev1.CIDR{{NetworkAddress: "192.0.2.0", PrefixLength: 24}, {NetworkAddress: "2001:db8::", PrefixLength: 32}}, DefaultIngress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_DROP, DefaultEgress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT}}},
		{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, CanonicalKey: "system"}, State: &resourcev1.ResourceDesiredState_OsUpdate{OsUpdate: updates}},
	}
	metadata := &resourcev1.ObservationMetadata{BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), ObservedAt: timestamppb.Now(), NativeRevision: bytes.Repeat([]byte{1}, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK, Backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: "synthetic", ProviderVersion: "loadlab-synthetic", Product: &resourcev1.PlatformProduct{OsId: "synthetic", Product: "protocol load fixture", Version: "1", Architecture: "synthetic"}}}
	return device, wanted, metadata
}

func TestFleetModelRetainsTypedEffectsAfterStart(t *testing.T) {
	device, wanted, metadata := fleetTestDevice(t)
	for _, desired := range wanted {
		t.Run(desired.GetRef().GetKind().String(), func(t *testing.T) {
			before, err := device.fleetObservation(desired, metadata)
			if err != nil {
				t.Fatal(err)
			}
			intent := &agentv1.ResourceExecutionIntent{Desired: desired, Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE}
			plan, err := device.fleetPlan(intent, before, metadata.GetNativeRevision())
			if err != nil {
				t.Fatal(err)
			}
			planDigest, err := resource.PlanDigest(plan)
			if err != nil {
				t.Fatal(err)
			}
			if device.fleet[serviceKey(desired.GetRef())] != nil {
				t.Fatal("preparation changed the model")
			}
			pending := &pendingService{intent: intent, challenge: &agentv1.ResourceExecutionChallenge{NativePlanSha256: planDigest[:]}, status: &agentv1.ResourceExecutionStatus{Before: before}}
			if err := device.applyFleet(pending); err != nil {
				t.Fatal(err)
			}
			if pending.status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
				t.Fatalf("model did not converge: %v", pending.status)
			}
			if err := resource.ValidatePlanVerification(plan, pending.status.GetVerification()); err != nil {
				t.Fatal(err)
			}
			if pending.status.GetVerification().GetAfter().GetMetadata().GetBackend().GetProduct().GetOsId() != "synthetic" {
				t.Fatal("model masquerades as native evidence")
			}
			if !proto.Equal(device.fleet[serviceKey(desired.GetRef())], desired) {
				t.Fatal("model did not retain effect")
			}
		})
	}
	wanted[1].GetSshServer().BannerText = proto.String("Changed outside the retained model")
	if device.fleet[serviceKey(wanted[1].GetRef())].GetSshServer().GetBannerText() == wanted[1].GetSshServer().GetBannerText() {
		t.Fatal("model shares mutable desired authority")
	}
}

func TestFleetModelDoesNotInventDenyProbeSuccess(t *testing.T) {
	device, wanted, metadata := fleetTestDevice(t)
	desired := wanted[2]
	desired.GetFirewallZone().SourceNetworks = desired.GetFirewallZone().SourceNetworks[:1]
	before, err := device.fleetObservation(desired, metadata)
	if err != nil {
		t.Fatal(err)
	}
	pending := &pendingService{intent: &agentv1.ResourceExecutionIntent{Desired: desired}, challenge: &agentv1.ResourceExecutionChallenge{NativePlanSha256: metadata.GetNativeRevision()}, status: &agentv1.ResourceExecutionStatus{Before: before}}
	if err := device.applyFleet(pending); err != nil {
		t.Fatal(err)
	}
	if pending.status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || pending.status.GetVerification().GetFirewallZone().GetDenyPacketProbe().GetPassed() {
		t.Fatal("missing IPv6 deny scope was reported successful")
	}
	if err := resource.ValidateVerification(pending.status.GetVerification()); err != nil {
		t.Fatal(err)
	}
}

func TestFleetModelDoesNotExpandOtherDemoHosts(t *testing.T) {
	device, wanted, metadata := fleetTestDevice(t)
	device.fleetPilot = false
	for _, desired := range wanted {
		if device.fleetSupports(desired) {
			t.Fatal("ordinary host acquired synthetic providers")
		}
		status, err := device.immediateResult(&agentv1.ResourceExecutionIntent{Desired: desired, Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, Ownership: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION}}}, metadata.GetNativeRevision(), &resourcev1.ResourceObservation{Metadata: metadata})
		if err != nil {
			t.Fatal(err)
		}
		if status.GetAdmissionRefusal().GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE {
			t.Fatalf("ordinary host lost its unsupported refusal: %v", status)
		}
	}
}
