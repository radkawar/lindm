// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/orgapply"
)

// The demo hosts' executor statuses and admission refusals come from the
// agent's own derivation for lab/demo/org.json's capability policies, so the
// console review shows every capability status and blocked reason the product
// produces.
func TestDemoAgentsDeriveEveryCapabilityState(t *testing.T) {
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
	// The organization's deployment policy plus each department's group grant:
	// provisioning tokens place a department's devices in their static groups.
	var deployment *adminv1.SetCapabilityPolicyRequest
	group := map[string]*adminv1.SetCapabilityPolicyRequest{}
	for _, entry := range organization.GetCapabilityPolicies() {
		if entry.GetRequest().GetScope().GetDeployment() {
			deployment = entry.GetRequest()
		}
		for _, token := range organization.GetProvisioningTokens() {
			if slices.Contains(token.GetRequest().GetGroupIds(), entry.GetRequest().GetScope().GetStaticGroupId()) {
				group[token.GetName()] = entry.GetRequest()
			}
		}
	}
	if deployment == nil || group["engineering"] == nil || group["finance"] == nil {
		t.Fatalf("lab/demo/org.json lacks the deployment, Engineering or Finance capability policy: %v %v", deployment, group)
	}
	resources := map[string]*policyv1.ProfileResource{}
	for _, profile := range organization.GetProfiles() {
		for _, item := range profile.GetSpec().GetResources() {
			resources[profile.GetSpec().GetName()+" "+item.GetDesired().GetRef().GetCanonicalKey()] = item
		}
	}
	type refusal struct {
		reason     agentv1.ResourceAdmissionRefusalReason
		capability agentv1.ManagementCapability
		detail     string
	}
	capabilityRefusal := func(c agentv1.ManagementCapability) refusal {
		return refusal{agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED, c, ""}
	}
	adoption := func(detail string) refusal {
		return refusal{agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_ADOPTION_REQUIRED, 0, detail}
	}
	const (
		enabled     = agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED
		local       = agentv1.CapabilityStatus_CAPABILITY_STATUS_LOCAL
		off         = agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED
		unavailable = agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE
	)
	firewall := "Company baseline db7f6c12-b34a-59d7-aae7-b5474fdc3f92"
	redirects := "Company baseline net.ipv4.conf.all.accept_redirects"
	password := "Company baseline system/local-auth"
	// Password policy is local-only: no signed policy grants it, so every stock
	// host blocks the row with the executor.json field root must set.
	passwordRefusal := capabilityRefusal(agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PASSWORD_POLICY)
	for _, tc := range []struct {
		hostname string
		// Catalogue order 1-9.
		statuses []agentv1.CapabilityStatus
		detail   map[agentv1.ManagementCapability]string
		refusals map[string]refusal
		// Refusals of the same rows declared create-only rather than adopted.
		createOnly map[string]refusal
	}{
		{
			hostname: "ubuntu-ws-01", statuses: []agentv1.CapabilityStatus{enabled, enabled, off, enabled, off, enabled, enabled, off, off},
			refusals: map[string]refusal{
				firewall: capabilityRefusal(agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL),
				// From the vendor archive the device derives itself.
				"Engineering tools deb/git": {},
				// Ubuntu's base-files issue.net is adopted, not a collision.
				"Engineering tools system":                {},
				"Engineering tools developer":             {},
				"Company baseline /etc/motd.d/50-company": {},
				redirects: {},
				password:  passwordRefusal,
				"Finance hardened /etc/modprobe.d/99-lindm-blocklist.conf": capabilityRefusal(agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_MODULE_BLOCKLIST),
			},
			createOnly: map[string]refusal{"Engineering tools system": adoption("existing_banner_file")},
		},
		{
			hostname: "ubuntu-ws-02", statuses: []agentv1.CapabilityStatus{unavailable, enabled, off, enabled, off, enabled, enabled, off, off},
			detail: map[agentv1.ManagementCapability]string{agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES: "vendor_key_unrecognized"},
			refusals: map[string]refusal{
				"Engineering tools deb/git":    capabilityRefusal(agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES),
				"Engineering tools developers": adoption("existing_account"),
				"Engineering tools developer":  {},
				password:                       passwordRefusal,
			},
		},
		{
			hostname: "fedora-ws-03", statuses: []agentv1.CapabilityStatus{enabled, enabled, enabled, enabled, off, enabled, enabled, off, off},
			refusals: map[string]refusal{
				firewall: capabilityRefusal(agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL),
				"Finance hardened /etc/modprobe.d/99-lindm-blocklist.conf": {},
				redirects: {},
				password:  passwordRefusal,
			},
		},
		{
			hostname: "ubuntu-srv-04", statuses: []agentv1.CapabilityStatus{enabled, local, off, enabled, off, enabled, enabled, off, local},
			refusals: map[string]refusal{"Company baseline /etc/motd.d/50-company": {}, redirects: {}, password: passwordRefusal},
		},
	} {
		t.Run(tc.hostname, func(t *testing.T) {
			var device *demoDevice
			for _, candidate := range devices {
				if candidate.hostname == tc.hostname {
					device = candidate
				}
			}
			if device == nil || device.agent == nil {
				t.Fatalf("%s has no capability-aware agent", tc.hostname)
			}
			if device.observation(nil, "synthetic-boot", timestamppb.Now()).GetDetails().GetApprovedConfiguration() != nil {
				t.Fatal("an executor without accepted configuration reported approvals")
			}
			policy := &agentv1.AgentCapabilityPolicy{FormatVersion: 1, DeploymentId: "11111111-1111-4111-8111-111111111111", DeviceId: "22222222-2222-4222-8222-222222222222", EnrollmentGeneration: "33333333-3333-4333-8333-333333333333", Version: 1, IssuedAt: timestamppb.Now(), Capabilities: slices.Clone(deployment.GetCapabilities()), SysctlKeys: slices.Clone(deployment.GetSysctlKeys())}
			// The server signs the union of every applicable scope.
			if extra := group[device.department]; extra != nil {
				for _, c := range extra.GetCapabilities() {
					if !slices.Contains(policy.Capabilities, c) {
						policy.Capabilities = append(policy.Capabilities, c)
					}
				}
				for _, key := range extra.GetSysctlKeys() {
					if !slices.Contains(policy.SysctlKeys, key) {
						policy.SysctlKeys = append(policy.SysctlKeys, key)
					}
				}
			}
			if err := device.agent.accept(device.release, &agentv1.CapabilityPolicyRecord{FormatVersion: 1, PolicyEnvelope: []byte("synthetic envelope"), Policy: policy, AcceptedAt: timestamppb.Now(), Active: true}); err != nil {
				t.Fatal(err)
			}
			now := timestamppb.Now()
			approved := device.observation(nil, "synthetic-boot", now).GetDetails().GetApprovedConfiguration()
			sources := device.agent.effective.Config.GetPackageProvider().GetSources()
			if !proto.Equal(approved.GetObservedAt(), now) || len(approved.GetPackageSources()) != len(sources) {
				t.Fatalf("approved configuration did not report effective package sources: %v", approved)
			}
			for index, source := range sources {
				if !proto.Equal(approved.PackageSources[index], source.GetRepository()) {
					t.Fatalf("approved source lost registry-derived authority: %v", approved.PackageSources[index])
				}
				approved.PackageSources[index].RepositoryId = "changed"
				if source.GetRepository().GetRepositoryId() == "changed" {
					t.Fatal("inventory report shares mutable effective package authority")
				}
			}
			report := device.agent.report
			if report.GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE || report.GetAppliedVersion() != 1 || len(report.GetAppliedSha256()) != 32 || len(report.GetCapabilities()) != len(tc.statuses) {
				t.Fatalf("report %v", report)
			}
			for i, observed := range report.GetCapabilities() {
				if observed.GetCapability() != agentv1.ManagementCapability(i+1) || observed.GetStatus() != tc.statuses[i] || observed.GetDetail() != tc.detail[observed.GetCapability()] {
					t.Errorf("%v: %v %q, want %v %q", observed.GetCapability(), observed.GetStatus(), observed.GetDetail(), tc.statuses[i], tc.detail[observed.GetCapability()])
				}
			}
			for key, want := range tc.refusals {
				item := resources[key]
				if item == nil {
					t.Fatalf("lab/demo/org.json has no %s", key)
				}
				reason, capability, detail := device.agent.admission(item.GetDesired(), item.GetOwnership().GetMode())
				if got := (refusal{reason, capability, detail}); got != want {
					t.Errorf("%s: %v, want %v", key, got, want)
				}
			}
			for key, want := range tc.createOnly {
				reason, capability, detail := device.agent.admission(resources[key].GetDesired(), resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY)
				if got := (refusal{reason, capability, detail}); got != want {
					t.Errorf("%s create-only: %v, want %v", key, got, want)
				}
			}
		})
	}
	// Agents older than capability policies keep refusing unknown kinds as
	// unsupported; the console shows they have not reported.
	for _, device := range devices {
		if device.hostname == "rhel-srv-05" && device.agent != nil {
			t.Fatal("rhel-srv-05 must keep an agent that does not report capability policies")
		}
	}
}
