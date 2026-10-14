// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/capabilitypolicy"
	"lindm/internal/platform"
)

// demoVendorKey stands in for an OS vendor's archive signing key on synthetic
// hosts. A host that "recognizes" it derives from a copy of its registry row
// whose accepted digest is this key's; the registry itself is never changed
// and no real vendor key is claimed.
var demoVendorKey = []byte("lindm synthetic console demo vendor key, not a real archive key\n")

// demoAgent is how one demo host's simulated executor treats signed
// capability policies. Hosts without one run an agent older than capability
// policies: they neither fetch nor report them.
type demoAgent struct {
	// vendorKey is false when the host's vendor key file is not one lindm
	// recognizes, so Software packages derive as unavailable.
	vendorKey bool
	// local is the root-owned executor.json; nil is the stock empty file.
	local *agentv1.AgentConfig
	// collisions is the closed adoption detail a create-only item of this kind
	// meets on the host: an unowned native object lindm did not create. An
	// approved adoption takes the object over instead.
	collisions map[resourcev1.ResourceKind]string

	// Set once the host has accepted its signed policy.
	host      capabilitypolicy.Host
	effective *capabilitypolicy.Effective
	report    *agentv1.CapabilityPolicyObservation
}

// demoAgents covers every executor capability status: enabled, set locally,
// not enabled, and unavailable (vendor key unrecognized). rhel-srv-05 keeps an
// agent older than capability policies, so the console shows a device that has
// not reported them.
func demoAgents() map[string]*demoAgent {
	banner := map[resourcev1.ResourceKind]string{
		// Ubuntu's base-files ships /etc/issue.net.
		resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER: "existing_banner_file",
	}
	return map[string]*demoAgent{
		"ubuntu-ws-01": {vendorKey: true, collisions: banner},
		"ubuntu-ws-02": {collisions: map[resourcev1.ResourceKind]string{
			resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER: "existing_banner_file",
			// The employee created a local developers group before enrollment;
			// the developer account that depends on it then waits on it.
			resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP: "existing_account",
		}},
		"fedora-ws-03": {vendorKey: true},
		// Root on the build server approved its build output root by hand.
		"ubuntu-srv-04":   {vendorKey: true, local: &agentv1.AgentConfig{FileProvider: &agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/etc/issue.d", "/etc/motd.d", "/srv/build/etc"}}}},
		demoScaleHostname: {vendorKey: true},
	}
}

// acceptCapabilityPolicy fetches, verifies and applies the device's signed
// policy, as the network process does right after execution trust and before
// publishing inventory, so the first host report carries the executor status
// and capability refusals are never re-dispatched by a status change.
func (r *runner) acceptCapabilityPolicy(ctx context.Context, d *simulatedDevice) error {
	response, err := d.client.GetCapabilityPolicy(ctx, connect.NewRequest(&devicev1.GetCapabilityPolicyRequest{SessionEpoch: d.epoch}))
	if err != nil {
		return err
	}
	if reason := response.Msg.GetUnavailableReason(); reason != "" {
		return fmt.Errorf("server issued no policy: %s", reason)
	}
	envelope := response.Msg.GetPolicyEnvelope()
	policy, err := r.verifier.VerifyCapabilityPolicy(ctx, d.root, d.delegation, envelope, time.Now())
	if err != nil {
		return err
	}
	if policy.GetDeviceId() != d.id || policy.GetEnrollmentGeneration() != d.generation {
		return errors.New("capability policy identity mismatch")
	}
	return d.demo.agent.accept(d.demo.release, &agentv1.CapabilityPolicyRecord{FormatVersion: 1, PolicyEnvelope: envelope, Policy: policy, AcceptedAt: timestamppb.Now(), Active: true})
}

// accept derives the effective providers and the reported status from an
// accepted record, exactly as the executor does for the same host evidence.
func (a *demoAgent) accept(release *platform.Release, record *agentv1.CapabilityPolicyRecord) error {
	a.host = demoCapabilityHost(release, a.vendorKey)
	local := a.local
	if local == nil {
		local = new(agentv1.AgentConfig)
	}
	effective, err := capabilitypolicy.Derive(local, record, a.host)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(record.GetPolicyEnvelope())
	a.effective = effective
	a.report = &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE, AppliedVersion: record.GetPolicy().GetVersion(), AppliedSha256: digest[:], AcceptedAt: record.GetAcceptedAt(), Capabilities: effective.Status}
	return nil
}

// demoCapabilityHost is synthetic host evidence: one wired interface with a
// permanent address, an enabled firewall restore unit and the stand-in vendor
// key, recognized only when vendorKey is set.
func demoCapabilityHost(row *platform.Release, vendorKey bool) capabilitypolicy.Host {
	release := row
	if vendorKey {
		copied := *row
		digest := sha256.Sum256(demoVendorKey)
		copied.VendorRepositories = nil
		for _, vendor := range row.VendorRepositories {
			vendor.KeySHA256 = []string{hex.EncodeToString(digest[:])}
			copied.VendorRepositories = append(copied.VendorRepositories, vendor)
		}
		release = &copied
	}
	return capabilitypolicy.Host{
		Release:      release,
		Architecture: "x86_64",
		Interfaces: func() ([]capabilitypolicy.Interface, error) {
			return []capabilitypolicy.Interface{{Name: "lo", Loopback: true}, {Name: "enp1s0", PermanentMAC: "02:00:00:00:00:01"}}, nil
		},
		ReadVendorKey:        func(string) ([]byte, error) { return demoVendorKey, nil },
		FirewallRestoreReady: func() bool { return true },
	}
}

// admission is the executor's refusal before any native observation: a
// capability the effective configuration does not provide, then a create-only
// collision with an unowned native object. Zero reason admits the intent.
func (a *demoAgent) admission(desired *resourcev1.ResourceDesiredState, mode resourcev1.OwnershipMode) (agentv1.ResourceAdmissionRefusalReason, agentv1.ManagementCapability, string) {
	if a == nil || a.effective == nil {
		return 0, 0, ""
	}
	if capability := capabilitypolicy.RequiredCapability(desired, a.effective.Config, a.host); capability != agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_UNSPECIFIED {
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED, capability, ""
	}
	if detail := a.collisions[desired.GetRef().GetKind()]; detail != "" && mode != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_ADOPTION_REQUIRED, 0, detail
	}
	return 0, 0, ""
}
