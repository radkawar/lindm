// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/connectivityguard"
	"lindm/internal/agent/firewallprovider"
	"lindm/internal/agent/nativehelper"
)

// The provider owns its invocation's proof. It never stores raw private packet
// evidence in the transport status or synthesizes it from a previous guard run.
type nativeFirewallResource struct {
	*firewallprovider.Provider
	evidence *agentv1.ConnectivityVerificationEvidence
}

func openFirewallResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent, platform := o.service, o.intent, o.platform
	holder := new(nativeFirewallResource)
	provider, err := firewallprovider.Open(ctx, firewallprovider.Config{
		Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: o.providers.native.Firewall,
		NativeApply: s.resourceNativeApply,
		NativeRead: func(ctx context.Context, template *resourcev1.ResourceObservation) (*agentv1.ResourceOwnershipSnapshot, error) {
			result, err := s.observeNativeResource(ctx, intent.GetDesired(), platform, template.GetMetadata().GetBackend())
			if err != nil {
				return nil, err
			}
			return result.GetAfter(), nil
		},
		NativeProbe: func(ctx context.Context, desired *resourcev1.FirewallZoneDesired, observed *resourcev1.ResourceObservation) (*resourcev1.ProbeReceipt, *resourcev1.ProbeReceipt, error) {
			holder.evidence = nil
			value := &resourcev1.ResourceDesiredState{Ref: proto.CloneOf(observed.GetRef()), State: &resourcev1.ResourceDesiredState_FirewallZone{FirewallZone: proto.CloneOf(desired)}}
			result, err := nativehelper.ObserveResource(ctx, s.directory, &agentv1.NativeResourceObservationRequest{Desired: value, Platform: proto.CloneOf(platform), ExecutorIncarnation: s.incarnation, Backend: proto.CloneOf(observed.GetMetadata().GetBackend()), FirewallVerification: proto.CloneOf(observed)})
			if err != nil {
				return nil, nil, err
			}
			holder.evidence = proto.CloneOf(result.GetFirewallEvidence())
			return result.GetFirewallAllow(), result.GetFirewallDeny(), nil
		},
		// The executor's read-only view of the supervisor's root custody; only
		// an exact terminal record of an interrupted effect resolves UNKNOWN.
		GuardOutcome: func(context.Context) (*agentv1.ConnectivityGuardRecord, error) {
			return connectivityguard.Outcome(connectivityguard.StateDirectory)
		},
	})
	if err != nil {
		return nil, err
	}
	holder.Provider = provider
	return holder, nil
}

func nativeFirewallEvidence(provider nativeResource) *agentv1.ConnectivityVerificationEvidence {
	if firewall, ok := provider.(*nativeFirewallResource); ok {
		return proto.CloneOf(firewall.evidence)
	}
	return nil
}

func validateFirewallEvidence(record *agentv1.ResourceExecutionRecord) error {
	evidence := record.GetFirewallEvidence()
	checks := record.GetVerification().GetFirewallZone()
	if evidence == nil {
		if checks.GetAllowPacketProbe().GetPassed() || checks.GetDenyPacketProbe().GetPassed() {
			return errRecoveryHold
		}
		return nil
	}
	if checks == nil || !proto.Equal(evidence.GetRef(), record.GetVerification().GetRef()) {
		return errRecoveryHold
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(evidence)
	if err != nil {
		return errRecoveryHold
	}
	digest := sha256.Sum256(encoded)
	observed, err := proto.MarshalOptions{Deterministic: true}.Marshal(record.GetVerification().GetAfter())
	if err != nil {
		return errRecoveryHold
	}
	observationDigest := sha256.Sum256(observed)
	if !bytes.Equal(observationDigest[:], evidence.GetObservationSha256()) {
		return errRecoveryHold
	}
	for _, receipt := range []*resourcev1.ProbeReceipt{checks.GetAllowPacketProbe(), checks.GetDenyPacketProbe()} {
		if receipt == nil || receipt.GetProbeId() != evidence.GetProbeId() || !proto.Equal(receipt.GetObservedAt(), evidence.GetObservedAt()) || !bytes.Equal(receipt.GetEvidenceSha256(), digest[:]) {
			return errRecoveryHold
		}
	}
	return nil
}
