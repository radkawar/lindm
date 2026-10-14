// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connectivityguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/firewallprovider"
	"lindm/internal/resource"
)

// ProbeVerification performs new native packet experiments. It does not read the
// guard record, retimestamp a transaction receipt, arm rollback, or write durable
// policy. Temporary nftrace-only tables are kernel socket-owned and auto-removed.
// The caller retains evidence in the protected native result; public ProbeReceipt
// digests bind the complete exact observation/native state/packet receipt set.
func (g *Guard) ProbeVerification(ctx context.Context, desired *resourcev1.FirewallZoneDesired, observed *resourcev1.ResourceObservation) (allow, deny *resourcev1.ProbeReceipt, evidence *agentv1.ConnectivityVerificationEvidence, err error) {
	if desired == nil || observed.GetRef().GetKind() != resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE || observed.GetRef().GetCanonicalKey() != desired.GetZoneId() {
		return nil, nil, nil, ErrConflict
	}
	if err := resource.ValidateObservation(observed); err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(g.config.Policy.GetTimeoutSeconds())*time.Second)
	defer cancel()
	before, err := firewallprovider.ReadNative(ctx, g.config.Native, observed)
	if err != nil {
		return nil, nil, nil, err
	}
	if before.GetFirewall().GetConflict() || !proto.Equal(before.GetObservation().GetFirewallZone(), observed.GetFirewallZone()) || !bytes.Equal(before.GetObservation().GetMetadata().GetNativeRevision(), observed.GetMetadata().GetNativeRevision()) {
		return nil, nil, nil, ErrConflict
	}
	id := uuid.NewString()
	probes, err := g.probe(ctx, id, before)
	if err != nil {
		return nil, nil, nil, err
	}
	after, err := firewallprovider.ReadNative(ctx, g.config.Native, observed)
	if err != nil {
		return nil, nil, nil, err
	}
	first, last := proto.CloneOf(before.GetFirewall()), proto.CloneOf(after.GetFirewall())
	first.RulesetGeneration = 0
	last.RulesetGeneration = 0
	// Our own diagnostic table creation/removal advances the global nft generation;
	// ignoring that counter does not ignore any managed byte, handle, generation
	// userdata, inode, namespace or persistent-state change.
	if !proto.Equal(first, last) || before.GetObservation().GetMetadata().GetBootId() != after.GetObservation().GetMetadata().GetBootId() {
		return nil, nil, nil, ErrConflict
	}
	observationBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(observed)
	if err != nil {
		return nil, nil, nil, err
	}
	observationSum := sha256.Sum256(observationBytes)
	nativeBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(first)
	if err != nil {
		return nil, nil, nil, err
	}
	nativeSum := sha256.Sum256(nativeBytes)
	evidence = &agentv1.ConnectivityVerificationEvidence{ProbeId: id, Ref: proto.CloneOf(observed.GetRef()), ObservationSha256: observationSum[:], NativeStateSha256: nativeSum[:], Probes: probes, ObservedAt: timestamppb.Now()}
	if err := g.store.validate(evidence); err != nil {
		return nil, nil, nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(evidence)
	if err != nil {
		return nil, nil, nil, err
	}
	sum := sha256.Sum256(encoded)
	allow = &resourcev1.ProbeReceipt{ProbeId: id, ObservedAt: proto.CloneOf(evidence.GetObservedAt()), EvidenceSha256: bytes.Clone(sum[:]), Passed: true, Reason: "fresh signed external packet receipt and exact native allow verdict"}
	deny = &resourcev1.ProbeReceipt{ProbeId: id, ObservedAt: proto.CloneOf(evidence.GetObservedAt()), EvidenceSha256: bytes.Clone(sum[:]), Passed: true, Reason: "fresh exact nonce packet and native drop or reject verdict; silence is not denial"}
	return allow, deny, evidence, nil
}
