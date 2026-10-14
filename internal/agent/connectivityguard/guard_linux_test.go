// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connectivityguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/mdlayher/netlink"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/trust"
)

func TestRestartBootPartitionAndCommitRecoveryDecisions(t *testing.T) {
	r := &agentv1.ConnectivityGuardRecord{Phase: agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_APPLIED, BootId: uuid.NewString(), DeadlineBoottimeNs: 120000000000}
	cases := []struct {
		name        string
		restart     bool
		boot        string
		now         uint64
		alive, want bool
	}{
		{"healthy", false, r.BootId, 119000000000, true, false},
		{"control_plane_partition_expires", false, r.BootId, 120000000000, true, true},
		{"suspend_counts_in_boottime", false, r.BootId, 301000000000, true, true},
		{"supervisor_restart", true, r.BootId, 1000, true, true},
		{"helper_restart_or_death", false, r.BootId, 1000, false, true},
		{"reboot_clock_reset", false, uuid.NewString(), 1000, false, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := recoveryRequired(r, test.restart, test.boot, test.now, test.alive); got != test.want {
				t.Fatalf("recovery=%v want %v", got, test.want)
			}
		})
	}
	r.Phase = agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_CONFIRMED
	if !recoveryRequired(r, true, r.BootId, 1000, true) {
		t.Fatal("confirmation without durable COMMITTED bypassed recovery")
	}
	for _, phase := range []agentv1.ConnectivityGuardPhase{agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_COMMITTED, agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_CONFLICT, agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_ROLLED_BACK} {
		r.Phase = phase
		if recoveryRequired(r, true, uuid.NewString(), 999999999999, false) {
			t.Fatal("terminal custody was replayed")
		}
	}
}
func TestExternalReceiptCannotChangeNonceDirectionFamilyOrTarget(t *testing.T) {
	target, packet, key := probeFixture(t)
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := transportPacket(target, packet.GetNonce())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(transport)
	receipt := &agentv1.ConnectivityProbeReceipt{Target: target, Packet: packet, Received: true, TransportSha256: digest[:]}
	signed, err := authority.Sign(t.Context(), receipt, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProbeReceipt(t.Context(), authority, signed, target.GetReceiver(), target, packet, false); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*agentv1.ConnectivityProbeTarget, *agentv1.ConnectivityProbePacket){func(_ *agentv1.ConnectivityProbeTarget, p *agentv1.ConnectivityProbePacket) { p.Nonce[0] ^= 1 }, func(t *agentv1.ConnectivityProbeTarget, _ *agentv1.ConnectivityProbePacket) { t.Address = "192.0.2.3" }, func(t *agentv1.ConnectivityProbeTarget, _ *agentv1.ConnectivityProbePacket) {
		t.Direction = agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_FORWARD
	}, func(t *agentv1.ConnectivityProbeTarget, _ *agentv1.ConnectivityProbePacket) {
		t.Address = "2001:db8::2"
		t.SourceAddress = "2001:db8::1"
	}, func(_ *agentv1.ConnectivityProbeTarget, p *agentv1.ConnectivityProbePacket) {
		p.ActionId = uuid.NewString()
	}}
	for _, mutate := range mutations {
		changedTarget, changedPacket := proto.CloneOf(target), proto.CloneOf(packet)
		mutate(changedTarget, changedPacket)
		if err := VerifyProbeReceipt(t.Context(), authority, signed, target.GetReceiver(), changedTarget, changedPacket, false); err == nil {
			t.Fatal("receipt accepted altered exact packet binding")
		}
	}
	if err := VerifyProbeReceipt(t.Context(), authority, signed, target.GetReceiver(), target, packet, true); err == nil {
		t.Fatal("receive receipt accepted as external transmission")
	}
	forged := bytes.Clone(signed)
	forged[len(forged)/2] ^= 1
	if err := VerifyProbeReceipt(t.Context(), authority, forged, target.GetReceiver(), target, packet, false); err == nil {
		t.Fatal("forged external witness accepted")
	}
}
func TestPacketEncodingBindsEverySupportedProtocolAndFamily(t *testing.T) {
	target, packet, _ := probeFixture(t)
	for _, v6 := range []bool{false, true} {
		for _, protocol := range []agentv1.ConnectivityProbeProtocol{agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP, agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_UDP} {
			candidate := proto.CloneOf(target)
			candidate.Protocol = protocol
			if v6 {
				candidate.SourceAddress = "2001:db8::1"
				candidate.Address = "2001:db8::2"
			}
			encoded, err := transportPacket(candidate, packet.GetNonce())
			if err != nil {
				t.Fatal(err)
			}
			header := 8
			if protocol == agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP {
				header = 20
				if encoded[12] != 0x50 || encoded[13] != 2 {
					t.Fatal("probe is not a new TCP SYN")
				}
			}
			if len(encoded) != header+32 || !bytes.Equal(encoded[header:], packet.GetNonce()) || binary.BigEndian.Uint16(encoded) != uint16(candidate.GetSourcePort()) || binary.BigEndian.Uint16(encoded[2:]) != uint16(candidate.GetPort()) {
				t.Fatal("wire transport lost exact nonce or target")
			}
			changed := bytes.Clone(packet.GetNonce())
			changed[31] ^= 1
			other, err := transportPacket(candidate, changed)
			if err != nil || bytes.Equal(encoded, other) {
				t.Fatal("nonce change did not change actual packet")
			}
		}
	}
	target.SourceAddress = "2001:db8::1"
	if _, err := transportPacket(target, packet.GetNonce()); err == nil {
		t.Fatal("mixed-family advertised proof accepted")
	}
}
func TestTraceDecoderRejectsDuplicateAndTruncatedKernelIdentity(t *testing.T) {
	attributes := []netlink.Attribute{{Type: 1, Data: []byte("lindm_z_exact\x00")}, {Type: 2, Data: []byte("input\x00")}, {Type: 3, Data: binary.BigEndian.AppendUint64(nil, 11)}, {Type: 4, Data: binary.BigEndian.AppendUint32(nil, 3)}, {Type: 6, Data: binary.BigEndian.AppendUint32(nil, 71)}, {Type: 16, Data: binary.BigEndian.AppendUint32(nil, 0)}}
	encode := func(a []netlink.Attribute) []byte {
		t.Helper()
		data, err := netlink.MarshalAttributes(a)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte{1, 0, 0, 0}, data...)
	}
	event, err := decodeTrace(encode(attributes))
	if err != nil || event.id != 71 || event.handle != 11 || !event.hasVerdict || event.verdict != 0 {
		t.Fatalf("lost explicit kernel DROP: %+v %v", event, err)
	}
	duplicate := append(append([]netlink.Attribute(nil), attributes...), attributes[4])
	if _, err := decodeTrace(encode(duplicate)); err == nil {
		t.Fatal("duplicate trace ID accepted")
	}
	attributes[2].Data = []byte{11}
	if _, err := decodeTrace(encode(attributes)); err == nil {
		t.Fatal("truncated rule handle accepted")
	}
}
func TestClosedGuardTimeoutAndBothFamilies(t *testing.T) {
	target, _, key := probeFixture(t)
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("fixture key is not Ed25519")
	}
	policy := &agentv1.ConnectivityGuardConfig{ConfirmationPublicKey: public}
	for _, v6 := range []bool{false, true} {
		for _, verdict := range []agentv1.ConnectivityProbeVerdict{agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW, agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY} {
			p := proto.CloneOf(target)
			p.Id = uuid.NewString()
			p.Expected = verdict
			if v6 {
				p.Address = "2001:db8::2"
				p.SourceAddress = "2001:db8::1"
			}
			policy.Probes = append(policy.Probes, p)
		}
	}
	if err := protovalidate.Validate(policy); err != nil {
		t.Fatal(err)
	}
	for _, seconds := range []uint32{30, 120, 300} {
		policy.TimeoutSeconds = proto.Uint32(seconds)
		if err := protovalidate.Validate(policy); err != nil {
			t.Fatal(err)
		}
	}
	for _, seconds := range []uint32{0, 29, 301} {
		policy.TimeoutSeconds = proto.Uint32(seconds)
		if protovalidate.Validate(policy) == nil {
			t.Fatal("out-of-contract rollback deadline accepted")
		}
	}
	policy.TimeoutSeconds = nil
	policy.Probes = policy.Probes[:2]
	if protovalidate.Validate(policy) == nil {
		t.Fatal("IPv4-only proof advertised as complete guard preflight")
	}
}
func TestCancelledPacketSendNeverBecomesDeny(t *testing.T) {
	target, packet, _ := probeFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	digest, err := transmitPacket(ctx, target, packet.GetNonce())
	if !errors.Is(err, context.Canceled) || len(digest) != 0 {
		t.Fatal("unattempted packet produced proof")
	}
}

func TestReceiverReadinessCannotSubstitutePacketEvidence(t *testing.T) {
	target, packet, key := probeFixture(t)
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := transportPacket(target, packet.GetNonce())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(transport)
	envelope, err := authority.Sign(t.Context(), &agentv1.ConnectivityProbeReceipt{Target: target, Packet: packet, ReceiverReady: true, TransportSha256: digest[:]}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProbeReadiness(t.Context(), authority, envelope, target.GetReceiver(), target, packet); err != nil {
		t.Fatal(err)
	}
	for _, sent := range []bool{false, true} {
		if err := VerifyProbeReceipt(t.Context(), authority, envelope, target.GetReceiver(), target, packet, sent); err == nil {
			t.Fatal("receiver readiness substituted for an actual packet")
		}
	}
	changed := proto.CloneOf(packet)
	changed.Nonce[0] ^= 1
	if err := VerifyProbeReadiness(t.Context(), authority, envelope, target.GetReceiver(), target, changed); err == nil {
		t.Fatal("receiver reservation accepted another nonce")
	}
}

func TestMutationRequiresDurablePerActionConfirmationCustody(t *testing.T) {
	guard := new(Guard)
	request := &agentv1.NativeResourceTransactionRequest{Plan: &resourcev1.ResourcePlan{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE}}}
	if err := guard.Arm(t.Context(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("armed without durable receipt retention: %v", err)
	}
	if err := guard.Committed(t.Context(), request, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("disarmed without durable receipt retention: %v", err)
	}
}
