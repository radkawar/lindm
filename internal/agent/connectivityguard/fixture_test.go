// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connectivityguard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func probeFixture(t *testing.T) (*agentv1.ConnectivityProbeTarget, *agentv1.ConnectivityProbePacket, ed25519.PrivateKey) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := &agentv1.ConnectivityProbeTarget{Id: uuid.NewString(), Address: "192.0.2.2", Port: 42341, SourceAddress: "192.0.2.1", SourcePort: 42342, Expected: agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW, Direction: agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT, Protocol: agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_UDP, Receiver: &agentv1.ConnectivityProbePeer{Origin: "https://probe.invalid:18446", PublicKey: public}}
	packet := &agentv1.ConnectivityProbePacket{TargetId: target.GetId(), ActionId: uuid.NewString(), Nonce: bytes.Repeat([]byte{7}, 32)}
	return target, packet, key
}
