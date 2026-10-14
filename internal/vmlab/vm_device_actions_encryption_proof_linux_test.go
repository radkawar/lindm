// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestActionEncryptionPublicHostOracle(t *testing.T) {
	headers := []EncryptedHeader{{UUID: "root-volume", JSON: json.RawMessage(`{"keyslots":{"0":{},"2":{}},"tokens":{"1":{"type":"systemd-tpm2","keyslots":["2"],"tpm2-blob":"never-record"}}}`)}}
	fresh := func() *actionEncryptionEvidence {
		return &actionEncryptionEvidence{LUKSUUID: "root-volume", Keyslots: []uint32{0, 2}, Tokens: []*agentv1.LUKSTokenObservation{{TokenId: 1, Type: "systemd-tpm2", Keyslots: []uint32{2}}}}
	}
	valid := fresh()
	if err := compareActionEncryptionHeaders(headers, valid); err != nil || !valid.HostOracleMatched {
		t.Fatalf("matching inventory rejected: %v", err)
	}
	for _, mutate := range []func(*actionEncryptionEvidence){
		func(e *actionEncryptionEvidence) { e.LUKSUUID = "different-volume" },
		func(e *actionEncryptionEvidence) { e.Keyslots = []uint32{0} },
		func(e *actionEncryptionEvidence) { e.Tokens = nil },
		func(e *actionEncryptionEvidence) { e.Tokens[0].Type = "different-token" },
		func(e *actionEncryptionEvidence) { e.Tokens[0].Keyslots = []uint32{0} },
	} {
		evidence := fresh()
		mutate(evidence)
		if err := compareActionEncryptionHeaders(headers, evidence); err == nil || evidence.HostOracleMatched {
			t.Fatal("mismatched public inventory accepted")
		}
	}
}
