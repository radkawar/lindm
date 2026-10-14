// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestInitialDelegationLoadsExactTypedRequest(t *testing.T) {
	original := &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: []byte("signed-envelope")}
	encoded, err := protojson.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeInitialDelegation(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(original, decoded) {
		t.Fatal("initial delegation request changed during loading")
	}
	clear(encoded)
	if !bytes.Equal(decoded.GetDelegationEnvelope(), original.GetDelegationEnvelope()) {
		t.Fatal("request retained the mutable input buffer")
	}
}

func TestInitialDelegationPreservesURLSafeBase64Bytes(t *testing.T) {
	decoded, err := decodeInitialDelegation([]byte(`{"delegationEnvelope":"-_8"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.GetDelegationEnvelope(), []byte{0xfb, 0xff}) {
		t.Fatal("URL-safe base64 request bytes changed during loading")
	}
}

func TestInitialDelegationRejectsMalformedOrUnboundedRequest(t *testing.T) {
	for _, input := range []string{
		`{}`,
		`{"delegationEnvelope":""}`,
		`{"delegationEnvelope":"not!base64"}`,
		`{"delegationEnvelope":"AQ==","callerTrustedKey":"AQ=="}`,
		`{"delegationEnvelope":"AQ=="} trailing`,
	} {
		if _, err := decodeInitialDelegation([]byte(input)); err == nil {
			t.Errorf("accepted malformed initial request %q", input)
		}
	}
	encoded, err := protojson.Marshal(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: make([]byte, 16385)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeInitialDelegation(encoded); err == nil {
		t.Fatal("accepted oversized initial delegation")
	}
}
