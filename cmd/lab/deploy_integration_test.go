// SPDX-License-Identifier: Apache-2.0
package main

import (
	"io"
	"testing"
)

func TestDeployIntegrationProofRejectsMissingAndPlaintextInputs(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-destination-id", "not-a-uuid", "-secret-sha256", "not-a-digest"},
		{"-key-file", "/unsafe/plaintext-key"},
		{"-signing-secret", "must-not-enter-argv"},
		{"-destination-id", "2f879d29-1836-45d7-8f92-5d3d8d08c244", "-secret-sha256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "-reject-fresh-key"},
	} {
		if err := runDeployIntegrationProof(t.Context(), args, io.Discard, io.Discard); err == nil {
			t.Fatal("missing, invalid or plaintext integration input was accepted")
		}
	}
}
