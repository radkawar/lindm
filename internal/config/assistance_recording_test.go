// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestAssistanceRecordingKeyCustody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recording.key")
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	d := &Document{Proto: &configv1.ServerConfig{Assistance: &configv1.AssistanceConfig{Recording: &configv1.AssistanceRecordingConfig{KeyFile: "recording.key", MaxStorageBytes: 1 << 30}}}, base: dir}
	recipient, err := d.assistanceRecording()
	if err != nil || recipient == nil || len(recipient.KeyID()) != 64 {
		t.Fatalf("protected recording key: %v", err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := d.assistanceRecording(); err == nil {
		t.Fatal("accepted a group-readable recording key")
	}
	if err := os.WriteFile(path, seed[:31], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.assistanceRecording(); err == nil {
		t.Fatal("accepted a short recording key")
	}
	d.Proto.Escrow = &configv1.EscrowConfig{TransportKeyFile: "transport.pem", WrappingKeyFile: "recording.key"}
	if _, err := d.assistanceRecording(); err == nil {
		t.Fatal("accepted a recording key shared with escrow")
	}
}
