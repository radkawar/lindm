// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestDeployInstallerDiagnosticsAreEncryptedRawStreams(t *testing.T) {
	for _, label := range []string{"first", "cold-launch", "first-journal", "cold-web-and-licenses", "management-agent-journal", "management-server-journal", "backup-command", "security-backup-command"} {
		t.Run(label, func(t *testing.T) {
			checkDeployDiagnosticsAreEncryptedRawStreams(t, label)
		})
	}
}

func checkDeployDiagnosticsAreEncryptedRawStreams(t *testing.T, label string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	recipient := filepath.Join(directory, "operator-recipient")
	if err := os.WriteFile(recipient, []byte(identity.Recipient().String()), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := []byte("private stdout\x00"), []byte("postgres://owner:secret@example.invalid/private\n")
	if err := writeDeployInstallerDiagnostics(recipient, directory, label, stdout, stderr); err != nil {
		t.Fatal(err)
	}
	for name, plaintext := range map[string][]byte{"stdout": stdout, "stderr": stderr} {
		path := filepath.Join(directory, label+"-"+name+".age")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, plaintext) {
			t.Fatal("plaintext diagnostic appeared on disk")
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("diagnostic is not private: %v", err)
		}
		decrypted, err := age.Decrypt(bytes.NewReader(body), identity)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(decrypted)
		if err != nil || !bytes.Equal(decoded, plaintext) {
			t.Fatalf("raw diagnostic bytes were not retained: %v", err)
		}
	}
	if err := writeDeployInstallerDiagnostics(recipient, directory, label, []byte("replacement"), nil); err == nil {
		t.Fatal("existing ciphertext replaced")
	}
}

func TestDeployInstallerDiagnosticsRejectUnboundedOrEscapingInputs(t *testing.T) {
	directory := t.TempDir()
	for _, label := range []string{"", ".", "../escape"} {
		if err := writeDeployInstallerDiagnostics("unused", directory, label, nil, nil); err == nil {
			t.Fatal("escaping label accepted")
		}
	}
	if err := writeDeployInstallerDiagnostics("unused", directory, "first", make([]byte, deployInstallerDiagnosticLimit+1), nil); err == nil {
		t.Fatal("unbounded plaintext accepted")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected diagnostics created files: %v", err)
	}
}
