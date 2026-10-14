// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

func TestDeployPassphraseEscrowEncryptsOnlyToOffhostOperator(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	recipient := filepath.Join(directory, "operator.pub")
	if err := os.WriteFile(recipient, []byte(identity.Recipient().String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "source-passphrase.age")
	passphrase := []byte("a fixture secret that must never be written plaintext")
	if err := encryptDeployEvidence(recipient, destination, passphrase); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, passphrase) {
		t.Fatal("plaintext passphrase appeared in ciphertext")
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recovered)
	if !bytes.Equal(recovered, passphrase) {
		t.Fatal("operator could not recover the original in-memory passphrase")
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("escrow is not private")
	}
	if err := encryptDeployEvidence(recipient, destination, []byte("replacement")); err == nil {
		t.Fatal("existing escrow was replaced")
	}
	unchanged, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, ciphertext) {
		t.Fatal("failed replacement changed the offhost object")
	}
}

func TestDeployPassphraseEscrowRejectsNonOperatorRecipient(t *testing.T) {
	directory := t.TempDir()
	recipient := filepath.Join(directory, "invalid.pub")
	destination := filepath.Join(directory, "never-created.age")
	if err := os.WriteFile(recipient, []byte("not-an-age-public-recipient"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := encryptDeployEvidence(recipient, destination, []byte("in-memory secret")); err == nil {
		t.Fatal("untrusted recipient accepted")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("invalid recipient created an escrow object")
	}
}

func TestDeployEvidenceCopiesStayPrivateBoundedAndSinglyLinked(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.age")
	content := []byte("authenticated fixture ciphertext")
	if err := os.WriteFile(source, content, 0600); err != nil {
		t.Fatal(err)
	}
	checksum := sha256.Sum256(content)
	digest := hex.EncodeToString(checksum[:])
	destination := filepath.Join(directory, "evidence.age")
	if err := copyDeployEvidence(t.Context(), source, destination, int64(len(content)), digest); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(copied, content) {
		t.Fatalf("copied evidence differs: %v", err)
	}
	for _, path := range []string{source, destination} {
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err != nil {
			t.Fatal(err)
		}
		if stat.Nlink != 1 || stat.Mode&0777 != 0600 {
			t.Fatal("offline ciphertext is not private and singly linked")
		}
	}
	if err := copyDeployEvidence(t.Context(), source, destination, int64(len(content)), digest); err == nil {
		t.Fatal("existing evidence was replaced")
	}
	for _, test := range []struct {
		name   string
		limit  int64
		digest string
	}{
		{"oversized", int64(len(content) - 1), digest},
		{"mismatched", int64(len(content)), strings.Repeat("0", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			rejected := filepath.Join(directory, test.name+".age")
			if err := copyDeployEvidence(t.Context(), source, rejected, test.limit, test.digest); err == nil {
				t.Fatal("invalid evidence copy accepted")
			}
			if _, err := os.Stat(rejected); !os.IsNotExist(err) {
				t.Fatal("failed evidence copy left a published artifact")
			}
		})
	}
}

func TestDeployDatabaseCredentialGateRequiresRootOwnerAndNativeHandoff(t *testing.T) {
	for _, guard := range []string{
		"for path in /etc/lindm/database-url /etc/lindm/migrate/database-url",
		`test ! -L "$path"`,
		`test -f "$path"`,
		`test "$(stat -c %u:%g:%a:%h "$path")" = 0:0:600:1`,
		"for account in lindmd lindmd-migrate",
		`if runuser -u "$account" -- test -r "$path"; then exit 1; fi`,
		"database-url:/etc/lindm/database-url",
		"database-url:/etc/lindm/migrate/database-url",
		"/etc/lindm/integrations.key",
		`test "$(stat -c %s /etc/lindm/integrations.key)" = 32`,
		"integrations-key:/etc/lindm/integrations.key",
		`test "$database_credential" = true`,
		`test "$integration_credential" = true`,
		"systemctl is-active --quiet lindmd.service",
	} {
		if !strings.Contains(deployDatabaseCredentialsCommand, guard) {
			t.Fatalf("native credential proof is missing required guard %q", guard)
		}
	}
}
