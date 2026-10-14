// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestDeployIntegrationProofAuthenticatesKeyDestinationAndCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	secret := bytes.Repeat([]byte{3}, 48)
	id := uuid.New()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nil, secret, id[:])
	actual, err := decryptDeployIntegration(key, ciphertext, id)
	if err != nil || !bytes.Equal(actual, secret) {
		t.Fatal("original integration key did not authenticate its destination secret")
	}
	clear(actual)
	for _, test := range []struct {
		name            string
		key, ciphertext []byte
		id              uuid.UUID
	}{
		{"fresh-key", bytes.Repeat([]byte{2}, 32), ciphertext, id},
		{"different-destination", key, ciphertext, uuid.New()},
		{"truncated", key, ciphertext[:len(ciphertext)-1], id},
		{"changed", key, append(append([]byte(nil), ciphertext[:len(ciphertext)-1]...), ciphertext[len(ciphertext)-1]^1), id},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := decryptDeployIntegration(test.key, test.ciphertext, test.id)
			clear(value)
			if err == nil {
				t.Fatal("unrelated key, destination or corrupted ciphertext authenticated")
			}
		})
	}
}

func TestDeployIntegrationRootReaderRequiresExactCustody(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native file custody regression requires root")
	}
	directory, err := os.MkdirTemp("/var/lib", "lindm-deploy-integration-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "integrations.key")
	key := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	value, err := readDeployIntegrationRootSecret(path, 32, 32)
	if err != nil || !bytes.Equal(value, key) {
		t.Fatalf("correct private root key refused: %v", err)
	}
	clear(value)
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := readDeployIntegrationRootSecret(path, 32, 32); err == nil {
		t.Fatal("group-readable root key accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(directory, "linked")
	if err := os.Link(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := readDeployIntegrationRootSecret(path, 32, 32); err == nil {
		t.Fatal("multiply linked root key accepted")
	}
}
