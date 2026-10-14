// SPDX-License-Identifier: Apache-2.0
//go:build linux && integration && production_signing

package releasekit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"lindm/internal/custody"
)

func protectTestSecrets(t *testing.T) {
	t.Helper()
	if err := custody.ProtectNativeSigningSecrets(); err != nil {
		t.Fatal(err)
	}
}

func loadDocuments(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	dir, err := openDirectory(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	documents, err := readPublic(dir)
	if closeErr := dir.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	return documents
}

func assertOnlyPublicAndEncryptedFiles(t *testing.T, directory string) {
	t.Helper()
	allowed := map[string]bool{CustodyFile: true, PinsFile: true, "pins.sig": true}
	for _, name := range publicFiles {
		allowed[name] = true
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(allowed) {
		t.Fatalf("unexpected retained files: %v", entries)
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() {
			t.Fatalf("unexpected retained object: %s", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe permissions for %s: %v", entry.Name(), info.Mode())
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range [][]byte{[]byte("-----BEGIN PRIVATE KEY-----"), []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----"), []byte("AGE-SECRET-KEY-"), []byte("(private-key")} {
			if bytes.Contains(data, marker) {
				t.Fatalf("plaintext private material retained in %s", entry.Name())
			}
		}
	}
	ciphertext, err := os.ReadFile(filepath.Join(directory, CustodyFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) {
		t.Fatal("custody is not an age ciphertext")
	}
}

func TestProductionKitPassphraseCustody(t *testing.T) {
	protectTestSecrets(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	ambient := t.TempDir()
	sentinel := filepath.Join(ambient, "operator-cache")
	if err := os.WriteFile(sentinel, []byte("not inherited"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", ambient)
	kit := filepath.Join(parent, "release-keys")
	passphrase := []byte("strong operator custody passphrase")
	defer clear(passphrase)
	pub, err := Init(context.Background(), kit, nil, passphrase, approvedCA(t))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(kit)
	if err != nil {
		t.Fatal(err)
	}
	if *pub != *loaded {
		t.Fatalf("public pins changed: %+v != %+v", pub, loaded)
	}
	if info, err := os.Stat(kit); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("kit is not private: %v %v", info, err)
	}
	assertOnlyPublicAndEncryptedFiles(t, kit)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "release-keys" {
		t.Fatalf("generation staging retained: %v", entries)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "not inherited" {
		t.Fatalf("ambient maintainer cache touched: %s %v", data, err)
	}
	if _, err := Init(context.Background(), kit, nil, passphrase, approvedCA(t)); err == nil {
		t.Fatal("existing kit overwritten")
	}

	t.Run("usable isolated signers and wiping", func(t *testing.T) {
		secrets, err := Unlock(context.Background(), kit, passphrase, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := secrets.Close(); err != nil {
				t.Error(err)
			}
		})
		if secrets.Purpose != AttestationPurpose {
			t.Fatalf("wrong purpose: %s", secrets.Purpose)
		}
		documents := loadDocuments(t, kit)
		identities, err := validateTrust(documents)
		if err != nil {
			t.Fatal(err)
		}
		if len(identities) != 8 {
			t.Fatalf("missing domains: %d", len(identities))
		}
		block, _ := pem.Decode(secrets.AttestationPEM)
		if block == nil {
			t.Fatal("no private attestation PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		clear(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			t.Fatal("attestation is not Ed25519")
		}
		defer clear(key)
		message := []byte("release attestation")
		if !ed25519.Verify(identities[0], message, ed25519.Sign(key, message)) {
			t.Fatal("returned attestation signer unusable")
		}
		clear(key)
		if err := validatePackageSecret(secrets.PackageSecret, secrets.PackagePassphrase, pub.PackageFingerprint); err != nil {
			t.Fatal(err)
		}
		identity, err := age.ParseX25519Identity(strings.TrimSpace(string(secrets.members["backup-identity.txt"])))
		if err != nil {
			t.Fatal(err)
		}
		if string(documents[BackupRecipientFile]) != identity.Recipient().String()+"\n" {
			t.Fatal("default backup custodian unavailable")
		}
		buffers := append([]*custody.SecretBuffer{}, secrets.buffers...)
		if err := secrets.Close(); err != nil {
			t.Fatal(err)
		}
		if secrets.Purpose != "" || secrets.AttestationPEM != nil || secrets.PackageSecret != nil || secrets.PackagePassphrase != nil {
			t.Fatal("closed signer remains exposed")
		}
		for _, buffer := range buffers {
			if buffer.Bytes() != nil {
				t.Fatal("closed secret mapping retained")
			}
		}
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		if value, err := Unlock(context.Background(), kit, []byte("wrong custody passphrase"), nil); err == nil || value != nil {
			t.Fatal("wrong passphrase exposed signers")
		}
	})
	t.Run("authenticated ciphertext tampering", func(t *testing.T) {
		path := filepath.Join(kit, CustodyFile)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Error(err)
			}
		})
		tampered := append([]byte{}, original...)
		tampered[len(tampered)-1] ^= 1
		if err := os.WriteFile(path, tampered, 0600); err != nil {
			t.Fatal(err)
		}
		if value, err := Unlock(context.Background(), kit, passphrase, nil); err == nil || value != nil {
			t.Fatal("tampered archive exposed signers")
		}
	})
	for _, name := range []string{PinsFile, InventoryFile, CAFile, AttestationPublicFile, RootFile, "targets.json", PackagePublicFile, BackupRecipientFile} {
		t.Run("public tamper "+name, func(t *testing.T) {
			path := filepath.Join(kit, name)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Error(err)
				}
			})
			if err := os.WriteFile(path, append(append([]byte{}, original...), 'x'), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(kit); err == nil {
				t.Fatal("tampered public document accepted")
			}
			if value, err := Unlock(context.Background(), kit, passphrase, nil); err == nil || value != nil {
				t.Fatal("tampered public document exposed signer")
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string][]byte, map[string][]byte)
	}{
		{"purpose", func(_ map[string][]byte, members map[string][]byte) {
			members["manifest.txt"] = bytes.ReplaceAll(members["manifest.txt"], []byte(AttestationPurpose), []byte("development-release-attestation"))
		}},
		{"public identity disagreement", func(documents map[string][]byte, members map[string][]byte) {
			members["execution.pem"] = members["attestation.pem"]
			members["manifest.txt"] = archiveManifest(documents, members)
		}},
		{"package passphrase disagreement", func(documents map[string][]byte, members map[string][]byte) {
			members["package-passphrase.txt"][0] ^= 1
			members["manifest.txt"] = archiveManifest(documents, members)
		}},
		{"unknown archive member", func(_ map[string][]byte, members map[string][]byte) {
			members["unexpected.pem"] = []byte("not an allowed purpose")
		}},
	} {
		t.Run("sealed archive "+test.name, func(t *testing.T) {
			path := filepath.Join(kit, CustodyFile)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Error(err)
				}
			})
			secrets, err := Unlock(context.Background(), kit, passphrase, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := secrets.Close(); err != nil {
					t.Error(err)
				}
			})
			documents := loadDocuments(t, kit)
			test.mutate(documents, secrets.members)
			recipient, err := age.NewScryptRecipient(string(passphrase))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := encryptArchive(context.Background(), kit, secrets.members, []age.Recipient{recipient}); err != nil {
				t.Fatal(err)
			}
			if err := secrets.Close(); err != nil {
				t.Fatal(err)
			}
			if value, err := Unlock(context.Background(), kit, passphrase, nil); err == nil || value != nil {
				t.Fatal("invalid sealed archive exposed signers")
			}
		})
	}
}

func TestProductionKitRecipientCustody(t *testing.T) {
	protectTestSecrets(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	kit := filepath.Join(t.TempDir(), "kit")
	if _, err := Init(context.Background(), kit, []string{identity.Recipient().String()}, nil, approvedCA(t)); err != nil {
		t.Fatal(err)
	}
	if value, err := Unlock(context.Background(), kit, []byte("irrelevant passphrase"), nil); err == nil || value != nil {
		t.Fatal("recipient custody accepted passphrase")
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if value, err := Unlock(context.Background(), kit, nil, []byte(other.String())); err == nil || value != nil {
		t.Fatal("wrong recipient identity unlocked custody")
	}
	secrets, err := Unlock(context.Background(), kit, nil, []byte(identity.String()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := secrets.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, exists := secrets.members["backup-identity.txt"]; exists {
		t.Fatal("operator supplied recipient created an unrelated backup identity")
	}
	if err := secrets.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(kit, BackupRecipientFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != identity.Recipient().String()+"\n" {
		t.Fatal("operator backup recipient changed")
	}
	assertOnlyPublicAndEncryptedFiles(t, kit)
}
