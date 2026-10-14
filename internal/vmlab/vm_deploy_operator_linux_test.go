// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestDeployUnlockEscrowReloadsFromDurableProtectedFiles(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".lindm-lab-escrow-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(directory, "identity.txt")
	public := filepath.Join(directory, "recipient.txt")
	if err := os.WriteFile(private, []byte(identity.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(public, []byte(identity.Recipient().String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	escrow := filepath.Join(directory, "unlock.age")
	phrase := []byte("durable encrypted lab fixture unlock, never a kernel-only secret")
	if err := encryptDeployEvidence(public, escrow, phrase); err != nil {
		t.Fatal(err)
	}
	reloaded, err := ReadDeployEscrowPassphrase(context.Background(), escrow, private)
	if err != nil || !bytes.Equal(reloaded, phrase) {
		t.Fatalf("durable unlock not reloaded: %v", err)
	}
	clear(reloaded)
	if err := os.Chmod(private, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDeployEscrowPassphrase(context.Background(), escrow, private); err == nil {
		t.Fatal("group-readable private lab identity accepted")
	}
	if err := os.Chmod(private, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(private, filepath.Join(directory, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDeployEscrowPassphrase(context.Background(), escrow, private); err == nil {
		t.Fatal("multiply-linked private lab identity accepted")
	}
}

func TestDeployUnlockEscrowRejectsInsecureAncestry(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "identity.txt")
	if err := os.WriteFile(path, []byte("not a private identity"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDeployEscrowInput(path, 4096); err == nil {
		t.Fatal("world-writable ancestor accepted as protected escrow custody")
	}
}
