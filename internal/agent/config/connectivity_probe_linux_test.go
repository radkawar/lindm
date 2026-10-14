// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestProbeCredentialsRejectReadableKeysAndReplaceableFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential custody test requires root")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "proof.pem")
	contents := []byte("private fixture material")
	if err := os.WriteFile(path, contents, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readProbeCredential(path, true); err == nil {
		t.Fatal("world-readable proof key accepted")
	}
	public, err := readProbeCredential(path, false)
	if err != nil || !bytes.Equal(public, contents) {
		t.Fatal("root-owned public credential did not load")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	private, err := readProbeCredential(path, true)
	if err != nil || !bytes.Equal(private, contents) {
		t.Fatal("protected credential did not load")
	}
	clear(private)
	alias := filepath.Join(directory, "alias.pem")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readProbeCredential(alias, true); err == nil {
		t.Fatal("symlink selected a private key")
	}
	hardlink := filepath.Join(directory, "linked.pem")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readProbeCredential(path, true); err == nil {
		t.Fatal("hardlinked private credential accepted")
	}
}
func TestProbeCredentialReadsAreBounded(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential custody test requires root")
	}
	path := filepath.Join(t.TempDir(), "oversized.pem")
	if err := os.WriteFile(path, make([]byte, 65537), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProbeCredential(path, true); err == nil {
		t.Fatal("oversized private credential accepted")
	}
	if _, err := readProbeCredential("relative-key.pem", true); err == nil {
		t.Fatal("unresolved private credential path accepted")
	}
}
