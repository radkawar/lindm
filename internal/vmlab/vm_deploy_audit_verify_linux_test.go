// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestHistoricalAuditVerifierFailsClosed(t *testing.T) {
	directory := protectedAuditTestDirectory(t)
	path := filepath.Join(directory, "not-a-frozen-go-lab")
	body := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	for _, test := range []struct{ name, path, digest string }{
		{"no pin", path, ""},
		{"relative path", "relative-lab", digest},
		{"wrong pin", path, "0000000000000000000000000000000000000000000000000000000000000000"},
		{"successful fake executable", path, digest},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := openDeployAuditVerifier(test.path, test.digest)
			if file != nil {
				if closeErr := file.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if err == nil {
				t.Fatal("untrusted historical verifier admitted")
			}
		})
	}
}

func TestHistoricalAuditVerifierRejectsSharedAndLinkedExecutables(t *testing.T) {
	directory := protectedAuditTestDirectory(t)
	path := filepath.Join(directory, "private-lab")
	body := []byte("not executable Go build metadata")
	if err := os.WriteFile(path, body, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if file, err := openDeployAuditVerifier(path, digest); err == nil {
		if file != nil {
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		}
		t.Fatal("public-readable verifier admitted")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked-lab")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openDeployAuditVerifier(path, digest); err == nil {
		if file != nil {
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		}
		t.Fatal("hardlinked verifier admitted")
	}
	symlink := filepath.Join(directory, "symlink-lab")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if file, err := openDeployAuditVerifier(symlink, digest); err == nil {
		if file != nil {
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		}
		t.Fatal("symlink verifier admitted")
	}
}

func TestHistoricalAuditManifestRejectsReplacementDuringAuthentication(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "release.json")
	if err := os.WriteFile(path, []byte(`{"revision":"untrusted"}`), 0600); err != nil {
		t.Fatal(err)
	}
	file, before, err := openDeployAuditManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	replacement := filepath.Join(directory, "replacement.json")
	if err := os.WriteFile(replacement, []byte(`{"revision":"replacement"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readDeployAuditManifest(file, before, path); err == nil {
		t.Fatal("manifest path replacement survived authentication")
	}
}
