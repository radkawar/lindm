// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func protectedAuditTestDirectory(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".lindm-audit-path-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	return directory
}

func TestHistoricalAuditRejectsReplaceableAncestors(t *testing.T) {
	for _, kind := range []string{"symlink", "writable"} {
		t.Run(kind, func(t *testing.T) {
			directory := protectedAuditTestDirectory(t)
			parent := filepath.Join(directory, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(parent, "key"), []byte("public"), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "writable" {
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			} else {
				link := filepath.Join(directory, "linked")
				if err := os.Symlink(parent, link); err != nil {
					t.Fatal(err)
				}
				parent = link
			}
			file, _, err := openDeployAuditProtected(filepath.Join(parent, "key"), unix.O_RDONLY)
			if err == nil {
				if closeErr := file.Close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("replaceable key ancestry accepted")
			}
		})
	}
}

func TestHistoricalAuditDirectoryDescriptorSurvivesPathReplacement(t *testing.T) {
	directory := protectedAuditTestDirectory(t)
	original := filepath.Join(directory, "release")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "release.json"), []byte("authenticated"), 0600); err != nil {
		t.Fatal(err)
	}
	root, _, err := openDeployAuditProtected(original, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Rename(original, filepath.Join(directory, "old-release")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "release.json"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(deployAuditDescriptorPath(root), "release.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "authenticated" {
		t.Fatal("pinned directory followed replacement")
	}
}

func TestHistoricalAuditPublicKeyDescriptorSurvivesPathReplacement(t *testing.T) {
	directory := protectedAuditTestDirectory(t)
	path := filepath.Join(directory, "attestation.pub")
	if err := os.WriteFile(path, []byte("independently pinned public key"), 0600); err != nil {
		t.Fatal(err)
	}
	key, _, err := openDeployAuditProtected(path, unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := key.Close(); err != nil {
			t.Error(err)
		}
	}()
	replacement := filepath.Join(directory, "replacement.pub")
	if err := os.WriteFile(replacement, []byte("different public key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(deployAuditDescriptorPath(key))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "independently pinned public key" {
		t.Fatal("pinned public key followed replacement")
	}
}
