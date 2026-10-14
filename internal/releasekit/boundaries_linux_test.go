// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasekit

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitRequiresExplicitApprovedInputs(t *testing.T) {
	ca := approvedCA(t)
	for _, test := range []struct {
		name       string
		recipients []string
		passphrase []byte
		ca         []byte
	}{
		{name: "no CA approval", passphrase: []byte("strong enough custody passphrase")},
		{name: "noncertificate CA", passphrase: []byte("strong enough custody passphrase"), ca: []byte("ambient host trust is not approval")},
		{name: "no custody mode", ca: ca},
		{name: "both custody modes", recipients: []string{"invalid"}, passphrase: []byte("strong enough custody passphrase"), ca: ca},
		{name: "weak passphrase", passphrase: []byte("short"), ca: ca},
		{name: "invalid recipient", recipients: []string{"not an X25519 recipient"}, ca: ca},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "not-created")
			if _, err := Init(context.Background(), directory, test.recipients, test.passphrase, test.ca); err == nil {
				t.Fatal("unapproved or invalid input accepted")
			}
			if _, err := os.Lstat(directory); !os.IsNotExist(err) {
				t.Fatalf("failed initialization created output: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Init(ctx, filepath.Join(t.TempDir(), "kit"), nil, []byte("strong enough custody passphrase"), ca); err == nil {
		t.Fatal("canceled initialization accepted")
	}
}

func TestKitRefusesSymlinkDirectoriesAndFiles(t *testing.T) {
	parent := t.TempDir()
	realDirectory := filepath.Join(parent, "real")
	if err := os.Mkdir(realDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(context.Background(), filepath.Join(link, "kit"), nil, []byte("strong enough custody passphrase"), approvedCA(t)); err == nil {
		t.Fatal("initialization followed symlink ancestry")
	}
	if _, err := Load(link); err == nil {
		t.Fatal("load followed symlink kit")
	}
	outside := filepath.Join(parent, "outside.pub")
	if err := os.WriteFile(outside, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(realDirectory, AttestationPublicFile)); err != nil {
		t.Fatal(err)
	}
	dir, err := openDirectory(realDirectory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := readFile(dir, AttestationPublicFile, maxFileSize); err == nil {
		t.Fatal("public reader followed symlink")
	}
}

func TestOwnedFileReaderBoundsAndPermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := openDirectory(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, test := range []struct {
		name string
		size int64
		mode os.FileMode
	}{
		{"oversize", maxFileSize + 1, 0600},
		{"world readable", 32, 0644},
		{"empty", 0, 0600},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := strings.ReplaceAll(test.name, " ", "-")
			file, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, test.mode)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(test.size); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(directory, name), test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := readFile(dir, name, maxFileSize); err == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
	file := filepath.Join(directory, "hardlinked")
	if err := os.WriteFile(file, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, filepath.Join(directory, "second-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(dir, "hardlinked", maxFileSize); err == nil {
		t.Fatal("hardlinked trust input accepted")
	}
}

func TestDomainIdentityReuseRejected(t *testing.T) {
	keys := make([]ed25519.PrivateKey, len(keyMembers))
	for index := range keys {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[index] = private
	}
	defer func() {
		for _, private := range keys {
			clear(private)
		}
	}()
	ca := approvedCA(t)
	for index := 1; index < len(keys); index++ {
		t.Run(purposes[index], func(t *testing.T) {
			aliased := append([]ed25519.PrivateKey{}, keys...)
			aliased[index] = keys[0]
			documents, err := trustDocuments(aliased, ca)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateTrust(documents); err == nil {
				t.Fatal("cross-purpose key reuse accepted")
			}
		})
	}
}

func TestArchiveRejectsAliasesAndDuplicateMembers(t *testing.T) {
	for _, test := range []struct {
		name  string
		names []string
		kind  byte
	}{
		{"path traversal", []string{"../attestation.pem"}, tar.TypeReg},
		{"duplicate", []string{"attestation.pem", "attestation.pem"}, tar.TypeReg},
		{"symlink", []string{"attestation.pem"}, tar.TypeSymlink},
	} {
		t.Run(test.name, func(t *testing.T) {
			var plain bytes.Buffer
			archive := tar.NewWriter(&plain)
			for _, name := range test.names {
				header := &tar.Header{Name: name, Mode: 0600, Typeflag: test.kind}
				if test.kind == tar.TypeReg {
					header.Size = 1
				} else {
					header.Linkname = "outside.pem"
				}
				if err := archive.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if test.kind == tar.TypeReg {
					if _, err := archive.Write([]byte("x")); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			_, buffers, err := readArchive(context.Background(), plain.Bytes())
			if err == nil {
				for _, buffer := range buffers {
					if err := buffer.Close(); err != nil {
						t.Error(err)
					}
				}
				t.Fatal("unsafe archive member accepted")
			}
		})
	}
}
