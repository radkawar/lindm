// SPDX-License-Identifier: Apache-2.0
//go:build linux

package packaging

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

func nativeProductionExport(t *testing.T, uid string) ([]byte, []byte) {
	t.Helper()
	if uid == ProductionSigningUID {
		if err := custody.ProtectNativeSigningSecrets(); err != nil {
			t.Fatal(err)
		}
	}
	requireNativeTools(t, "gpg", "gpgconf")
	// Short owned paths leave room for native agent Unix socket names.
	work, err := os.MkdirTemp("", "pkg-export-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeWork(work); err != nil {
			t.Error(err)
		}
	})
	if err := os.Mkdir(filepath.Join(work, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(work, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	guard, err := lockSignerHome(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := guard.close(context.Background(), work); err != nil {
			t.Error(err)
		}
	}()
	passphrase := []byte("native-fixture-passphrase-64-characters-protected-only-in-memory!!")
	t.Cleanup(func() { clear(passphrase) })
	protected, err := newPassphraseFD(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := protected.close(); err != nil {
			t.Error(err)
		}
	}()
	common := []string{"--no-options", "--require-secmem", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", "/proc/self/fd/3", "--homedir", home}
	if _, _, err := runTool(context.Background(), work, toolCmd{Name: "gpg", Args: append(append([]string{}, common...), "--quick-generate-key", uid, "rsa4096", "sign", "never"), Files: []*os.File{protected.file}}); err != nil {
		t.Fatal(err)
	}
	if err := encryptedSignerHome(home); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := listSecretFingerprint(context.Background(), work, home)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := runTool(context.Background(), work, toolCmd{Name: "gpg", Args: append(append([]string{}, common...), "--armor", "--export-secret-keys", fingerprint), Files: []*os.File{protected.file}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(secret) })
	return secret, passphrase
}
func TestProductionImportRejectsRelabeledDevelopmentKeys(t *testing.T) {
	secret, passphrase := nativeProductionExport(t, developmentUID)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	// The export carries a cryptographically valid development UID, without any
	// filesystem marker. It cannot become production by changing directory labels.
	if _, _, err := encryptedProductionSecret(secret); !errors.Is(err, ErrSigner) {
		t.Fatalf("development purpose passed the production parser: %v", err)
	}
	if _, cleanup, err := ImportProductionSigner(context.Background(), parent, secret, passphrase); err == nil || cleanup != nil {
		t.Fatalf("relabeled development secret accepted: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected import wrote private files: %v", err)
	}
}
func TestProtectedPassphraseRequiresSealedBoundedMemory(t *testing.T) {
	for _, value := range [][]byte{nil, []byte("two\nlines"), []byte("nul\x00byte"), bytes.Repeat([]byte("a"), maxPassphrase+1)} {
		if secret, err := newPassphraseFD(value); !errors.Is(err, ErrSigner) {
			if secret != nil {
				if closeErr := secret.close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			t.Fatalf("unsafe passphrase accepted: %v", err)
		}
	}
	file, err := os.CreateTemp(t.TempDir(), "unsealed")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := file.Write([]byte("not a credential")); err != nil {
		t.Fatal(err)
	}
	if memory, err := lockPassphraseFD(file); !errors.Is(err, ErrSigner) || memory != nil {
		t.Fatalf("ordinary disk file accepted as protected FD: %v", err)
	}
	secret, err := newPassphraseFD([]byte("protected-memory-only"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := secret.close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := secret.file.WriteAt([]byte("x"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("inherited passphrase remained writable: %v", err)
	}
	if mapping, err := unix.Mmap(int(secret.file.Fd()), 0, len(secret.memory), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err == nil {
		if err := unix.Munmap(mapping); err != nil {
			t.Error(err)
		}
		t.Fatal("sealed passphrase admitted a new writable mapping")
	}
	key := SigningKey{Custody: CustodyProduction, PassphraseFD: secret.file}
	if path, err := passphraseFile(t.TempDir(), key); err != nil || path != "/proc/self/fd/3" {
		t.Fatalf("memory-only descriptor path: %q %v", path, err)
	}
	key.PassphraseFile = "/absent/disk-passphrase"
	if _, err := passphraseFile(t.TempDir(), key); !errors.Is(err, ErrSigner) {
		t.Fatalf("simultaneous file and memory passphrase accepted: %v", err)
	}
	for range 2 {
		out, _, err := runTool(context.Background(), t.TempDir(), toolCmd{Name: "cat", Args: []string{"/proc/self/fd/3"}, Files: []*os.File{secret.file}})
		if err != nil || !bytes.Equal(out, secret.memory) {
			t.Fatalf("native helper could not reopen inherited descriptor: %v", err)
		}
		clear(out)
	}
	if strings.Contains(secret.file.Name(), "/") {
		t.Fatal("passphrase descriptor gained a filesystem path")
	}
}
