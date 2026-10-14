// SPDX-License-Identifier: Apache-2.0

package custody

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func secretPipe(t *testing.T, value []byte) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	if value != nil {
		if _, err = writer.Write(value); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return reader, writer
}

func TestProtectedPassphrasePipeConfirmationAndCancellation(t *testing.T) {
	secret := []byte("operator-vault-passphrase-strong-95248f0f")
	input, _ := secretPipe(t, append(append(append([]byte(nil), secret...), '\n'), append(secret, '\n')...))
	got, err := ReadPassphraseFD(t.Context(), int(input.Fd()), true)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if !bytes.Equal(got, secret) {
		t.Fatal("confirmed protected pipe did not round trip")
	}
	missing, _ := secretPipe(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if data, err := ReadPassphraseFD(ctx, int(missing.Fd()), true); err == nil || data != nil {
		t.Fatal("cancelled incomplete pipe accepted")
	}
	mismatch, _ := secretPipe(t, []byte("operator-vault-passphrase-strong-95248f0f\noperator-vault-passphrase-different-value\n"))
	if data, err := ReadPassphraseFD(t.Context(), int(mismatch.Fd()), true); err == nil || data != nil {
		t.Fatal("mismatched confirmation accepted")
	}
}

func TestPassphraseRejectsDiskAndNamedFIFO(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("deliberately-planted-secret-canary\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err = ReadPassphraseFD(t.Context(), int(file.Fd()), false); err == nil {
		t.Fatal("plaintext disk passphrase accepted")
	}
	fifo := filepath.Join(directory, "fifo")
	if err = unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(fifo, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			t.Error(err)
		}
	}()
	if _, err = ReadPassphraseFD(t.Context(), fd, false); err == nil {
		t.Fatal("named FIFO accepted as anonymous pipe")
	}
}
