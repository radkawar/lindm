//go:build linux

package vmlab

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestEncryptedMachineArchitecture(t *testing.T) {
	firmware := EncryptedFirmwareOptions{Code: "code.fd", Vars: "vars.fd", Package: "firmware", Version: "pinned"}
	for _, architecture := range []string{"amd64", "x86_64", "arm64", "aarch64"} {
		t.Run(architecture, func(t *testing.T) {
			hardware, err := encryptedMachineHardware(&labv1.ImageManifest{Architecture: architecture}, EncryptedVMOptions{Firmware: firmware, Hardware: &VMHardwareOptions{Accelerator: "tcg", TPM: true}})
			if err != nil {
				t.Fatal(err)
			}
			want, _, err := encryptedInstallerArchitecture(architecture)
			if err != nil || hardware.Architecture != want || hardware.Firmware == nil || !hardware.TPM {
				t.Fatalf("incorrect manifest hardware: %+v, %v", hardware, err)
			}
		})
	}
	if _, err := encryptedMachineHardware(&labv1.ImageManifest{Architecture: "aarch64"}, EncryptedVMOptions{Firmware: firmware, Hardware: &VMHardwareOptions{Architecture: "x86_64"}}); err == nil {
		t.Fatal("accepted hardware architecture different from signed installer manifest")
	}
	if _, err := encryptedMachineHardware(nil, EncryptedVMOptions{}); err == nil {
		t.Fatal("accepted missing installer manifest")
	}
}

func TestEncryptedUnlockSerialFragmentedPrompt(t *testing.T) {
	host, guest := net.Pipe()
	defer func() { _ = host.Close(); _ = guest.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		for _, part := range []string{"booting kernel\r\nPlease enter pass", "phrase for disk fixture: "} {
			if _, err := io.WriteString(guest, part); err != nil {
				done <- err
				return
			}
		}
		input := make([]byte, len("recovery-key\r"))
		_, err := io.ReadFull(guest, input)
		if err == nil && string(input) != "recovery-key\r" {
			t.Errorf("unexpected unlock bytes")
		}
		cancel()
		done <- err
	}()
	var diagnostic strings.Builder
	seen, err := unlockEncryptedSerial(ctx, host, "recovery-key", &cappedWriter{w: &diagnostic, remaining: 4096})
	if err != nil || !seen {
		t.Fatalf("unlock prompt: seen=%v err=%v", seen, err)
	}
	if diagnostic.String() != "booting kernel\r\nPlease enter passphrase for disk fixture: " {
		t.Fatalf("private diagnosis did not retain only the received console bytes: %q", diagnostic.String())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedUnlockSerialRejectsRepeatedPrompt(t *testing.T) {
	host, guest := net.Pipe()
	defer func() { _ = host.Close(); _ = guest.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(guest, "Please unlock disk cryptroot: "); err != nil {
			done <- err
			return
		}
		if _, err := io.ReadFull(guest, make([]byte, len("wrong-key\r"))); err != nil {
			done <- err
			return
		}
		_, err := io.WriteString(guest, "No key available\r\nPlease unlock disk cryptroot: ")
		done <- err
	}()
	seen, err := unlockEncryptedSerial(ctx, host, "wrong-key", nil)
	if !seen || err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected explicit rejection, seen=%v err=%v", seen, err)
	}
	if strings.Contains(err.Error(), "wrong-key") {
		t.Fatal("secret leaked into error")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Tumbleweed's systemd tty agent erases and rewrites its prompt line once input
// arrives; that is the same request, not a rejection. A prompt on a fresh line
// after submission still is.
func TestEncryptedUnlockSerialPromptRedrawIsNotRejection(t *testing.T) {
	const prompt = "\r\nPlease enter passphrase for disk cr_root::"
	for _, tc := range []struct {
		name, after string
		rejected    bool
	}{
		{"redraw", "\x1b[2K\rPlease enter passphrase for disk cr_root: \r\n[  OK  ] Finished Cryptography Setup for cr_root.\r\n", false},
		{"redraw then fresh prompt", "\x1b[2K\rPlease enter passphrase for disk cr_root: \r\n" + prompt, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, guest := net.Pipe()
			defer func() { _ = host.Close(); _ = guest.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if _, err := io.WriteString(guest, prompt); err != nil {
					done <- err
					return
				}
				if _, err := io.ReadFull(guest, make([]byte, len("secret\r"))); err != nil {
					done <- err
					return
				}
				_, err := io.WriteString(guest, tc.after)
				done <- err
			}()
			seen, err := unlockEncryptedSerial(ctx, host, "secret", nil)
			if !seen || (err != nil) != tc.rejected || (err != nil && err.Error() != "encrypted boot rejected unlock secret") {
				t.Fatalf("seen=%v err=%v, want rejected=%v", seen, err, tc.rejected)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A serial console delivers the agent's per-keystroke redraws and the boot
// output that follows in small reads. Bounding the retained console tail must
// never cut a redraw's erase sequence and so turn its prompt text into what
// looks like a fresh prompt (observed as a false rejection on Tumbleweed).
func TestEncryptedUnlockSerialBoundedTailKeepsRedrawsIntact(t *testing.T) {
	const prompt = "\r\nPlease enter passphrase for disk cr_root::"
	var after strings.Builder
	for i := range 64 {
		after.WriteString("\x1b[2K\rPlease enter passphrase for disk cr_root::" + strings.Repeat("*", i+1))
	}
	after.WriteString("\r\n")
	for i := range 400 {
		fmt.Fprintf(&after, "[  OK  ] Started boot unit %03d of the initrd.\r\n", i)
	}
	host, guest := net.Pipe()
	defer func() { _ = host.Close(); _ = guest.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(guest, prompt); err != nil {
			done <- err
			return
		}
		if _, err := io.ReadFull(guest, make([]byte, len("secret\r"))); err != nil {
			done <- err
			return
		}
		data := after.String()
		for i := range len(data) {
			if _, err := io.WriteString(guest, data[i:i+1]); err != nil {
				done <- err
				return
			}
		}
		// Every byte was consumed without a rejection: end the wait.
		cancel()
		done <- nil
	}()
	seen, err := unlockEncryptedSerial(ctx, host, "secret", nil)
	if !seen || err != nil {
		t.Fatalf("seen=%v err=%v, want the redrawn prompt accepted", seen, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedUnlockSerialRejectsFailureWithoutRepeatedPrompt(t *testing.T) {
	for _, message := range []string{
		"No key available with this passphrase.",
		"Failed to activate with specified passphrase. (Passphrase incorrect?)",
	} {
		t.Run(message, func(t *testing.T) {
			host, guest := net.Pipe()
			defer func() { _ = host.Close(); _ = guest.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if _, err := io.WriteString(guest, "Please enter passphrase for disk fixture: "); err != nil {
					done <- err
					return
				}
				if _, err := io.ReadFull(guest, make([]byte, len("wrong-key\r"))); err != nil {
					done <- err
					return
				}
				for _, part := range []string{message[:len(message)/2], message[len(message)/2:]} {
					if _, err := io.WriteString(guest, part); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			seen, err := unlockEncryptedSerial(ctx, host, "wrong-key", nil)
			if !seen || err == nil || err.Error() != "encrypted boot rejected unlock secret" {
				t.Fatalf("expected explicit passphrase rejection, seen=%v err=%v", seen, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncryptedPromptDoesNotMatchLogin(t *testing.T) {
	for _, text := range []string{"lindm-lab login:", "Password:", "Enter your password:", "systemd-ask-password: service starting"} {
		if encryptedUnlockPrompt(text) {
			t.Fatalf("non-LUKS prompt matched: %q", text)
		}
	}
}

func TestEncryptedUnattendedBootRejectsPasswordPrompt(t *testing.T) {
	host, guest := net.Pipe()
	defer func() { _ = host.Close(); _ = guest.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(guest, "Please unlock disk cryptroot: "); done <- err }()
	seen, err := unlockEncryptedSerial(ctx, host, "", nil)
	if err == nil || !seen || !strings.Contains(err.Error(), "unattended") {
		t.Fatalf("prompt was not rejected: seen=%v err=%v", seen, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(guest)
	if err != nil || len(data) != 0 {
		t.Fatalf("unattended boot transmitted secret input: bytes=%d err=%v", len(data), err)
	}
}

func TestEncryptedCopyRejectsSymlinks(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	for _, name := range []string{"firmware-code.fd", "nvram.fd"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(source, "tpm"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../nvram.fd", filepath.Join(source, "tpm", "state")); err != nil {
		t.Fatal(err)
	}
	if err := copyEncryptedState(source, target); err == nil {
		t.Fatal("symlink TPM state copied")
	}
}

func TestEncryptedSnapshotRequiresCompleteStoppedMachine(t *testing.T) {
	v := &EncryptedVM{guest: new(guestVM)}
	if err := v.Snapshot(context.Background(), filepath.Join(t.TempDir(), "snapshot")); err == nil {
		t.Fatal("live disk-only snapshot accepted")
	}
	if _, err := v.HeadersAll(context.Background()); err == nil {
		t.Fatal("whole-machine header observation accepted while VM is running")
	}
	v.guest = nil
	v.tpm = new(encryptedProcess)
	if _, err := v.Headers(context.Background()); err == nil {
		t.Fatal("header observation accepted while TPM still running")
	}
	if _, err := v.HeadersAll(context.Background()); err == nil {
		t.Fatal("whole-machine header observation accepted while TPM is running")
	}
}
