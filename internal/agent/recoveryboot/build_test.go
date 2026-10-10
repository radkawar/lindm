package recoveryboot

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fixtureIngredient(t *testing.T, directory, name string, data []byte) Ingredient {
	t.Helper()
	file := filepath.Join(directory, name)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return Ingredient{Source: file, SHA256: digest[:]}
}

func TestApprovedIngredientRejectsDigestPermissionAndLinkChanges(t *testing.T) {
	for _, variant := range []string{"digest", "world_write", "link", "missing_digest"} {
		t.Run(variant, func(t *testing.T) {
			directory := t.TempDir()
			input := fixtureIngredient(t, directory, "kernel", []byte("approved-release-kernel"))
			switch variant {
			case "digest":
				input.SHA256 = make([]byte, 32)
			case "world_write":
				if err := os.Chmod(input.Source, 0666); err != nil {
					t.Fatal(err)
				}
			case "link":
				link := filepath.Join(directory, "linked")
				if err := os.Symlink(input.Source, link); err != nil {
					t.Fatal(err)
				}
				input.Source = link
			case "missing_digest":
				input.SHA256 = nil
			}
			if err := VerifyImage(context.Background(), input.Source, input.SHA256); err == nil {
				t.Fatal("unapproved image accepted")
			}
			if err := copyApproved(input, filepath.Join(directory, "staged"), 0600); err == nil {
				t.Fatal("unapproved image staged")
			}
			if _, err := os.Stat(filepath.Join(directory, "staged")); !os.IsNotExist(err) {
				t.Fatal("rejected image created a stage file")
			}
		})
	}
}

func TestCopyNeverReplacesExistingArtifact(t *testing.T) {
	dir := t.TempDir()
	input := fixtureIngredient(t, dir, "approved", []byte("approved"))
	destination := filepath.Join(dir, "existing")
	if err := os.WriteFile(destination, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyApproved(input, destination, 0600); err == nil {
		t.Fatal("replaced unrelated file")
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "unrelated" {
		t.Fatal("modified unrelated file")
	}
}

type failedCopyReader struct {
	cause error
}

func (r failedCopyReader) Read([]byte) (int, error) {
	return 0, r.cause
}

func TestExclusiveCopyCleansOwnedPartialAndPreservesCause(t *testing.T) {
	for _, cause := range []error{syscall.ENOSPC, syscall.EIO, io.ErrUnexpectedEOF} {
		t.Run(cause.Error(), func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "partial")
			err := withExclusiveFile(target, 0600, func(out *os.File) error {
				source := io.MultiReader(strings.NewReader("partially copied image"), failedCopyReader{cause: cause})
				_, err := io.Copy(out, source)
				return err
			})
			if !errors.Is(err, cause) {
				t.Fatalf("copy lost failure cause: %v", err)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed copy retained its partial file: %v", err)
			}
			// A fresh exclusive create proves failure did not leave a replay-
			// blocking pathname. This is not an automatic staging retry.
			if err := writeExclusive(target, []byte("new file"), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExclusiveCopyCleansSyncAndCloseFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "partial")
	err := withExclusiveFile(target, 0600, func(out *os.File) error {
		if _, err := out.Write([]byte("partial")); err != nil {
			return err
		}
		// Closing the actual descriptor forces the subsequent Sync and Close
		// to fail without a process-global fault injector or a full filesystem.
		return out.Close()
	})
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("sync/close failure lost: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed sync/close left a newly owned file: %v", err)
	}
}

func TestExclusiveCopyPreservesExistingAndReplacementFiles(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "replacement"}[replacement], func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "unrelated")
			if !replacement {
				if err := os.WriteFile(target, []byte("unrelated"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			err := withExclusiveFile(target, 0600, func(out *os.File) error {
				called = true
				if !replacement {
					t.Fatal("existing path reached exclusive writer")
				}
				if _, err := out.Write([]byte("partial")); err != nil {
					return err
				}
				if err := os.Remove(target); err != nil {
					return err
				}
				if err := os.WriteFile(target, []byte("unrelated"), 0600); err != nil {
					return err
				}
				return syscall.ENOSPC
			})
			if replacement {
				if !called || !errors.Is(err, syscall.ENOSPC) || !strings.Contains(err.Error(), "exclusive_file_ownership_changed") {
					t.Fatalf("replacement ownership failure lost: %v", err)
				}
			} else if called || !errors.Is(err, os.ErrExist) {
				t.Fatalf("existing file was not rejected by exclusive create: %v", err)
			}
			got, readErr := os.ReadFile(target)
			if readErr != nil || string(got) != "unrelated" {
				t.Fatalf("cleanup changed unrelated file: %q, %v", got, readErr)
			}
		})
	}
}

func TestCopyApprovedRetainsCompleteVerifiedFile(t *testing.T) {
	dir := t.TempDir()
	input := fixtureIngredient(t, dir, "approved", []byte("approved image bytes"))
	target := filepath.Join(dir, "staged")
	if err := copyApproved(input, target, 0600); err != nil {
		t.Fatal(err)
	}
	if err := approved(Ingredient{Source: target, SHA256: input.SHA256}); err != nil {
		t.Fatalf("complete verified copy was removed or changed: %v", err)
	}
}

func TestInitramfsReproducibleAndRejectsClosureEscape(t *testing.T) {
	dir := t.TempDir()
	input := fixtureIngredient(t, dir, "ingredient", []byte("deterministic-approved-bytes"))
	request := BuildRequest{Kernel: input, Stub: input, Busybox: input, Agent: input, Config: input, Certificate: input, StateUUID: "12345678-1234-1234-1234-123456789abc", ESPUUID: "ABCD-1234", SourceDateEpoch: 1700000000}
	first, second := filepath.Join(dir, "first.cpio"), filepath.Join(dir, "second.cpio")
	closure, err := writeInitramfs(first, request)
	if err != nil {
		t.Fatal(err)
	}
	other, err := writeInitramfs(second, request)
	if err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) || closure != other {
		t.Fatal("identical approved closure produced different initramfs")
	}
	compressed, err := gzip.NewReader(bytes.NewReader(a))
	if err != nil {
		t.Fatalf("initramfs is not gzip-compressed: %v", err)
	}
	if !compressed.ModTime.IsZero() || compressed.Name != "" || compressed.Comment != "" {
		t.Fatal("gzip header carries host-dependent metadata")
	}
	archive, readErr := io.ReadAll(compressed)
	if err := errors.Join(readErr, compressed.Close()); err != nil {
		t.Fatal(err)
	}
	if len(a) >= len(archive) {
		t.Fatal("initramfs compression did not reduce the fixture archive")
	}
	// Decode the decompressed kernel payload, not just its compression header.
	// All payloads must remain aligned newc records with required boot files.
	entries := decodeCPIO(t, archive)
	for _, name := range []string{".", "init", "etc/lindm/udhcpc", "bin/busybox", "usr/bin/lindm-agent", "etc/lindm/recovery.json", "etc/lindm/image-signing.pem"} {
		if _, ok := entries[name]; !ok {
			t.Fatalf("missing boot ingredient %s", name)
		}
	}
	for _, destination := range []string{"../escape", "/absolute", "etc/../escape", "init", "usr/bin/lindm-agent", "usr"} {
		request.Files = []Ingredient{{Source: input.Source, SHA256: input.SHA256, Destination: destination}}
		if _, err := writeInitramfs(filepath.Join(dir, "rejected"), request); err == nil {
			t.Fatalf("accepted invalid destination %q", destination)
		}
	}
}

func TestMissingNativeClosureRejectedBeforeBuild(t *testing.T) {
	if err := validateClosure(nil); err == nil || !strings.Contains(err.Error(), "required_native_helper_missing") {
		t.Fatalf("missing native closure not rejected: %v", err)
	}
}

func TestBuildRejectsUnsafeCustodyIdentityBeforeTools(t *testing.T) {
	for _, request := range []BuildRequest{{StateUUID: "$(poweroff)"}, {ESPUUID: "invalid"}, {StateUUID: "12345678-1234-1234-1234-123456789abc", SourceDateEpoch: -1}} {
		if _, err := Build(context.Background(), request); err == nil || !strings.Contains(err.Error(), "invalid_build_identity") {
			t.Fatalf("unsafe build identity accepted: %v", err)
		}
	}
}

func TestRecoveryCommandLinePinsDiagnosticConsole(t *testing.T) {
	for _, console := range []string{"", "ttyS0,115200n8", "ttyAMA0,115200"} {
		commandLine, err := recoveryCommandLine(console)
		if err != nil || !strings.HasPrefix(commandLine, "rdinit=/init panic=10 quiet") {
			t.Fatalf("console %q lost closed recovery init: %q, %v", console, commandLine, err)
		}
		if console != "" && !strings.HasSuffix(commandLine, " console=tty0 console="+console) {
			t.Fatalf("console %q not embedded in signed command line: %q", console, commandLine)
		}
	}
	for _, console := range []string{"ttyS0 init=/bin/sh", "ttyS0\nrdinit=/bin/sh", "/dev/console", "ttyS0,9600"} {
		if _, err := recoveryCommandLine(console); err == nil {
			t.Fatalf("arbitrary kernel console accepted: %q", console)
		}
	}
}

func TestRecoveryInitOpensConsoleAfterDeviceMount(t *testing.T) {
	mount := strings.Index(initScript, "$BB mount -t devtmpfs devtmpfs /dev\n")
	console := strings.Index(initScript, "exec </dev/console >/dev/console 2>&1\n")
	proc := strings.Index(initScript, "$BB mount -t proc proc /proc\n")
	if mount < 0 || console <= mount || proc <= console {
		t.Fatal("recovery init must bind standard streams after devices exist and before fallible setup")
	}
	if !strings.Contains(initScript, "trap fail EXIT INT TERM") || !strings.Contains(initScript, "fail() { $BB poweroff -f; exit 1; }") {
		t.Fatal("console diagnostics must not introduce an interactive failure path")
	}
}
