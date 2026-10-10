package recoveryboot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
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
	// Check the archive as a consumer, not an echo of source text: all payloads
	// are aligned newc records and the required boot/runtime files are present.
	entries := decodeCPIO(t, a)
	for _, name := range []string{"init", "etc/lindm/udhcpc", "bin/busybox", "usr/bin/lindm-agent", "etc/lindm/recovery.json", "etc/lindm/image-signing.pem"} {
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
