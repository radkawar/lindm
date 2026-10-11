package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

type signingFixture struct {
	home    string
	primary string
	subkey  string
	key     []byte
}

func newSigningFixture(t *testing.T) signingFixture {
	t.Helper()
	for _, tool := range []string{"gpg", "gpgv", "gpgconf"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("image verification tests require %s: %v", tool, err)
		}
	}
	fixture := signingFixture{home: t.TempDir()}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "gpgconf", "--homedir", fixture.home, "--kill", "gpg-agent").Run()
	})
	fixture.gpg(t, nil, "--quick-generate-key", "Lindm image test <images@example.invalid>", "ed25519", "cert", "1d")
	listing := fixture.gpg(t, nil, "--with-colons", "--list-keys")
	fixture.primary = firstFingerprint(t, listing)
	fixture.gpg(t, nil, "--quick-add-key", fixture.primary, "ed25519", "sign", "1d")
	listing = fixture.gpg(t, nil, "--with-colons", "--list-keys")
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" && fields[9] != fixture.primary {
			fixture.subkey = fields[9]
		}
	}
	if fixture.subkey == "" {
		t.Fatal("signing fixture lacks signing subkey")
	}
	fixture.key = fixture.gpg(t, nil, "--armor", "--export", fixture.primary)
	return fixture
}

func firstFingerprint(t *testing.T, listing []byte) string {
	t.Helper()
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			return fields[9]
		}
	}
	t.Fatal("gpg did not return a fixture fingerprint")
	return ""
}

func (f signingFixture) gpg(t *testing.T, input []byte, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	base := []string{"--no-options", "--homedir", f.home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""}
	cmd := exec.CommandContext(ctx, "gpg", append(base, args...)...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("create isolated signing fixture: %v: %s", err, stderr.String())
	}
	return out
}

func testManifest(image []byte, fingerprint string, mode labv1.ChecksumMode) *labv1.ImageManifest {
	hash := sha256.Sum256(image)
	m := &labv1.ImageManifest{
		Id: "test-release", Distribution: "test", Version: "1", Architecture: "amd64", Edition: "cloud", Release: "1.0",
		ImageFilename: "image.qcow2", ImageUrl: "https://example.invalid/image.qcow2",
		ChecksumUrl: "https://example.invalid/checksums", KeyUrl: "https://example.invalid/key",
		Sha256: hex.EncodeToString(hash[:]), SignerFingerprint: fingerprint, ImageSizeBytes: uint64(len(image)), ChecksumMode: mode,
		SignerProvenanceUrl: "https://example.invalid/security/", ReleaseProvenanceUrl: "https://example.invalid/releases/1.0/",
	}
	if detachedChecksum(mode) {
		m.SignatureUrl = proto.String("https://example.invalid/signature")
	}
	return m
}

func TestManifestRepositorySnapshot(t *testing.T) {
	for _, tc := range []struct {
		name         string
		distribution string
		snapshot     *string
		wantError    bool
	}{
		{name: "other distribution unpinned", distribution: "fedora"},
		{name: "Arch unpinned", distribution: "arch", wantError: true},
		{name: "Arch pinned", distribution: "arch", snapshot: proto.String("2026-10-02")},
		{name: "empty date", distribution: "arch", snapshot: proto.String(""), wantError: true},
		{name: "mutable alias", distribution: "arch", snapshot: proto.String("latest"), wantError: true},
		{name: "unpadded date", distribution: "arch", snapshot: proto.String("2026-1-2"), wantError: true},
		{name: "invalid month", distribution: "arch", snapshot: proto.String("2026-13-02"), wantError: true},
		{name: "invalid day", distribution: "arch", snapshot: proto.String("2026-10-32"), wantError: true},
		{name: "path injection", distribution: "arch", snapshot: proto.String("../../etc"), wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := testManifest([]byte("image"), strings.Repeat("A", 40), labv1.ChecksumMode_CHECKSUM_MODE_DETACHED)
			manifest.Distribution = tc.distribution
			manifest.RepositorySnapshotDate = tc.snapshot
			if err := validateManifest(manifest); (err != nil) != tc.wantError {
				t.Fatalf("validateManifest() = %v, want error %t", err, tc.wantError)
			}
		})
	}
}

func checksumText(m *labv1.ImageManifest) string {
	if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED {
		return fmt.Sprintf("%s *%s\n", m.Sha256, m.ImageFilename)
	}
	return fmt.Sprintf("# %s: %d bytes\nSHA256 (%s) = %s\n", m.ImageFilename, m.ImageSizeBytes, m.ImageFilename, m.Sha256)
}

func (f signingFixture) signed(t *testing.T, m *labv1.ImageManifest, text string) (checksum, signature []byte) {
	t.Helper()
	args := []string{"--local-user", f.primary, "--digest-algo", "SHA256", "--output", "-"}
	if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED || m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512 {
		return []byte(text), f.gpg(t, []byte(text), append(args, "--detach-sign")...)
	}
	return f.gpg(t, []byte(text), append(args, "--clearsign")...), nil
}

func writeArtifacts(t *testing.T, image, checksum, signature, key []byte) Artifacts {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string][]byte{"image": image, "checksums": checksum, "signature": signature, "key": key} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return Artifacts{Image: filepath.Join(dir, "image"), Checksum: filepath.Join(dir, "checksums"), Signature: filepath.Join(dir, "signature"), Key: filepath.Join(dir, "key")}
}

func TestVerifyArtifactsSignedBoundaries(t *testing.T) {
	fixture := newSigningFixture(t)
	other := newSigningFixture(t)
	image := []byte("finite fixture cloud image bytes\n")
	for _, mode := range []labv1.ChecksumMode{labv1.ChecksumMode_CHECKSUM_MODE_DETACHED, labv1.ChecksumMode_CHECKSUM_MODE_CLEARSIGNED, labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512} {
		t.Run(mode.String(), func(t *testing.T) {
			original := testManifest(image, fixture.primary, mode)
			text := checksumText(original)
			if mode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512 {
				text = sha512ChecksumText(original, image)
			}
			checksum, signature := fixture.signed(t, original, text)
			t.Run("primary authorizes bound signing subkey", func(t *testing.T) {
				result, err := VerifyArtifacts(context.Background(), original, writeArtifacts(t, image, checksum, signature, fixture.key))
				if err != nil {
					t.Fatal(err)
				}
				if result.SigningFingerprint != fixture.subkey || result.PrimaryFingerprint != fixture.primary || result.SHA256 != original.Sha256 || result.Size != int64(len(image)) {
					t.Fatalf("incorrect verified image evidence: %+v", result)
				}
			})
			t.Run("exact signing subkey and binary keyring", func(t *testing.T) {
				m := proto.CloneOf(original)
				m.SignerFingerprint = fixture.subkey
				binaryKey := fixture.gpg(t, nil, "--export", fixture.primary)
				if _, err := VerifyArtifacts(context.Background(), m, writeArtifacts(t, image, checksum, signature, binaryKey)); err != nil {
					t.Fatal(err)
				}
			})
			for _, failure := range []string{"wrong signer", "unsigned", "tampered checksum", "tampered image", "truncated image", "wrong pinned digest", "missing filename", "duplicate filename", "unrelated keyring", "symlink image"} {
				t.Run(failure, func(t *testing.T) {
					m := proto.CloneOf(original)
					payload, sums, sig, key := bytes.Clone(image), bytes.Clone(checksum), bytes.Clone(signature), bytes.Clone(fixture.key)
					switch failure {
					case "wrong signer":
						sums, sig = other.signed(t, m, text)
						key = append(key, other.key...)
					case "unsigned":
						sums, sig = []byte(text), nil
					case "tampered checksum":
						sums = bytes.Replace(sums, []byte(m.ImageFilename), []byte("other.qcow2"), 1)
					case "tampered image":
						payload[0] ^= 1
					case "truncated image":
						payload = payload[:len(payload)-1]
					case "wrong pinned digest":
						m.Sha256 = strings.Repeat("0", 64)
					case "missing filename":
						sums, sig = fixture.signed(t, m, strings.ReplaceAll(text, m.ImageFilename, "other.qcow2"))
					case "duplicate filename":
						sums, sig = fixture.signed(t, m, text+text)
					case "unrelated keyring":
						key = other.key
					}
					files := writeArtifacts(t, payload, sums, sig, key)
					if failure == "symlink image" {
						link := filepath.Join(t.TempDir(), "image-link")
						if err := os.Symlink(files.Image, link); err != nil {
							t.Fatal(err)
						}
						files.Image = link
					}
					if _, err := VerifyArtifacts(context.Background(), m, files); err == nil {
						t.Fatal("unsafe image was accepted")
					}
				})
			}
		})
	}
}

func TestPublicKeyArmorCorruption(t *testing.T) {
	fixture := newSigningFixture(t)
	binary := fixture.gpg(t, nil, "--export", fixture.primary)
	decoded, err := publicKeyring(fixture.key)
	if err != nil || !bytes.Equal(decoded, binary) {
		t.Fatalf("public key armor did not preserve key packets: %v", err)
	}
	lines := strings.Split(string(fixture.key), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "=") {
			lines[i] = "=AAAA"
		}
	}
	if _, err := publicKeyring([]byte(strings.Join(lines, "\n"))); err == nil {
		t.Fatal("corrupt key armor checksum accepted")
	}
}
