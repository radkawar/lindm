package recoveryboot

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/foxboron/go-uefi/authenticode"
)

// The fixtures are a minimal PE32+ EFI application signed by sbsigntool 0.9.4
// (`sbsign --key KEY --cert signer.pem`), plus the same image signed by an
// unrelated key. Private keys are not retained.
const authenticodeFixtures = "testdata/authenticode"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(authenticodeFixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// securityDirectory returns the file offset of the PE32+ certificate table
// data-directory entry.
func securityDirectory(t *testing.T, image []byte) int {
	t.Helper()
	header := int(binary.LittleEndian.Uint32(image[0x3c:]))
	if string(image[header:header+4]) != "PE\x00\x00" || binary.LittleEndian.Uint16(image[header+24:]) != 0x20b {
		t.Fatal("fixture is not PE32+")
	}
	return header + 24 + 144
}

func setTable(t *testing.T, image []byte, address, size uint32) {
	t.Helper()
	offset := securityDirectory(t, image)
	binary.LittleEndian.PutUint32(image[offset:], address)
	binary.LittleEndian.PutUint32(image[offset+4:], size)
}

func tableOf(t *testing.T, image []byte) (uint32, uint32) {
	t.Helper()
	offset := securityDirectory(t, image)
	return binary.LittleEndian.Uint32(image[offset:]), binary.LittleEndian.Uint32(image[offset+4:])
}

// transplantedSignature moves signed.efi's signature onto a modified image and
// rewrites only the unsigned SpcIndirectDataContent image digest. The signed
// messageDigest attribute still names the original content.
func transplantedSignature(t *testing.T) []byte {
	t.Helper()
	original := readFixture(t, "signed.efi")
	address, size := tableOf(t, original)
	modified := bytes.Clone(original)
	modified[0x500] ^= 0xff
	parsed, err := authenticode.Parse(bytes.NewReader(modified))
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := parsed.Signatures()
	if err != nil || len(signatures) != 1 {
		t.Fatalf("fixture signatures: %v", err)
	}
	signed, err := authenticode.ParseAuthenticode(signatures[0].Certificate)
	if err != nil {
		t.Fatal(err)
	}
	table := modified[address : address+size]
	at := bytes.Index(table, signed.Digest)
	if at < 0 || bytes.LastIndex(table, signed.Digest) != at {
		t.Fatal("fixture image digest not uniquely located")
	}
	copy(table[at:], parsed.Hash(crypto.SHA256))
	return modified
}

type authenticodeCase struct {
	name        string
	certificate string
	image       func(t *testing.T) []byte
	accept      bool
}

func authenticodeCases() []authenticodeCase {
	signed := func(t *testing.T) []byte { return readFixture(t, "signed.efi") }
	return []authenticodeCase{
		{"valid", "signer.pem", signed, true},
		{"wrong certificate", "other.pem", signed, false},
		{"other signer", "signer.pem", func(t *testing.T) []byte { return readFixture(t, "other-signed.efi") }, false},
		{"unsigned", "signer.pem", func(t *testing.T) []byte { return readFixture(t, "unsigned.efi") }, false},
		{"tampered section", "signer.pem", func(t *testing.T) []byte {
			image := signed(t)
			image[0x500] ^= 1
			return image
		}, false},
		{"tampered header", "signer.pem", func(t *testing.T) []byte {
			image := signed(t)
			image[0x80+24+68] ^= 1 // PE32+ Subsystem
			return image
		}, false},
		{"appended trailing data", "signer.pem", func(t *testing.T) []byte {
			return append(signed(t), make([]byte, 8)...)
		}, false},
		{"truncated certificate table", "signer.pem", func(t *testing.T) []byte {
			image := signed(t)
			address, size := tableOf(t, image)
			setTable(t, image, address, size-16)
			return image[:address+size-16]
		}, false},
		{"truncated signature", "signer.pem", func(t *testing.T) []byte {
			image := signed(t)
			address, _ := tableOf(t, image)
			length := binary.LittleEndian.Uint32(image[address:])
			binary.LittleEndian.PutUint32(image[address:], length-64)
			return image
		}, false},
		{"undersized certificate entry", "signer.pem", func(t *testing.T) []byte {
			image := signed(t)
			address, _ := tableOf(t, image)
			binary.LittleEndian.PutUint32(image[address:], 4)
			return image
		}, false},
		{"multiple signatures", "signer.pem", func(t *testing.T) []byte {
			image := signed(t)
			address, size := tableOf(t, image)
			setTable(t, image, address, size*2)
			return append(image, image[address:address+size]...)
		}, false},
		{"table before section data", "signer.pem", func(t *testing.T) []byte {
			image := signed(t)
			_, size := tableOf(t, image)
			setTable(t, image, 0x400, size)
			return image
		}, false},
		{"transplanted signature", "signer.pem", transplantedSignature, false},
	}
}

func TestAuthenticodeVerifierAcceptsOnlyExactPinnedSignature(t *testing.T) {
	for _, test := range authenticodeCases() {
		t.Run(test.name, func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "image.efi")
			if err := os.WriteFile(image, test.image(t), 0600); err != nil {
				t.Fatal(err)
			}
			err := verifyAuthenticode(image, filepath.Join(authenticodeFixtures, test.certificate))
			if test.accept != (err == nil) {
				t.Fatalf("accept=%v, got %v", test.accept, err)
			}
		})
	}
}

// The pinned go-uefi PKCS#7 verifier checks the RSA signature over the
// authenticated attributes but not their messageDigest; this records why the
// wrapper's own binding is load-bearing.
func TestAuthenticodeTransplantDefeatsUnwrappedLibraryVerify(t *testing.T) {
	parsed, err := authenticode.Parse(bytes.NewReader(transplantedSignature(t)))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := readSignerCertificate(filepath.Join(authenticodeFixtures, "signer.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := parsed.Verify(certificate); !ok || err != nil {
		t.Skipf("library now rejects the transplant (%v, %v); wrapper binding remains required", ok, err)
	}
}

func TestAuthenticodeRejectsUnsafeCertificateAndImageFiles(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "image.efi")
	if err := os.WriteFile(image, readFixture(t, "signed.efi"), 0600); err != nil {
		t.Fatal(err)
	}
	pemData := readFixture(t, "signer.pem")
	for name, data := range map[string][]byte{
		"two certificates": append(bytes.Clone(pemData), pemData...),
		"trailing garbage": append(bytes.Clone(pemData), "junk"...),
		"not pem":          []byte("not a certificate"),
	} {
		certificate := filepath.Join(dir, "certificate.pem")
		if err := os.WriteFile(certificate, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyAuthenticode(image, certificate); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	link := filepath.Join(dir, "link.efi")
	if err := os.Symlink(image, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuthenticode(link, filepath.Join(authenticodeFixtures, "signer.pem")); err == nil {
		t.Fatal("followed an image symlink")
	}
}

// TestAuthenticodeMatchesSbverify cross-checks every fixture against the real
// sbsigntool verifier when it is installed. Differences are only the
// documented strictness additions, where sbverify accepts and lindm refuses.
func TestAuthenticodeMatchesSbverify(t *testing.T) {
	sbverify, err := exec.LookPath("sbverify")
	if err != nil {
		t.Skip("sbverify is not installed; cross-check not run")
	}
	stricter := map[string]bool{"multiple signatures": true}
	for _, test := range authenticodeCases() {
		t.Run(test.name, func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "image.efi")
			if err := os.WriteFile(image, test.image(t), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			native := exec.CommandContext(ctx, sbverify, "--cert", filepath.Join(authenticodeFixtures, test.certificate), image).Run()
			var exit *exec.ExitError
			if native != nil && !errors.As(native, &exit) {
				t.Fatal(native)
			}
			ours := verifyAuthenticode(image, filepath.Join(authenticodeFixtures, test.certificate)) == nil
			theirs := native == nil
			if ours != theirs && (!stricter[test.name] || !theirs || ours) {
				t.Fatalf("lindm accept=%v, sbverify accept=%v", ours, theirs)
			}
			t.Logf("lindm accept=%v sbverify accept=%v", ours, theirs)
		})
	}
}
