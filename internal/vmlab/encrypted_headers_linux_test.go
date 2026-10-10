package vmlab

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const encryptedTestUUID = "12345678-1234-1234-1234-123456789abc"
const encryptedTestMetadata = `{"keyslots":{"0":{"type":"luks2","key_size":64}},"tokens":{},"segments":{"0":{"type":"crypt","offset":"16777216"}},"digests":{},"config":{"json_size":"12288"}}`

func TestEncryptedHeadersEqualityPreservesSecurityMetadata(t *testing.T) {
	original := EncryptedHeader{Device: "/dev/vda3", UUID: encryptedTestUUID, JSON: []byte(encryptedTestMetadata)}
	for _, tc := range []struct {
		name, metadata, uuid string
		wantEqual, wantError bool
	}{
		{"exact", encryptedTestMetadata, encryptedTestUUID, true, false},
		{"format and number spelling", `{"config":{"json_size":"12288"},"digests":{},"segments":{"0":{"offset":"16777216","type":"crypt"}},"tokens":{},"keyslots":{"0":{"key_size":6.4e1,"type":"luks2"}}}`, encryptedTestUUID, true, false},
		{"keyslot changed", strings.Replace(encryptedTestMetadata, "64", "32", 1), encryptedTestUUID, false, false},
		{"token added", strings.Replace(encryptedTestMetadata, `"tokens":{}`, `"tokens":{"0":{"type":"systemd-tpm2","keyslots":["0"]}}`, 1), encryptedTestUUID, false, false},
		{"UUID changed", encryptedTestMetadata, "22345678-1234-1234-1234-123456789abc", false, false},
		{"large integer A", strings.Replace(encryptedTestMetadata, "64", "9007199254740992", 1), encryptedTestUUID, false, false},
		{"duplicate object key", strings.Replace(encryptedTestMetadata, `"key_size":64`, `"key_size":32,"key_size":64`, 1), encryptedTestUUID, false, true},
		{"missing objects", `{}`, encryptedTestUUID, false, true},
		{"trailing JSON", encryptedTestMetadata + `{}`, encryptedTestUUID, false, true},
		{"null object", strings.Replace(encryptedTestMetadata, `"tokens":{}`, `"tokens":null`, 1), encryptedTestUUID, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := EncryptedHeader{Device: "/dev/disk/guestfs/encrypted3", UUID: tc.uuid, JSON: []byte(tc.metadata)}
			equal, err := encryptedHeadersEqual([]EncryptedHeader{original}, []EncryptedHeader{observed})
			if equal != tc.wantEqual || (err != nil) != tc.wantError {
				t.Fatalf("equal/error = %v/%v, want %v/%v", equal, err, tc.wantEqual, tc.wantError)
			}
		})
	}
	largeA, largeB := original, original
	largeA.JSON = []byte(strings.Replace(encryptedTestMetadata, "64", "9007199254740992", 1))
	largeB.JSON = []byte(strings.Replace(encryptedTestMetadata, "64", "9007199254740993", 1))
	if equal, err := encryptedHeadersEqual([]EncryptedHeader{largeA}, []EncryptedHeader{largeB}); err != nil || equal {
		t.Fatalf("large integer precision lost: %v, %v", equal, err)
	}
	if _, err := encryptedHeadersEqual([]EncryptedHeader{original, original}, []EncryptedHeader{original}); err == nil {
		t.Fatal("duplicate UUID accepted")
	}
}

func TestEncryptedHeaderFraming(t *testing.T) {
	valid := "\nLINDM-LUKS2\n/dev/disk/guestfs/encrypted3\n" + encryptedTestUUID + "\n" + encryptedTestMetadata + "\n"
	headers, err := parseEncryptedHeaders([]byte(valid))
	if err != nil || len(headers) != 1 || headers[0].UUID != encryptedTestUUID {
		t.Fatalf("valid oracle output: %v, %v", headers, err)
	}
	wholeDisk := strings.Replace(valid, "encrypted3", "encrypted", 1)
	headers, err = parseEncryptedHeaders([]byte(wholeDisk))
	if err != nil || len(headers) != 1 || headers[0].Device != "/dev/disk/guestfs/encrypted" {
		t.Fatalf("whole-disk LUKS oracle output: %v, %v", headers, err)
	}
	for _, empty := range []string{"", "\n"} {
		headers, err := parseEncryptedHeaders([]byte(empty))
		if err != nil || headers == nil || len(headers) != 0 {
			t.Fatalf("successful empty scan must remain distinguishable from errors: %v, %v", headers, err)
		}
	}
	for _, invalid := range []string{
		"tool warning" + valid, valid + valid,
		strings.Replace(valid, "/dev/disk/guestfs/encrypted3", "/dev/sda", 1),
		strings.Replace(valid, "encrypted3", "encrypted03", 1),
		strings.Replace(valid, "encrypted3", "encrypted0", 1),
		strings.Replace(valid, "encrypted3", "encrypted-other", 1),
		strings.Replace(valid, encryptedTestUUID, "not-a-uuid", 1),
		strings.Replace(valid, encryptedTestMetadata, "null", 1),
		valid + "unexpected suffix",
	} {
		if _, err := parseEncryptedHeaders([]byte(invalid)); err == nil {
			t.Fatal("accepted malformed, missing, duplicate or ambiguous header evidence")
		}
	}
}

func TestEncryptedOracleRejectsHostDevicesAndUnsafeBacking(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Rejection precedes guestfish lookup or any host block-device attachment.
	if _, err := readEncryptedHeaders(t.Context(), "/dev/null", dir); err == nil {
		t.Fatal("accepted nonregular overlay")
	}
	for _, tc := range []struct {
		name, backing string
		external      bool
		wantError     bool
	}{
		{"standalone", "", false, false},
		{"host device", "/dev/null", false, true},
		{"network", "nbd:example.invalid:10809", false, true},
		{"relative backing", "base.qcow2", false, true},
		{"external data", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 104+len(tc.backing))
			copy(data, "QFI\xfb")
			binary.BigEndian.PutUint32(data[4:8], 3)
			if tc.external {
				binary.BigEndian.PutUint64(data[72:80], 1<<2)
			}
			if tc.backing != "" {
				binary.BigEndian.PutUint64(data[8:16], 104)
				binary.BigEndian.PutUint32(data[16:20], uint32(len(tc.backing)))
				copy(data[104:], tc.backing)
			}
			path := filepath.Join(t.TempDir(), "overlay.qcow2")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			file, err := openRegular(path)
			if err != nil {
				t.Fatal(err)
			}
			err = encryptedQCOWChain(file, path, 0)
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if (err != nil) != tc.wantError {
				t.Fatalf("backing safety error = %v, want error %v", err, tc.wantError)
			}
		})
	}
}
