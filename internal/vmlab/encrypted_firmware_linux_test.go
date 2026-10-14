// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptedFirmwareExactPackageOwnership(t *testing.T) {
	const files = "/usr/share/OVMF/code.fd\n/usr/share/OVMF/vars.fd\n"
	for _, tc := range []struct {
		name, version, files string
		wantError            bool
	}{
		{"exact", "installed\novmf\n2024.02-1\n", files, false},
		{"version drift", "installed\novmf\n2024.02-2\n", files, true},
		{"wrong package", "installed\nother\n2024.02-1\n", files, true},
		{"removed package", "config-files\novmf\n2024.02-1\n", files, true},
		{"multiple packages", "installed\novmf\n2024.02-1\ninstalled\novmf\n2024.02-1\n", files, true},
		{"unowned vars", "installed\novmf\n2024.02-1\n", "/usr/share/OVMF/code.fd\n/usr/share/OVMF/vars.fd.other\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := matchEncryptedFirmwarePackage([]byte(tc.version), []byte(tc.files), "ovmf", "2024.02-1", "/usr/share/OVMF/code.fd", "/usr/share/OVMF/vars.fd")
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error %v", err, tc.wantError)
			}
		})
	}
}

func TestEncryptedFirmwareCopiesPrivateIndependentNVRAM(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "template.fd"), filepath.Join(dir, "nvram.fd")
	original := []byte("firmware variable template")
	if err := os.WriteFile(source, original, 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := copyEncryptedFirmware(t.Context(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(original)
	if digest != hex.EncodeToString(want[:]) {
		t.Fatal("copy digest does not identify initial variable state")
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private copy mode: %v, %v", info, err)
	}
	if _, err := copyEncryptedFirmware(t.Context(), source, destination); err == nil {
		t.Fatal("overwrote an existing run's NVRAM")
	}
	if err := os.WriteFile(destination, []byte("guest changed its NVRAM"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(source)
	if err != nil || string(data) != string(original) {
		t.Fatalf("shared variable template changed: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := copyEncryptedFirmware(ctx, source, filepath.Join(dir, "cancelled.fd")); err == nil {
		t.Fatal("cancelled copy succeeded")
	}
}

func TestEncryptedFirmwareRejectsUnenrolledVariables(t *testing.T) {
	variable := func(name, guid string) map[string]string {
		return map[string]string{"name": name, "guid": guid, "data": strings.Repeat("01", 128)}
	}
	global := "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	db := "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
	for _, tc := range []struct {
		name      string
		variables []map[string]string
		wantError bool
	}{
		{"enrolled", []map[string]string{variable("PK", global), variable("KEK", global), variable("db", db)}, false},
		{"empty template", nil, true},
		{"PK only", []map[string]string{variable("PK", global)}, true},
		{"wrong namespace", []map[string]string{variable("PK", db), variable("KEK", global), variable("db", db)}, true},
		{"duplicate key", []map[string]string{variable("PK", global), variable("PK", global), variable("KEK", global), variable("db", db)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(map[string]any{"version": 2, "variables": tc.variables})
			if err != nil {
				t.Fatal(err)
			}
			if err := encryptedEnrolledVars(data); (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error %v", err, tc.wantError)
			}
		})
	}
}
