// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestCapturedEncryptedStorageIdentity(t *testing.T) {
	for _, distribution := range []string{"ubuntu24", "fedora44"} {
		t.Run(distribution, func(t *testing.T) {
			directory := filepath.Join("testdata", "storage", distribution)
			load := func(name string) []byte {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			var provenance struct {
				Match     bool              `json:"independent_oracle_match"`
				Cleaned   bool              `json:"guest_cleaned"`
				Unchanged bool              `json:"stopped_headers_unchanged"`
				UUID      string            `json:"luks_uuid"`
				Serial    string            `json:"controller_serial"`
				WWN       string            `json:"controller_wwn"`
				Size      uint64            `json:"stopped_partition_size_bytes"`
				Files     map[string]string `json:"files_sha256"`
			}
			if err := json.Unmarshal(load("provenance.json"), &provenance); err != nil {
				t.Fatal(err)
			}
			if !provenance.Match || !provenance.Cleaned || !provenance.Unchanged || provenance.UUID == "" || provenance.Serial == "" || provenance.WWN == "" || provenance.Size == 0 {
				t.Fatal("capture lacks independent completed identity proof")
			}
			for name, expected := range provenance.Files {
				if !filepath.IsLocal(name) || filepath.Base(name) != name {
					t.Fatal("invalid capture filename")
				}
				digest := sha256.Sum256(load(name))
				if hex.EncodeToString(digest[:]) != expected {
					t.Fatalf("capture digest mismatch for %s", name)
				}
			}
			parsed := parseStorage(bytes.NewReader(load("lsblk.json")))
			if parsed.Status != success {
				t.Fatalf("native lsblk parse failed: %v", parsed.Status)
			}
			var root *inventoryv1.BlockDevice
			for _, device := range parsed.Devices {
				if device.GetIdentity().GetLuksUuid().GetValue() == provenance.UUID {
					root = device
				}
			}
			if root == nil || root.Identity.Serial.Value != provenance.Serial || root.Identity.Wwn.Value != provenance.WWN || root.SizeBytes.Value != provenance.Size || !root.Identity.RootBacking.Value {
				t.Fatalf("captured lsblk exact root identity mismatch: %v", root)
			}
			text, status := parseLUKSSummary(bytes.NewReader(load("luks.txt")))
			if status != success || text.uuid != provenance.UUID {
				t.Fatalf("native LUKS text mismatch: %v", status)
			}
			metadata, status := parseLUKSMetadata(bytes.NewReader(load("luks.json")))
			if status != success {
				t.Fatalf("native LUKS metadata failed: %v", status)
			}
			slices.Sort(text.types)
			if text.keyslots != metadata.keyslots || text.tokens != metadata.tokens || !slices.Equal(text.types, metadata.types) {
				t.Fatal("native public metadata disagrees with text")
			}
			observed := new(inventoryv1.StorageDetails)
			if err := protojson.Unmarshal(load("agent-storage.json"), observed); err != nil {
				t.Fatal(err)
			}
			if err := protovalidate.Validate(observed); err != nil {
				t.Fatal(err)
			}
			var actual *inventoryv1.BlockDevice
			for _, device := range observed.Devices {
				if device.GetIdentity().GetLuksUuid().GetValue() == provenance.UUID {
					actual = device
				}
			}
			if actual == nil || actual.Identity.Serial.Value != provenance.Serial || actual.Identity.Wwn.Value != provenance.WWN || actual.Identity.LuksKeyslotCount.Value != metadata.keyslots || actual.Identity.LuksTokenCount.Value != metadata.tokens || actual.Identity.LuksTokenTypes.Value != strings.Join(metadata.types, ",") {
				t.Fatal("packaged root observation differs from independent captured facts")
			}
			for _, record := range strings.Split(strings.TrimSpace(string(load("udev.txt"))), "\n\n") {
				var properties strings.Builder
				for line := range strings.SplitSeq(record, "\n") {
					if value, ok := strings.CutPrefix(line, "E: "); ok {
						properties.WriteString(value)
						properties.WriteByte('\n')
					}
				}
				if _, status := parseUdevProperties(strings.NewReader(properties.String())); status != success {
					t.Fatalf("native block udev properties failed: %v", status)
				}
			}
		})
	}
}

func TestCapturedTransientObserverRetainsEncryptedRootTopology(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "storage", "ubuntu24-transient-lsblk.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := parseStorage(bytes.NewReader(data))
	if got.Status != success || len(got.Devices) != 6 {
		t.Fatalf("incomplete encrypted root topology: %v", got)
	}
	byName := make(map[string]*inventoryv1.BlockDevice)
	for _, device := range got.Devices {
		byName[device.Name] = device
	}
	for _, name := range []string{"vda", "vda3", "dm_crypt-0", "ubuntu--vg-ubuntu--lv"} {
		device := byName[name]
		if device == nil || device.Identity.RootBacking.Status != success || !device.Identity.RootBacking.Value {
			t.Fatalf("lost root ancestor %s: %v", name, device)
		}
	}
	container := byName["vda3"]
	if container.Identity.LuksUuid.Value != "f393f8b5-f6bf-41a0-81fd-736cf10b6d9d" || container.Identity.LuksVersion.Value != "2" {
		t.Fatal("lost observed LUKS identity")
	}
	root := byName["ubuntu--vg-ubuntu--lv"]
	if root.Mountpoint.Value != "/" || root.Parent.Value != "dm_crypt-0" || root.Encryption.Value != "inherited-dm-crypt" {
		t.Fatalf("lost LVM root encryption ancestry: %v", root)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}
