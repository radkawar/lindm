//go:build linux

package vmlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const storageInspectTestUUID = "12345678-1234-1234-1234-123456789abc"

func TestStorageCaptureLUKSProjectionDropsEveryPayload(t *testing.T) {
	input := []byte(`{"keyslots":{"0":{"type":"luks2","key_size":64,"kdf":{"salt":"PRIVATE-SALT"},"area":{"offset":"PRIVATE-AREA"}}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["0"],"tpm2-blob":"PRIVATE-BLOB","future":{"key":"PRIVATE-KEY"}}},"segments":{},"digests":{"0":{"digest":"PRIVATE-DIGEST"}},"config":{}}`)
	got, err := projectStorageLUKS(input)
	if err != nil {
		t.Fatal(err)
	}
	var expected, actual any
	if err := json.Unmarshal([]byte(`{"keyslots":{"0":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["0"]}}}`), &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatal(err)
	}
	a, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || strings.Contains(string(got), "PRIVATE") {
		t.Fatalf("unsafe projection: %s", got)
	}
	for name, bad := range map[string]string{
		"duplicate object":  `{"keyslots":{},"keyslots":{},"tokens":{},"segments":{},"digests":{},"config":{}}`,
		"invalid slot":      `{"keyslots":{"32":{"type":"luks2"}},"tokens":{},"segments":{},"digests":{},"config":{}}`,
		"missing reference": `{"keyslots":{},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["0"]}},"segments":{},"digests":{},"config":{}}`,
		"type payload":      `{"keyslots":{},"tokens":{"0":{"type":"type\nPRIVATE","keyslots":[]}},"segments":{},"digests":{},"config":{}}`,
		"missing metadata":  `{"keyslots":{}}`,
		"trailing data":     string(input) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := projectStorageLUKS([]byte(bad)); err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}

func TestStorageCaptureLUKSTextProjection(t *testing.T) {
	input := "LUKS header information\nVersion:       2\nUUID:          " + storageInspectTestUUID + "\nKeyslots:\n  0: luks2\n\tSalt: PRIVATE-SALT\n\tKey: PRIVATE-KEY\nTokens:\n  0: systemd-tpm2\n\ttpm2-blob: PRIVATE-BLOB\nDigests:\n  0: pbkdf2\n\tDigest: PRIVATE-DIGEST\n"
	got, err := projectStorageLUKSText([]byte(input), storageInspectTestUUID)
	if err != nil {
		t.Fatal(err)
	}
	want := "Version:       2\nUUID:          " + storageInspectTestUUID + "\nKeyslots:\n  0: luks2\nTokens:\n  0: systemd-tpm2\n"
	if string(got) != want {
		t.Fatalf("unexpected public text: %q", got)
	}
	if _, err := projectStorageLUKSText([]byte(strings.ReplaceAll(input, storageInspectTestUUID, "00000000-0000-0000-0000-000000000000")), storageInspectTestUUID); err == nil {
		t.Fatal("mismatched UUID accepted")
	}
}

func TestStorageCaptureUdevProjection(t *testing.T) {
	input := "P: /devices/virtual/net/eth0\nE: SUBSYSTEM=net\nE: PRIVATE=NETWORK-SECRET\n\nP: /devices/pci/block/sda\nN: sda\nE: SUBSYSTEM=block\nE: DEVNAME=/dev/sda\nE: ID_BUS=scsi\nE: ID_REVISION=2.0\nE: ID_SERIAL_SHORT=lindm-lab-0\nE: UNKNOWN_TOKEN=PRIVATE-BLOB\n\n"
	got, err := projectStorageUdev([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want := "P: /devices/pci/block/sda\nN: sda\nE: SUBSYSTEM=block\nE: DEVNAME=/dev/sda\nE: ID_BUS=scsi\nE: ID_REVISION=2.0\nE: ID_SERIAL_SHORT=lindm-lab-0\n\n"
	if string(got) != want {
		t.Fatalf("unexpected public block records: %q", got)
	}
	if _, err := projectStorageUdev([]byte("E: SUBSYSTEM=net\n")); err == nil {
		t.Fatal("empty block capture accepted")
	}
}

func storageInspectTestObservation() (*inventoryv1.StorageDetails, *inventoryv1.StorageDetails) {
	disk := &inventoryv1.BlockDevice{Name: "sda", Type: truthString("disk"), SizeBytes: truthUint(24 << 30), Parent: truthString(""), Identity: &inventoryv1.StorageIdentity{Serial: truthString("lindm-lab-0"), Wwn: truthString("0x5000000000000001"), RootBacking: truthBool(true), BackingDisk: truthString("sda")}}
	partition := &inventoryv1.BlockDevice{Name: "sda3", Type: truthString("part"), SizeBytes: truthUint(23 << 30), Parent: truthString("sda"), Identity: &inventoryv1.StorageIdentity{LuksUuid: truthString(storageInspectTestUUID), LuksVersion: truthString("2"), Serial: truthString("lindm-lab-0"), Wwn: truthString("0x5000000000000001"), RootBacking: truthBool(true), BackingDisk: truthString("sda"), LuksKeyslotCount: truthUint(1), LuksTokenCount: truthUint(0), LuksTokenTypes: truthString("")}}
	root := &inventoryv1.BlockDevice{Name: "cryptroot", Type: truthString("crypt"), SizeBytes: truthUint((23 << 30) - (16 << 20)), Parent: truthString("sda3"), Mountpoint: truthString("/")}
	actual := &inventoryv1.StorageDetails{Status: truthSuccess, Devices: []*inventoryv1.BlockDevice{disk, partition, root}}
	return proto.CloneOf(actual), actual
}

func TestStorageCaptureRejectsIndependentIdentityMismatches(t *testing.T) {
	truth, actual := storageInspectTestObservation()
	if name, err := compareEncryptedStorage(truth, actual, storageInspectTestUUID); err != nil || name != "sda3" {
		t.Fatalf("matching root rejected: %s %v", name, err)
	}
	if err := compareStorageController(actual, "virtio-scsi", "sda3"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*inventoryv1.StorageDetails){
		"size": func(s *inventoryv1.StorageDetails) { s.Devices[1].SizeBytes.Value++ },
		"uuid": func(s *inventoryv1.StorageDetails) {
			s.Devices[1].Identity.LuksUuid.Value = "00000000-0000-0000-0000-000000000000"
		},
		"serial":    func(s *inventoryv1.StorageDetails) { s.Devices[0].Identity.Serial.Value = "wrong" },
		"wwn":       func(s *inventoryv1.StorageDetails) { s.Devices[0].Identity.Wwn.Value = "wrong" },
		"root":      func(s *inventoryv1.StorageDetails) { s.Devices[1].Identity.RootBacking.Value = false },
		"denied":    func(s *inventoryv1.StorageDetails) { s.Devices[1].Identity.LuksUuid.Status = truthDenied },
		"duplicate": func(s *inventoryv1.StorageDetails) { s.Devices = append(s.Devices, s.Devices[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(actual)
			mutate(changed)
			if _, err := compareEncryptedStorage(truth, changed, storageInspectTestUUID); err == nil {
				t.Fatal("independent identity mismatch accepted")
			}
		})
	}
	// Native and agent can agree on the wrong controller; the host-owned
	// configuration comparison must still reject that jointly wrong identity.
	actual.Devices[0].Identity.Serial.Value = "wrong"
	actual.Devices[1].Identity.Serial.Value = "wrong"
	if err := compareStorageController(actual, "virtio-scsi", "sda3"); err == nil {
		t.Fatal("jointly wrong guest controller identity accepted")
	}
}

func TestStorageCaptureRejectsPublicSummaryMismatch(t *testing.T) {
	_, actual := storageInspectTestObservation()
	public := []byte(`{"keyslots":{"0":{"type":"luks2"}},"tokens":{}}`)
	if err := compareStoragePublicSummary(actual, storageInspectTestUUID, public); err != nil {
		t.Fatal(err)
	}
	actual.Devices[1].Identity.LuksKeyslotCount.Value = 2
	if err := compareStoragePublicSummary(actual, storageInspectTestUUID, public); err == nil {
		t.Fatal("keyslot mismatch accepted")
	}
}

func TestStorageCaptureCreateOnlyPrivatePublication(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "capture")
	files := map[string][]byte{"lsblk.json": []byte(`{"blockdevices":[]}`), "provenance.json": []byte(`{"guest_cleaned":true}`)}
	if err := publishStorageCapture(path, files); err != nil {
		t.Fatal(err)
	}
	for name := range files {
		info, err := os.Stat(filepath.Join(path, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("nonprivate capture: %v %v", info, err)
		}
	}
	if err := publishStorageCapture(path, map[string][]byte{"lsblk.json": []byte("overwrite")}); err == nil {
		t.Fatal("existing capture overwritten")
	}
	data, err := os.ReadFile(filepath.Join(path, "lsblk.json"))
	if err != nil || string(data) != string(files["lsblk.json"]) {
		t.Fatalf("original capture changed: %q %v", data, err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	if err := validateStorageCaptureDestination(filepath.Join(link, "new")); err == nil {
		t.Fatal("symlink output parent accepted")
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateStorageCaptureDestination(filepath.Join(parent, "new")); err == nil {
		t.Fatal("nonprivate parent accepted")
	}
}
