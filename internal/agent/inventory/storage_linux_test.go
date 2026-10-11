//go:build linux

package inventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/actionprovider"
)

// Synthetic util-linux/cryptsetup-format inputs, not VM/native qualification.
const syntheticStorage = `{"blockdevices":[{"name":"sda","kname":"sda","type":"disk","size":1000,"tran":"sata","model":"Synthetic disk","serial":"disk-serial","wwn":"0x5000000000000001","pttype":"gpt","ptuuid":"49865c36-1e3a-4d2b-b719-89144a6e179e","rev":"1.0","mountpoints":[null],"children":[{"name":"sda1","kname":"sda1","type":"part","size":900,"pkname":"sda","fstype":"crypto_LUKS","fsver":"2","uuid":"32cfd1cf-6a1c-4d7c-a792-664b3a0f4508","partuuid":"6f638c1f-2e3f-496e-9450-12b596d31cf0","parttype":"0fc63daf-8483-4772-8e79-3d69d8477de4","children":[{"name":"cryptroot","kname":"dm-0","type":"crypt","size":800,"pkname":"sda1","fstype":"ext4","uuid":"e9e97724-b8b0-4b3b-8d61-297b038a9758","mountpoints":["/var","/"]}]}]},{"name":"sdb","type":"disk","size":2000,"mountpoints":[null]}]}`

const syntheticLUKS2 = "LUKS header information\nVersion:       \t2\nUUID:          \t32cfd1cf-6a1c-4d7c-a792-664b3a0f4508\nData segments:\n  0: crypt\nKeyslots:\n  0: luks2\n\tSalt: synthetic-header-salt-not-for-publication\n  2: luks2\nTokens:\n  0: systemd-tpm2\n\tKeyslot: 2\n\tPayload: forbidden-token-payload\nDigests:\n  0: pbkdf2\n\tDigest: forbidden-digest\n"

const syntheticLUKS2JSON = `{"keyslots":{"0":{"type":"luks2","kdf":{"salt":"synthetic-header-salt-not-for-publication"}},"2":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["2"],"tpm2-blob":"forbidden-token-payload"}},"digests":{"0":{"type":"pbkdf2","digest":"forbidden-digest"}}}`

func TestStorageIdentityAndRootTopology(t *testing.T) {
	got := parseStorage(strings.NewReader(syntheticStorage))
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
	if got.Status != success || len(got.Devices) != 4 {
		t.Fatalf("storage: %v", got)
	}
	for _, device := range got.Devices[:3] {
		id := device.Identity
		if id.BackingDisk.Value != "sda" || id.Serial.Value != "disk-serial" || id.Wwn.Value != "0x5000000000000001" || id.GptDiskGuid.Status != success || id.GptDiskGuid.Value != "49865c36-1e3a-4d2b-b719-89144a6e179e" || !id.RootBacking.Value {
			t.Fatalf("ancestry/identity: %v", device)
		}
	}
	container, filesystem, other := got.Devices[1], got.Devices[2], got.Devices[3]
	if container.SizeBytes.Value != 900 || container.Identity.LuksVersion.Value != "2" || container.Identity.LuksUuid.Value == "" || container.Identity.FilesystemUuid.Status != unavailable || container.Identity.PartitionUuid.Value == "" {
		t.Fatalf("container identity changed: %v", container)
	}
	if filesystem.Identity.FilesystemUuid.Value == "" || filesystem.Mountpoint.Value != "/" || filesystem.Identity.LuksUuid.Status != unavailable {
		t.Fatalf("filesystem identity: %v", filesystem)
	}
	if other.Identity.RootBacking.Status != success || other.Identity.RootBacking.Value || other.Identity.Serial.Status != unavailable || other.Identity.Wwn.Status != unavailable || other.Identity.GptDiskGuid.Status != unavailable {
		t.Fatalf("invented identity/root: %v", other)
	}
}

func TestStorageGPTDiskGUIDRequiresUniqueGPTBackingDisk(t *testing.T) {
	const guid = "49865c36-1e3a-4d2b-b719-89144a6e179e"
	for _, test := range []struct {
		name, fields string
		status       inventoryv1.CollectionStatus
		value        string
	}{
		{"GPT", `"pttype":"gpt","ptuuid":"` + guid + `"`, success, guid},
		{"missing type", `"ptuuid":"` + guid + `"`, unavailable, ""},
		{"MBR", `"pttype":"dos","ptuuid":"12345678"`, unavailable, ""},
		{"missing GUID", `"pttype":"gpt"`, unavailable, ""},
		{"null GUID", `"pttype":"gpt","ptuuid":null`, unavailable, ""},
		{"invalid GUID", `"pttype":"gpt","ptuuid":"not-a-guid"`, invalid, ""},
		{"zero GUID", `"pttype":"gpt","ptuuid":"00000000-0000-0000-0000-000000000000"`, invalid, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A partition's own table UUID or PARTUUID never substitutes for the
			// physical disk GUID, even when the disk field is unavailable.
			data := `{"blockdevices":[{"name":"vda","type":"disk","size":1000,` + test.fields + `,"children":[{"name":"vda1","type":"part","size":900,"pttype":"gpt","ptuuid":"11111111-2222-4333-8444-555555555555","partuuid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}]}]}`
			got := parseStorage(strings.NewReader(data))
			if got.Status != success || len(got.Devices) != 2 {
				t.Fatalf("storage: %v", got)
			}
			for _, device := range got.Devices {
				if field := device.Identity.GptDiskGuid; field.GetStatus() != test.status || field.GetValue() != test.value {
					t.Fatalf("incorrect GPT disk identity: %v", device)
				}
			}
			if err := protovalidate.Validate(got); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, data := range []string{
		`{"blockdevices":[{"name":"vda1","type":"part","size":900,"pkname":"missing","pttype":"gpt","ptuuid":"` + guid + `"}]}`,
		`{"blockdevices":[{"name":"vda","type":"disk","size":1000,"pttype":"gpt","ptuuid":"` + guid + `","children":[{"name":"md0","type":"raid1","size":900}]},{"name":"vdb","type":"disk","size":1000,"pttype":"gpt","ptuuid":"` + guid + `","children":[{"name":"md0","type":"raid1","size":900}]}]}`,
	} {
		got := parseStorage(strings.NewReader(data))
		if got.Status != success || len(got.Devices) == 0 {
			t.Fatalf("storage: %v", got)
		}
		for _, device := range got.Devices {
			if device.Type.Value != "disk" && (device.Identity.GptDiskGuid.GetStatus() != unavailable || device.Identity.BackingDisk.GetStatus() != unavailable) {
				t.Fatalf("ambiguous or missing backing disk supplied GPT identity: %v", device)
			}
		}
	}
}

func TestStorageVirtioGPTNativeCollection(t *testing.T) {
	const guid = "49865c36-1e3a-4d2b-b719-89144a6e179e"
	const data = `{"blockdevices":[{"name":"vda","type":"disk","size":1000,"serial":"virtio-root","wwn":null,"pttype":"gpt","ptuuid":"` + guid + `","children":[{"name":"vda1","type":"part","size":900,"fstype":"crypto_LUKS","fsver":"2","uuid":"32cfd1cf-6a1c-4d7c-a792-664b3a0f4508"}]}]}`
	sources := detailSources{run: func(_ context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if selected.name != "lsblk" {
			t.Fatalf("unexpected native request: %+v", selected)
		}
		fields := "," + selected.args[len(selected.args)-1] + ","
		if !strings.Contains(fields, ",PTTYPE,") || !strings.Contains(fields, ",PTUUID,") {
			t.Fatalf("native storage observation omitted GPT identity fields: %+v", selected)
		}
		return consume(strings.NewReader(data))
	}}
	got := collectStorage(t.Context(), sources)
	if got.Status != success || len(got.Devices) != 2 {
		t.Fatalf("storage: %v", got)
	}
	for _, device := range got.Devices {
		id := device.Identity
		if id.GptDiskGuid.GetStatus() != success || id.GptDiskGuid.GetValue() != guid || id.Serial.GetValue() != "virtio-root" || id.Wwn.GetStatus() != unavailable || id.BackingDisk.GetValue() != "vda" {
			t.Fatalf("no-WWN disk identity lost or invented: %v", device)
		}
	}
	if got.Devices[0].SizeBytes.Value != 1000 || got.Devices[1].SizeBytes.Value != 900 || got.Devices[1].Identity.LuksUuid.Value != "32cfd1cf-6a1c-4d7c-a792-664b3a0f4508" {
		t.Fatalf("disk size replaced container identity: %v", got)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}

func TestStorageTopologyRefusesIncompleteOrAmbiguousAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		status     inventoryv1.CollectionStatus
	}{
		{"cycle", `{"blockdevices":[{"name":"a","type":"crypt","size":10,"pkname":"b"},{"name":"b","type":"crypt","size":10,"pkname":"a"}]}`, invalid},
		{"unsafe name", `{"blockdevices":[{"name":"../sda","type":"disk","size":10}]}`, invalid},
		{"conflicting duplicates", `{"blockdevices":[{"name":"a","type":"disk","size":10},{"name":"a","type":"disk","size":11}]}`, invalid},
		{"missing ancestor", `{"blockdevices":[{"name":"a","type":"part","size":10,"pkname":"absent","mountpoints":["/"]}]}`, success},
		{"no root mount", `{"blockdevices":[{"name":"a","type":"disk","size":10}]}`, success},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseStorage(strings.NewReader(tc.data))
			if got.Status != tc.status {
				t.Fatalf("status: %v", got)
			}
			if err := protovalidate.Validate(got); err != nil {
				t.Fatal(err)
			}
			if tc.status != success && len(got.Devices) != 0 {
				t.Fatal("partial invalid topology")
			}
			if tc.status == success && got.Devices[0].Identity.RootBacking.Status != unavailable {
				t.Fatal("unknown root represented as false")
			}
			if tc.name == "missing ancestor" && got.Devices[0].Identity.BackingDisk.Status != unavailable {
				t.Fatal("invented backing disk")
			}
		})
	}
	multi := `{"blockdevices":[{"name":"sda","type":"disk","size":20,"serial":"a","children":[{"name":"md0","type":"raid1","size":10,"mountpoints":["/"]}]},{"name":"sdb","type":"disk","size":20,"serial":"b","children":[{"name":"md0","type":"raid1","size":10,"mountpoints":["/"]}]}]}`
	got := parseStorage(strings.NewReader(multi))
	if got.Status != success || len(got.Devices) != 3 {
		t.Fatalf("multi-parent tree: %v", got)
	}
	for _, device := range got.Devices {
		if !device.Identity.RootBacking.Value {
			t.Fatalf("missed root ancestor: %v", device)
		}
	}
	if got.Devices[1].Identity.BackingDisk.Status != unavailable || got.Devices[1].Identity.Serial.Status != unavailable || got.Devices[1].Parent.Status != unavailable {
		t.Fatal("ambiguous disk became exact authority")
	}
}

func TestStorageCountsAndPerFieldBounds(t *testing.T) {
	var rows []string
	for i := range 257 {
		rows = append(rows, fmt.Sprintf(`{"name":"disk%d","type":"disk","size":1}`, i))
	}
	got := parseStorage(strings.NewReader(`{"blockdevices":[` + strings.Join(rows, ",") + `]}`))
	if got.Status != capacity || len(got.Devices) != 0 {
		t.Fatalf("device capacity: %v", got)
	}
	got = parseStorage(strings.NewReader(`{"blockdevices":[{"name":"sda","type":"disk","size":1,"serial":"` + strings.Repeat("x", 4097) + `","wwn":"native"}]}`))
	if got.Status != success || got.Devices[0].Identity.Serial.Status != invalid || got.Devices[0].Identity.Wwn.Value != "native" {
		t.Fatalf("independent field bound: %v", got)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}

func TestLUKSSummaryPublicProjectionAndMalformed(t *testing.T) {
	got, status := parseLUKSSummary(strings.NewReader(syntheticLUKS2))
	if status != success || got.version != "2" || got.keyslots != 2 || got.tokens != 1 || strings.Join(got.types, ",") != "systemd-tpm2" {
		t.Fatalf("LUKS2 summary: %+v %v", got, status)
	}
	luks1 := "LUKS header information\nVersion:       \t1\nUUID:          \t32cfd1cf-6a1c-4d7c-a792-664b3a0f4508\n"
	for i := range 8 {
		state := "DISABLED"
		if i == 0 {
			state = "ENABLED"
		}
		luks1 += fmt.Sprintf("Key Slot %d: %s\n", i, state)
	}
	got, status = parseLUKSSummary(strings.NewReader(luks1))
	if status != success || got.version != "1" || got.keyslots != 1 {
		t.Fatalf("LUKS1: %+v %v", got, status)
	}
	for _, data := range []string{"", "Version: 2\n", strings.Replace(syntheticLUKS2, "  2: luks2", "  0: luks2", 1), strings.Replace(syntheticLUKS2, "  0: systemd-tpm2", "  32: systemd-tpm2", 1), strings.Replace(syntheticLUKS2, "Tokens:\n", "", 1), strings.Replace(luks1, "Key Slot 7: DISABLED\n", "", 1), syntheticLUKS2 + "\x00\n"} {
		if summary, status := parseLUKSSummary(strings.NewReader(data)); status != invalid || summary != nil {
			t.Fatalf("malformed accepted: %+v %v", summary, status)
		}
	}
	if summary, status := parseLUKSSummary(strings.NewReader(strings.Replace(syntheticLUKS2, "\t2\n", "\t3\n", 1))); status != unavailable || summary != nil {
		t.Fatalf("unsupported version: %+v %v", summary, status)
	}
}

func TestStoragePermissionFailuresStayPerField(t *testing.T) {
	permission := inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
	s := detailSources{
		readFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "/device/firmware_rev") {
				return nil, fs.ErrPermission
			}
			return nil, fs.ErrNotExist
		},
		openBlock: func(string) (*os.File, error) { return nil, fs.ErrPermission },
		run: func(_ context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
			if selected.name == "lsblk" {
				return consume(strings.NewReader(strings.Replace(syntheticStorage, `"rev":"1.0",`, "", 1)))
			}
			if selected.name == "udevadm" {
				return unavailable
			}
			t.Fatalf("permission failure unexpectedly started %s", selected.name)
			return invalid
		},
	}
	got := collectStorage(t.Context(), s)
	if got.Status != success {
		t.Fatalf("field failure discarded topology: %v", got)
	}
	if got.Devices[0].Identity.Firmware.Status != permission || got.Devices[0].Identity.Serial.Value != "disk-serial" {
		t.Fatalf("firmware status/serial: %v", got.Devices[0])
	}
	id := got.Devices[1].Identity
	if id.LuksKeyslotCount.Status != permission || id.LuksTokenCount.Status != permission || id.LuksTokenTypes.Status != permission || id.LuksUuid.Status != success || id.LuksVersion.Value != "2" {
		t.Fatalf("LUKS permission conflation: %v", id)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}

func TestLUKSCollectionNeverPublishesSensitiveSummaryLines(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "synthetic-source")
	if err := os.WriteFile(filePath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	id := parseStorage(strings.NewReader(syntheticStorage)).Devices[1].Identity
	s := detailSources{
		openBlock: func(string) (*os.File, error) { return os.Open(filePath) },
		run: func(_ context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
			if selected.name != "cryptsetup" || selected.args[0] != "luksDump" || !strings.HasPrefix(selected.args[len(selected.args)-1], "/proc/") {
				t.Fatalf("unsafe native request: %+v", selected)
			}
			switch {
			case len(selected.args) == 2:
				return consume(strings.NewReader(syntheticLUKS2))
			case len(selected.args) == 3 && selected.args[1] == "--dump-json-metadata":
				return consume(strings.NewReader(syntheticLUKS2JSON))
			default:
				t.Fatalf("unsafe native request: %+v", selected)
				return invalid
			}
		},
	}
	collectLUKS(t.Context(), s, "sda1", id)
	if id.LuksKeyslotCount.Value != 2 || id.LuksTokenCount.Value != 1 || id.LuksTokenTypes.Value != "systemd-tpm2" {
		t.Fatalf("summary missing: %v", id)
	}
	data, err := protojson.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"forbidden", "synthetic-header-salt", "Payload", "Digest", "Salt"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("sensitive metadata published: %s", data)
		}
	}
	if err := protovalidate.Validate(id); err != nil {
		t.Fatal(err)
	}
	s.run = func(context.Context, backend, func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		return commandFailure
	}
	collectLUKS(t.Context(), s, "sda1", id)
	if id.LuksTokenCount.Status != commandFailure || id.LuksTokenCount.Value != 0 || id.LuksTokenTypes.Value != "" {
		t.Fatalf("partial command metadata retained: %v", id)
	}
}

func TestNVMeScopeUsesExactReadOnlyTargetSeam(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-descriptor")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	device := parseStorage(strings.NewReader(`{"blockdevices":[{"name":"nvme0n1","type":"disk","size":4096,"tran":"nvme","serial":"native-serial","wwn":"native-wwn"}]}`)).Devices[0]
	called := false
	s := detailSources{
		openBlock: func(name string) (*os.File, error) {
			if name != "/dev/nvme0n1" {
				t.Fatalf("wrong block: %s", name)
			}
			return os.Open(path)
		},
		nvmeScope: func(_ context.Context, file *os.File, target *agentv1.StorageTarget) (*agentv1.NVMeSanitizeScope, error) {
			called = true
			if file == nil || target.GetIdentityBasis() != agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL || target.Serial != "native-serial" || target.Wwn != "native-wwn" || target.SizeBytes != 4096 || target.LuksUuid != "" || target.GetGptDiskGuid() != "" || target.GetDiskSizeBytes() != 0 {
				t.Fatalf("identity fork: %v", target)
			}
			return nil, fs.ErrPermission
		},
	}
	got := collectNVMeScope(t.Context(), s, "nvme0n1", device)
	if !called || got.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED || got.Scope != nil {
		t.Fatalf("scope failure: %v", got)
	}
	scope := &agentv1.NVMeSanitizeScope{
		NamespaceId: 1,
		Identity: &agentv1.NVMeSanitizeIdentity{
			Basis:    agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_NAMESPACE_NID,
			VendorId: 0x1b36, SubsystemVendorId: 0x1234,
			ControllerSerial: "native-serial", ControllerModel: "Synthetic NVMe",
			ControllerFirmware: "1.0", NamespaceSizeBytes: 4096, LbaDataSizeShift: 9,
		},
	}
	s.nvmeScope = func(context.Context, *os.File, *agentv1.StorageTarget) (*agentv1.NVMeSanitizeScope, error) {
		return scope, nil
	}
	got = collectNVMeScope(t.Context(), s, "nvme0n1", device)
	if got.Status != success || got.Scope != scope {
		t.Fatalf("exact native scope not retained: %v", got)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
	s.nvmeScope = func(context.Context, *os.File, *agentv1.StorageTarget) (*agentv1.NVMeSanitizeScope, error) {
		return &agentv1.NVMeSanitizeScope{ControllerWide: true}, nil
	}
	if got := collectNVMeScope(t.Context(), s, "nvme0n1", device); got.Status != invalid || got.Scope != nil {
		t.Fatalf("controller-wide authority: %v", got)
	}
	// An NVMe namespace whose sysfs identity is absent is an explicit invalid
	// observation with its fixed reason, never a namespace without scope.
	s.nvmeScope = func(context.Context, *os.File, *agentv1.StorageTarget) (*agentv1.NVMeSanitizeScope, error) {
		return nil, &actionprovider.NVMeScopeRefusal{Reason: "nvme_sysfs_wwid_absent"}
	}
	got = collectNVMeScope(t.Context(), s, "nvme0n1", device)
	if got.Status != invalid || got.Scope != nil || got.Reason != "nvme_sysfs_wwid_absent" {
		t.Fatalf("sysfs refusal: %v", got)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
	got.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	if err := protovalidate.Validate(got); err == nil {
		t.Fatal("refusal reason accepted on a non-invalid observation")
	}
	for _, candidate := range []string{path, "/dev/null"} {
		file, err := openStorageBlock(candidate)
		if file != nil {
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			t.Fatal("nonblock descriptor accepted")
		}
		if !errors.Is(err, errInvalid) {
			t.Fatalf("nonblock error: %v", err)
		}
	}
	link := filepath.Join(t.TempDir(), "device-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openStorageBlock(link); err == nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("symlink accepted")
	}
}

func TestStorageNativeFallbackAndAbsentSignature(t *testing.T) {
	for _, tc := range []struct{ field, want string }{{`,"fstype":null`, "none"}, {"", ""}} {
		input := `{"blockdevices":[{"name":"vda","type":"disk","size":100` + tc.field + `,"children":[{"name":"vda1","type":"part","size":90,"fstype":"ext4","mountpoints":["/"]}]}]}`
		s := detailSources{
			readFile: func(path string) ([]byte, error) {
				switch {
				case strings.HasSuffix(path, "/device/uevent"):
					return []byte("DRIVER=virtio_blk\nMODALIAS=virtio:d00000002v00001AF4\n"), nil
				case strings.HasSuffix(path, "/device/rev"):
					return []byte("native-revision\n"), nil
				case strings.HasSuffix(path, "/eui"):
					return []byte("1200000000000034\n"), nil
				default:
					return nil, fs.ErrNotExist
				}
			},
			run: func(_ context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
				if selected.name != "lsblk" {
					t.Fatalf("unexpected tool: %+v", selected)
				}
				return consume(strings.NewReader(input))
			},
		}
		got := collectStorage(t.Context(), s)
		if got.Status != success || got.Devices[0].Encryption.Value != tc.want {
			t.Fatalf("signature availability: %v", got)
		}
		for _, device := range got.Devices {
			id := device.Identity
			if id.Transport.Value != "virtio" || id.Firmware.Value != "native-revision" || id.Eui.Value != "1200000000000034" || id.Serial.Status != unavailable || id.Wwn.Status != unavailable {
				t.Fatalf("fallback/inheritance invented identifiers: %v", device)
			}
		}
		if err := protovalidate.Validate(got); err != nil {
			t.Fatal(err)
		}
	}
}
