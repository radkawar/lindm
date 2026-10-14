// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Synthetic kernel/native metadata fixtures; not native encryption qualification.
type graphEntry string

func (e graphEntry) Name() string               { return string(e) }
func (e graphEntry) IsDir() bool                { return false }
func (e graphEntry) Type() fs.FileMode          { return fs.ModeSymlink }
func (e graphEntry) Info() (fs.FileInfo, error) { return nil, errors.New("unused synthetic entry") }
func graphFixture(ids map[string]string, edges map[string][]string) (func(string) ([]byte, error), func(string) ([]os.DirEntry, error)) {
	read := func(path string) ([]byte, error) {
		suffix := strings.TrimPrefix(path, "/sys/dev/block/")
		device, tail, _ := strings.Cut(suffix, "/")
		if tail == "dm/uuid" {
			if id, ok := ids[device]; ok {
				return []byte(id), nil
			}
			return nil, os.ErrNotExist
		}
		if strings.HasPrefix(tail, "slaves/") && strings.HasSuffix(tail, "/dev") {
			child := strings.TrimSuffix(strings.TrimPrefix(tail, "slaves/"), "/dev")
			for _, edge := range edges[device] {
				if edge == child {
					return []byte(edge), nil
				}
			}
		}
		return nil, os.ErrNotExist
	}
	children := func(path string) ([]os.DirEntry, error) {
		device := strings.TrimSuffix(strings.TrimPrefix(path, "/sys/dev/block/"), "/slaves")
		var result []os.DirEntry
		for _, edge := range edges[device] {
			result = append(result, graphEntry(edge))
		}
		return result, nil
	}
	return read, children
}

const complianceUUID = "32cfd1cf-6a1c-4d7c-a792-664b3a0f4508"
const complianceDM = "CRYPT-LUKS2-32cfd1cf6a1c4d7ca792664b3a0f4508-root"

func TestComplianceFollowsActualRootThroughLVM(t *testing.T) {
	read, children := graphFixture(map[string]string{"253:0": "LVM-synthetic", "253:1": complianceDM, "253:2": "CRYPT-LUKS2-42cfd1cf6a1c4d7ca792664b3a0f4508-extra"}, map[string][]string{"253:0": {"253:1"}, "253:1": {"8:2"}, "253:2": {"8:3"}})
	graph, err := rootEncryptionGraph("253:0", read, children)
	if err != nil || graph.cryptUUID != complianceUUID || graph.backing != "8:2" || graph.protected != 1 {
		t.Fatalf("root graph=%+v err=%v", graph, err)
	}
	// An unrelated encrypted disk cannot make an ordinary root encrypted.
	graph, err = rootEncryptionGraph("8:1", read, children)
	if err != nil || graph.cryptUUID != "" || graph.protected != 0 {
		t.Fatalf("unrelated encryption selected: %+v %v", graph, err)
	}
}
func TestComplianceRefusesMixedAmbiguousAndUnsupportedGraphs(t *testing.T) {
	for name, tc := range map[string]struct {
		ids   map[string]string
		edges map[string][]string
		root  string
	}{
		"mixed root":         {map[string]string{"253:0": "LVM-root", "253:1": complianceDM}, map[string][]string{"253:0": {"253:1", "8:1"}, "253:1": {"8:2"}}, "253:0"},
		"cycle":              {nil, map[string][]string{"253:0": {"253:1"}, "253:1": {"253:0"}}, "253:0"},
		"luks1":              {map[string]string{"253:0": "CRYPT-LUKS1-32cfd1cf6a1c4d7ca792664b3a0f4508-root"}, map[string][]string{"253:0": {"8:1"}}, "253:0"},
		"two encrypted legs": {map[string]string{"253:0": "LVM-root", "253:1": complianceDM, "253:2": complianceDM}, map[string][]string{"253:0": {"253:1", "253:2"}, "253:1": {"8:1"}, "253:2": {"8:2"}}, "253:0"},
		"nonblock root":      {nil, nil, "0:42"},
	} {
		t.Run(name, func(t *testing.T) {
			read, children := graphFixture(tc.ids, tc.edges)
			if _, err := rootEncryptionGraph(tc.root, read, children); err == nil {
				t.Fatal("unsupported graph accepted")
			}
		})
	}
}
func TestComplianceSelectsExactDurableRootNotFirstLUKS(t *testing.T) {
	nodes := []blockNode{{Path: "/dev/sda", Type: "disk", Device: "8:0", WWN: "root-wwn", Serial: "root-serial", Children: []blockNode{
		{Path: "/dev/sda1", Type: "part", Device: "8:1", Size: 10, UUID: "42cfd1cf-6a1c-4d7c-a792-664b3a0f4508", Filesystem: "crypto_LUKS"},
		{Path: "/dev/sda2", Type: "part", Device: "8:2", Size: 20, UUID: complianceUUID, Filesystem: "crypto_LUKS"},
	}}}
	native := func(string) sysfsBlockIdentity { return sysfsBlockIdentity{} }
	g := &complianceGraph{cryptUUID: complianceUUID, backing: "8:2"}
	target, err := complianceTarget(nodes, g, native)
	if err != nil || target.GetLuksUuid() != complianceUUID || target.GetSizeBytes() != 20 || target.GetSerial() != "root-serial" {
		t.Fatalf("target=%v err=%v", target, err)
	}
	nodes[0].Children[1].UUID = "42cfd1cf-6a1c-4d7c-a792-664b3a0f4508"
	if _, err := complianceTarget(nodes, g, native); err == nil {
		t.Fatal("mapping/header UUID mismatch accepted")
	}
}
func TestComplianceRejectsStaleTokenAndEmptyPCRPolicy(t *testing.T) {
	// Existing native metadata parser rejects a token referring to a removed slot.
	if _, err := parseMetadata([]byte(`{"keyslots":{"0":{}},"tokens":{"1":{"type":"systemd-tpm2","keyslots":["2"],"tpm2-pcrs":[7]}},"segments":{"0":{"type":"crypt","offset":"16777216"}}}`)); err == nil {
		t.Fatal("stale token accepted")
	}
	good := luksToken{Type: "systemd-tpm2", Keyslots: []string{"2"}, PCRs: []uint32{7, 11}}
	if !complianceTPMToken(good) {
		t.Fatal("valid token candidate rejected")
	}
	for _, token := range []luksToken{
		{Type: "systemd-tpm2", Keyslots: []string{"2"}},
		{Type: "systemd-tpm2", Keyslots: []string{"2"}, PCRs: []uint32{24}},
		{Type: "systemd-tpm2", Keyslots: []string{"2"}, PCRs: []uint32{7, 7}},
		{Type: "systemd-tpm2", Keyslots: []string{"2", "3"}, PCRs: []uint32{7}},
		{Type: "other-token", Keyslots: []string{"2"}, PCRs: []uint32{7}},
	} {
		if complianceTPMToken(token) {
			t.Fatalf("unsafe TPM candidate accepted: %+v", token)
		}
	}
}

func TestComplianceTPMRequiresNativeUnlockNotTokenPresence(t *testing.T) {
	token := luksToken{Type: "systemd-tpm2", Keyslots: []string{"2"}, PCRs: []uint32{7}}
	calls := 0
	nativeErr := errors.New("native PCR policy or TPM mismatch")
	p := &Provider{run: func(_ context.Context, request nativeRequest) ([]byte, error) {
		calls++
		want := []string{"open", "--type", "luks2", "--test-passphrase", "--token-only", "--token-id", "1", "--key-slot", "2", descriptor(0)}
		if request.command != cryptsetup || !slices.Equal(request.args, want) || len(request.files) != 1 || len(request.input) != 0 {
			t.Fatal("TPM probe changed native mapping or requested secret output")
		}
		return nil, nativeErr
	}}
	if p.testComplianceTPMToken(t.Context(), nil, "1", token) || calls != 1 {
		t.Fatal("stale native TPM token became compliant")
	}
	nativeErr = nil
	if !p.testComplianceTPMToken(t.Context(), nil, "1", token) || calls != 2 {
		t.Fatal("successful exact native probe rejected")
	}
	token.PCRs = nil
	if p.testComplianceTPMToken(t.Context(), nil, "1", token) || calls != 2 {
		t.Fatal("empty PCR policy reached native probe")
	}
}

func TestComplianceRequiresCompleteCryptMappingNotUUIDLabel(t *testing.T) {
	good := "0 4096 crypt aes-xts-plain64 00000000 0 8:2 32768\n"
	if !complianceCryptTableMatches([]byte(good), "8:2", 4096) {
		t.Fatal("complete crypt mapping rejected")
	}
	for _, table := range []string{
		"0 4096 linear 8:2 32768\n",
		"0 2048 crypt aes-xts-plain64 00000000 0 8:2 32768\n2048 2048 linear 8:2 34816\n",
		strings.Replace(good, "aes-xts-plain64", "cipher_null-ecb", 1),
		strings.Replace(good, "4096", "2048", 1),
		strings.Replace(good, "8:2", "8:3", 1),
		strings.Replace(good, "0 4096", "1 4096", 1),
	} {
		if complianceCryptTableMatches([]byte(table), "8:2", 4096) {
			t.Fatal("plaintext, partial or wrong backing mapping accepted")
		}
	}
}

func TestComplianceHelperDeviceScopeUsesOnlyExactKernelRootFacts(t *testing.T) {
	graph := &complianceGraph{cryptUUID: complianceUUID, backing: "8:2"}
	reads := 0
	read := func(path string) ([]byte, error) {
		reads++
		switch path {
		case "/sys/dev/block/8:2/uevent":
			return []byte("MAJOR=8\nMINOR=2\nDEVNAME=sda2\nDEVTYPE=partition\n"), nil
		case "/sys/class/tpmrm/tpmrm0/uevent":
			return []byte("MAJOR=253\nMINOR=65536\nDEVNAME=tpmrm0\n"), nil
		default:
			t.Fatalf("scope discovery read outside fixed sysfs facts: %s", path)
			return nil, ErrUnsupported
		}
	}
	devices, err := complianceReadDevices(graph, read)
	if err != nil || !slices.Equal(devices, []string{"/dev/sda2", "/dev/mapper/control", "/dev/tpmrm0"}) {
		t.Fatalf("device scope: %v %v", devices, err)
	}
	before := reads
	devices, err = complianceReadDevices(&complianceGraph{}, read)
	if err != nil || len(devices) != 0 || reads != before {
		t.Fatal("unencrypted root acquired native device access")
	}
	devices, err = complianceReadDevices(graph, func(path string) ([]byte, error) {
		if path == "/sys/class/tpmrm/tpmrm0/uevent" {
			return nil, os.ErrNotExist
		}
		return read(path)
	})
	if err != nil || !slices.Equal(devices, []string{"/dev/sda2", "/dev/mapper/control"}) {
		t.Fatal("missing TPM widened helper device access")
	}
}

func TestComplianceHelperDeviceScopeRejectsAmbiguousOrRedirectedNames(t *testing.T) {
	for _, event := range []string{
		"MAJOR=8\nMINOR=3\nDEVNAME=sda2\n",
		"MAJOR=8\nMINOR=2\nDEVNAME=../sda2\n",
		"MAJOR=8\nMINOR=2\nDEVNAME=sda2\nDEVNAME=sda3\n",
		"MAJOR=8\nMINOR=2\nDEVNAME=*\n",
		"MAJOR=8\nMINOR=2\nDEVNAME=..\n",
		"MAJOR=08\nMINOR=2\nDEVNAME=sda2\n",
	} {
		_, err := complianceReadDevices(&complianceGraph{cryptUUID: complianceUUID, backing: "8:2"}, func(string) ([]byte, error) { return []byte(event), nil })
		if err == nil {
			t.Fatal("ambiguous or redirected device scope accepted")
		}
	}
}

func TestComplianceSelectsExistingSerialGPTLUKSBasis(t *testing.T) {
	nodes := []blockNode{{Path: "/dev/vda", Type: "disk", Device: "252:0", Size: 8192, PartitionTable: "gpt", DiskGUID: "11111111-1111-4111-8111-111111111111", Children: []blockNode{{Path: "/dev/vda3", Type: "part", Device: "252:3", Size: 4096, UUID: complianceUUID, Filesystem: "crypto_LUKS"}}}}
	native := func(string) sysfsBlockIdentity {
		return sysfsBlockIdentity{WWID: sysfsIdentityValue{Error: "absent"}, DeviceWWID: sysfsIdentityValue{Error: "absent"}, BlockSerial: sysfsIdentityValue{Value: "synthetic-virtio-serial"}}
	}
	graph := &complianceGraph{cryptUUID: complianceUUID, backing: "252:3"}
	target, err := complianceTarget(nodes, graph, native)
	if err != nil || target.GetIdentityBasis() != agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS || target.GetWwn() != "" || target.GetGptDiskGuid() != nodes[0].DiskGUID || target.GetDiskSizeBytes() != 8192 || target.GetSerial() != "synthetic-virtio-serial" {
		t.Fatalf("existing no-WWN native tuple lost: %v %v", target, err)
	}
	// The same serial on a second physical disk is ambiguous even when that
	// disk has a different size/GUID and is not in the root dependency graph.
	nodes = append(nodes, blockNode{Path: "/dev/vdb", Type: "disk", Device: "252:16", Size: 16384, PartitionTable: "gpt", DiskGUID: complianceUUID})
	if _, err := complianceTarget(nodes, graph, native); err == nil {
		t.Fatal("duplicate physical serial accepted")
	}
	nodes = nodes[:1]
	if _, err := complianceTarget(nodes, graph, func(string) sysfsBlockIdentity {
		return sysfsBlockIdentity{WWID: sysfsIdentityValue{Error: "unavailable"}}
	}); err == nil {
		t.Fatal("WWN read failure treated as proven absence")
	}
	nodes[0].PartitionTable = "dos"
	if _, err := complianceTarget(nodes, graph, native); err == nil {
		t.Fatal("non-GPT disk selected fallback basis")
	}
}

func TestComplianceHelperAdmitsOnlyExactGPTParentDisk(t *testing.T) {
	read := func(path string) ([]byte, error) {
		switch path {
		case "/sys/dev/block/252:3/partition":
			return []byte("3\n"), nil
		case "/sys/devices/pci/block/vda/dev":
			return []byte("252:0\n"), nil
		case "/sys/dev/block/252:0/partition":
			return nil, os.ErrNotExist
		case "/sys/dev/block/252:3/uevent":
			return []byte("MAJOR=252\nMINOR=3\nDEVNAME=vda3\n"), nil
		case "/sys/dev/block/252:0/uevent":
			return []byte("MAJOR=252\nMINOR=0\nDEVNAME=vda\n"), nil
		case "/sys/class/tpmrm/tpmrm0/uevent":
			return nil, os.ErrNotExist
		default:
			t.Fatalf("unexpected discovery read %s", path)
			return nil, ErrUnsupported
		}
	}
	parent, err := complianceParentDisk("252:3", read, func(path string) (string, error) {
		if path != "/sys/dev/block/252:3" {
			t.Fatal("wrong ancestry lookup")
		}
		return "/sys/devices/pci/block/vda/vda3", nil
	})
	if err != nil || parent != "252:0" {
		t.Fatalf("parent discovery: %q %v", parent, err)
	}
	devices, err := complianceReadDevices(&complianceGraph{cryptUUID: complianceUUID, backing: "252:3", backingDisk: parent}, read)
	if err != nil || !slices.Equal(devices, []string{"/dev/vda3", "/dev/mapper/control", "/dev/vda"}) {
		t.Fatalf("GPT parent confinement: %v %v", devices, err)
	}
	if _, err := complianceParentDisk("252:3", read, func(string) (string, error) { return "/dev/vda3", nil }); err == nil {
		t.Fatal("sysfs ancestry redirected to /dev")
	}
}
