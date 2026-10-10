//go:build linux

package actionprovider

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestOpenTargetExplicitlyRequestsBlockTree(t *testing.T) {
	target := &agentv1.StorageTarget{LuksUuid: fixtureLUKS, Wwn: "root-wwn", Serial: "root-serial", SizeBytes: 64 << 20}
	stopped := errors.New("stop before opening any device")
	observed := false
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{Target: target}}}}
	p.run = func(_ context.Context, request nativeRequest) ([]byte, error) {
		observed = true
		if request.command != lsblk || !slices.Contains(request.args, "--tree") {
			t.Fatal("identity inheritance requires explicit lsblk tree when NAME is absent")
		}
		return nil, stopped
	}
	_, err := p.openTarget(t.Context(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: target}}}, false)
	if !observed || !errors.Is(err, stopped) {
		t.Fatalf("native topology collection not reached: %v", err)
	}
}

func TestOpenTargetIdentityRefusalRetainsApprovedAndObservedTuples(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "no matches", true: "duplicate matches"}[duplicate], func(t *testing.T) {
			target := &agentv1.StorageTarget{Wwn: "approved-wwn", Serial: "approved-serial", SizeBytes: 4096}
			nodes := []blockNode{{Path: "/dev/sda", Type: "disk", Size: 4096, Device: "4294967295:0"}, {Path: "/dev/sdb", Type: "disk", Size: 4096, Device: "4294967295:16"}}
			if duplicate {
				for i := range nodes {
					nodes[i].WWN, nodes[i].Serial = target.Wwn, target.Serial
				}
			}
			diagnostic := refusedIdentityDiagnostic(t, target, nodes)
			wantMatches := 0
			if duplicate {
				wantMatches = 2
			}
			if diagnostic.MatchCount != wantMatches || diagnostic.CandidateCount != 2 || len(diagnostic.Candidates) != 2 {
				t.Fatalf("incorrect refusal cardinality: %+v", diagnostic)
			}
			if diagnostic.Approved.WWN != target.Wwn || diagnostic.Approved.Serial != target.Serial || diagnostic.Approved.Size != target.SizeBytes {
				t.Fatalf("approved tuple lost: %+v", diagnostic.Approved)
			}
			for i, candidate := range diagnostic.Candidates {
				if candidate.Path != nodes[i].Path || candidate.Type != nodes[i].Type || candidate.Device != nodes[i].Device || candidate.WWN != nodes[i].WWN || candidate.Serial != nodes[i].Serial || candidate.Size != nodes[i].Size || candidate.Matched != duplicate {
					t.Fatalf("observed tuple lost: %+v", candidate)
				}
			}
		})
	}
}

func TestOpenTargetIdentityDiagnosticIsBoundedAndEscaped(t *testing.T) {
	target := &agentv1.StorageTarget{Wwn: "approved", Serial: "serial", SizeBytes: 4096}
	nodes := make([]blockNode, 20)
	for i := range nodes {
		nodes[i] = blockNode{Path: "/dev/\n\"injected\"", Type: "disk", Size: 4096, WWN: strings.Repeat("w", 1024), Serial: "public-serial", Filesystem: "private-filesystem", Mountpoints: []*string{new("private-mount")}}
	}
	diagnostic := refusedIdentityDiagnostic(t, target, nodes)
	if diagnostic.CandidateCount != 20 || len(diagnostic.Candidates) > 16 || len(diagnostic.Candidates) == 0 || diagnostic.CandidatesOmitted != 20-len(diagnostic.Candidates) || diagnostic.MatchCount != 0 {
		t.Fatalf("unbounded candidate diagnostic: %+v", diagnostic)
	}
	for _, candidate := range diagnostic.Candidates {
		if candidate.WWN != strings.Repeat("w", 256)+"[truncated]" || candidate.Path != nodes[0].Path {
			t.Fatalf("incorrect diagnostic encoding: %+v", candidate)
		}
	}
}

func refusedIdentityDiagnostic(t *testing.T, target *agentv1.StorageTarget, nodes []blockNode) targetIdentityDiagnostic {
	t.Helper()
	output, err := json.Marshal(struct {
		Devices []blockNode `json:"blockdevices"`
	}{Devices: nodes})
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{Target: target}}}}
	p.run = func(context.Context, nativeRequest) ([]byte, error) { return output, nil }
	_, err = p.openTarget(t.Context(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: target}}}, false)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected identity refusal, got %v", err)
	}
	_, encoded, ok := strings.Cut(err.Error(), "target_identity_ambiguous ")
	if !ok || len(encoded) > 12<<10 || strings.Contains(encoded, "private-") || strings.ContainsAny(encoded, "\n\r") {
		t.Fatalf("missing or unsafe identity diagnostic: %v", err)
	}
	var diagnostic targetIdentityDiagnostic
	if err := json.Unmarshal([]byte(encoded), &diagnostic); err != nil {
		t.Fatalf("invalid diagnostic: %v", err)
	}
	return diagnostic
}

// Reproduces the public approved tuple and kernel/lsblk facts retained from the
// 2026-10-10 Ubuntu SATA/NVMe signed-recovery diagnostic boots. Both original
// match counts were zero, not duplicates. NVMe changed from nvme0n1 to nvme1n1.
func recoveryIdentityFixture(bus string) (*agentv1.StorageTarget, []blockNode, map[string]sysfsBlockIdentity) {
	target := &agentv1.StorageTarget{Wwn: "0x5000000000000001", Serial: "lindm-lab-0", SizeBytes: 3758096384}
	disk := blockNode{Path: "/dev/sda", Type: "disk", Size: target.SizeBytes, Device: "8:0"}
	state := blockNode{Path: "/dev/sdb", Type: "disk", Size: 1073741824, Device: "8:16"}
	seed := blockNode{Path: "/dev/vda", Type: "disk", Size: 374784, Device: "253:0"}
	native := map[string]sysfsBlockIdentity{
		disk.Device:  {DeviceWWID: sysfsIdentityValue{Value: "naa.5000000000000001"}, VPDSerial: sysfsIdentityValue{Value: "lindm-lab-0"}},
		state.Device: {DeviceWWID: sysfsIdentityValue{Value: "naa.5000000000000002"}, VPDSerial: sysfsIdentityValue{Value: "lindm-lab-1"}},
	}
	partPaths := []string{"/dev/sda1", "/dev/sda14", "/dev/sda15", "/dev/sda16"}
	partDevices := []string{"8:1", "8:14", "8:15", "259:0"}
	if bus == "nvme" {
		target.Wwn = "nvme.1b36-6c696e646d2d6c61622d30-51454d55204e564d65204374726c-00000001"
		disk.Path, disk.Device, disk.Serial = "/dev/nvme1n1", "259:0", "lindm-lab-0         "
		state.Path, state.Device, state.Serial = "/dev/nvme0n1", "259:1", "lindm-lab-1         "
		native = map[string]sysfsBlockIdentity{
			disk.Device:  {WWID: sysfsIdentityValue{Value: target.Wwn}, Serial: sysfsIdentityValue{Value: target.Serial}},
			state.Device: {WWID: sysfsIdentityValue{Value: "nvme.1b36-6c696e646d2d6c61622d31-51454d55204e564d65204374726c-00000001"}, Serial: sysfsIdentityValue{Value: "lindm-lab-1"}},
		}
		partPaths = []string{"/dev/nvme1n1p1", "/dev/nvme1n1p14", "/dev/nvme1n1p15", "/dev/nvme1n1p16"}
		partDevices = []string{"259:2", "259:3", "259:4", "259:5"}
	}
	for i, size := range []uint64{2683289088, 4194304, 111149056, 957350400} {
		disk.Children = append(disk.Children, blockNode{Path: partPaths[i], Type: "part", Device: partDevices[i], Size: size})
	}
	return target, []blockNode{disk, state, seed}, native
}

func TestResolveTargetIdentityRecoversExactNativeBasisWithoutUdev(t *testing.T) {
	for _, bus := range []string{"sata", "nvme"} {
		t.Run(bus, func(t *testing.T) {
			target, nodes, native := recoveryIdentityFixture(bus)
			selected, disk, diagnostic := resolveTargetIdentity(nodes, target, true, func(device string) sysfsBlockIdentity { return native[device] })
			if diagnostic.MatchCount != 1 || diagnostic.CandidateCount != 7 || selected != &nodes[0] || disk != selected || selected.WWN != target.Wwn || selected.Serial != target.Serial {
				t.Fatalf("exact recovery identity not selected: %s", diagnostic.encode())
			}
			if diagnostic.Candidates[0].WWN != "" || diagnostic.Candidates[0].EffectiveWWN != target.Wwn || diagnostic.Candidates[0].EffectiveSerial != target.Serial {
				t.Fatalf("raw/effective identity evidence lost: %+v", diagnostic.Candidates[0])
			}
			for _, child := range selected.Children {
				if child.WWN != target.Wwn || child.Serial != target.Serial {
					t.Fatalf("partition did not inherit physical identity: %+v", child)
				}
			}
		})
	}
}

func TestResolveTargetIdentityNeverWeakensApprovedTuple(t *testing.T) {
	for _, bus := range []string{"sata", "nvme"} {
		for _, variant := range []string{"missing-wwn", "missing-serial", "different-wwn", "different-serial", "different-size", "lsblk-conflict", "duplicate", "blank-approved-wwn", "blank-approved-serial"} {
			t.Run(bus+"/"+variant, func(t *testing.T) {
				target, nodes, native := recoveryIdentityFixture(bus)
				identity := native[nodes[0].Device]
				switch variant {
				case "missing-wwn":
					identity.WWID, identity.DeviceWWID = sysfsIdentityValue{}, sysfsIdentityValue{}
				case "missing-serial":
					identity.Serial, identity.VPDSerial = sysfsIdentityValue{}, sysfsIdentityValue{}
					nodes[0].Serial = ""
				case "different-wwn":
					if bus == "sata" {
						identity.DeviceWWID.Value = "naa.5000000000000009"
					} else {
						identity.WWID.Value = strings.TrimSuffix(identity.WWID.Value, "1") + "2"
					}
				case "different-serial":
					if bus == "sata" {
						identity.VPDSerial.Value = "different"
					} else {
						identity.Serial.Value = "different"
					}
				case "different-size":
					nodes[0].Size++
				case "lsblk-conflict":
					nodes[0].WWN = "different-lsblk-wwn"
				case "duplicate":
					duplicate := nodes[0]
					duplicate.Path, duplicate.Device, duplicate.Children = "/dev/another", "8:128", nil
					nodes = append(nodes, duplicate)
					native[duplicate.Device] = identity
				case "blank-approved-wwn":
					target.Wwn = ""
				case "blank-approved-serial":
					target.Serial = ""
				}
				native[nodes[0].Device] = identity
				selected, disk, diagnostic := resolveTargetIdentity(nodes, target, true, func(device string) sysfsBlockIdentity { return native[device] })
				wantMatches := 0
				if variant == "duplicate" {
					wantMatches = 2
				}
				if selected != nil || disk != nil || diagnostic.MatchCount != wantMatches {
					t.Fatalf("weakened frozen identity: %s", diagnostic.encode())
				}
			})
		}
	}
}

func TestResolveTargetIdentitySurvivesBootLocalRenumbering(t *testing.T) {
	for _, bus := range []string{"sata", "nvme"} {
		t.Run(bus, func(t *testing.T) {
			target, nodes, native := recoveryIdentityFixture(bus)
			identity, stateIdentity := native[nodes[0].Device], native[nodes[1].Device]
			nodes[0].Path, nodes[1].Path = nodes[1].Path, nodes[0].Path
			nodes[0].Device, nodes[1].Device = nodes[1].Device, nodes[0].Device
			native[nodes[0].Device], native[nodes[1].Device] = identity, stateIdentity
			nodes[0], nodes[1] = nodes[1], nodes[0]
			selected, _, diagnostic := resolveTargetIdentity(nodes, target, true, func(device string) sysfsBlockIdentity { return native[device] })
			if diagnostic.MatchCount != 1 || selected != &nodes[1] || selected.WWN != target.Wwn {
				t.Fatalf("boot-local name or enumeration order selected target: %s", diagnostic.encode())
			}
		})
	}
}

func TestResolveTargetIdentityInheritsOnlyWithinPhysicalBranch(t *testing.T) {
	target := &agentv1.StorageTarget{Wwn: "wwn", Serial: "serial", LuksUuid: fixtureLUKS, SizeBytes: 4096}
	absent := func(string) sysfsBlockIdentity { return sysfsBlockIdentity{} }
	for _, variant := range []string{"one-uuid", "no-uuid-after-erase", "wrong-uuid", "duplicate", "orphan-sibling", "mapped-device", "conflicting-child"} {
		t.Run(variant, func(t *testing.T) {
			nodes := []blockNode{{Path: "/dev/sda", Type: "disk", Device: "8:0", WWN: target.Wwn, Serial: target.Serial, Size: 8192, Children: []blockNode{{Path: "/dev/sda1", Type: "part", Device: "8:1", Size: target.SizeBytes, UUID: target.LuksUuid}}}}
			switch variant {
			case "one-uuid":
				nodes[0].Children = append(nodes[0].Children, blockNode{Path: "/dev/sda2", Type: "part", Device: "8:2", Size: target.SizeBytes, UUID: "different"})
			case "no-uuid-after-erase":
				nodes[0].Children[0].UUID = ""
			case "wrong-uuid":
				nodes[0].Children[0].UUID = "different"
			case "duplicate":
				nodes[0].Children = append(nodes[0].Children, nodes[0].Children[0])
			case "orphan-sibling":
				nodes = append(nodes, nodes[0].Children[0])
				nodes[0].Children = nil
			case "mapped-device":
				nodes[0].Children[0].Type = "crypt"
			case "conflicting-child":
				nodes[0].Children[0].WWN = "different"
			}
			selected, disk, diagnostic := resolveTargetIdentity(nodes, target, false, absent)
			want := variant == "one-uuid" || variant == "no-uuid-after-erase" || variant == "mapped-device"
			if (selected != nil) != want || (disk != nil) != want {
				t.Fatalf("incorrect tree identity inheritance: %s", diagnostic.encode())
			}
		})
	}
}

func TestResolveSanitizeTargetExcludesFullSizePartition(t *testing.T) {
	target, nodes, native := recoveryIdentityFixture("sata")
	nodes[0].Children[0].Size = target.SizeBytes
	selected, _, diagnostic := resolveTargetIdentity(nodes, target, true, func(device string) sysfsBlockIdentity { return native[device] })
	if selected != &nodes[0] || diagnostic.MatchCount != 1 {
		t.Fatalf("partition confused with approved whole-disk sanitize scope: %s", diagnostic.encode())
	}
}

func TestResolvedNVMeTargetStillRequiresFrozenControllerScope(t *testing.T) {
	for _, variant := range []string{"approved", "basis", "namespace", "controller-model", "controller-firmware", "controller-wide"} {
		t.Run(variant, func(t *testing.T) {
			action := nvmeActionFixture(agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, false)
			nodes := []blockNode{{Path: "/dev/nvme9n1", Device: "259:7", Type: "disk", Size: action.Target.SizeBytes, Serial: action.Target.Serial + "     "}}
			identity := sysfsBlockIdentity{WWID: sysfsIdentityValue{Value: action.Target.Wwn}, Serial: sysfsIdentityValue{Value: action.Target.Serial}}
			selected, _, diagnostic := resolveTargetIdentity(nodes, action.Target, true, func(string) sysfsBlockIdentity { return identity })
			if selected == nil || diagnostic.MatchCount != 1 {
				t.Fatalf("native kernel identity not resolved: %s", diagnostic.encode())
			}
			switch variant {
			case "basis":
				action.NvmeScope.Identity.Basis = agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID
			case "namespace":
				action.NvmeScope.NamespaceId++
			case "controller-model":
				action.NvmeScope.Identity.ControllerModel = "different model"
			case "controller-firmware":
				action.NvmeScope.Identity.ControllerFirmware = "different firmware"
			case "controller-wide":
				action.NvmeScope.ControllerWide = true
			}
			inventory := nvmeNamespaceListFixture(1)
			_, err := nvmePlan(action, 1, nvmeControllerFixture(), nvmeNamespaceFixture(), inventory, inventory)
			if (err == nil) != (variant == "approved") {
				t.Fatalf("kernel discovery bypassed frozen native controller scope: %v", err)
			}
		})
	}
}
