//go:build linux

package vmlab

import (
	"math"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestNativeTruthStatusDistinguishesMissingFromZero(t *testing.T) {
	for _, test := range []struct {
		data   string
		status inventoryv1.CollectionStatus
		value  string
	}{
		{"success\n0\n", truthSuccess, "0\n"},
		{"success\n", truthSuccess, ""},
		{"unavailable\n", truthUnavailable, ""},
		{"denied\n", truthDenied, ""},
	} {
		value, status, err := parseTruthStatus([]byte(test.data))
		if err != nil || status != test.status || string(value) != test.value {
			t.Fatalf("status parsing = %q %v %v", value, status, err)
		}
	}
	for _, data := range []string{"", "success", "unavailable\n0", "denied\nprivate", "unknown\n"} {
		if _, _, err := parseTruthStatus([]byte(data)); err == nil {
			t.Fatalf("accepted malformed status %q", data)
		}
	}
}

func TestNativeBlockTruthPreservesEscapedMountpoints(t *testing.T) {
	values, err := parseTruthPairs(`NAME="dm-0" MOUNTPOINT="/media/private\x20disk\x22" SIZE="0" FSTYPE=""`)
	if err != nil {
		t.Fatal(err)
	}
	if values["MOUNTPOINT"] != "/media/private disk\"" || values["SIZE"] != "0" || values["FSTYPE"] != "" {
		t.Fatalf("lost native values: %#v", values)
	}
	for _, data := range []string{`NAME="x`, `NAME=x`, `NAME="x" NAME="y"`, `NAME="\xzz"`, `NAME="x" trailing`} {
		if _, err := parseTruthPairs(data); err == nil {
			t.Fatalf("accepted malformed pairs %q", data)
		}
	}
}

func TestNativeLocalTruthPreservesUIDAndShell(t *testing.T) {
	users, err := parseTruthUsers([]byte("root:x:0:0:Root:/root:/bin/bash\nservice:x:998:998::/:/usr/sbin/nologin\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(users.Users) != 2 || users.Users[0].Uid != 0 || users.Users[1].Shell != "/usr/sbin/nologin" {
		t.Fatalf("lost local identities: %v", users)
	}
	for _, data := range []string{"", "root:x:0:0::/:/bin/sh", "root:x:no:0::/:/bin/sh\n", "root:x:0:0::/:/bin/sh\nroot:x:1:0::/:/bin/sh\n"} {
		if _, err := parseTruthUsers([]byte(data)); err == nil {
			t.Fatal("accepted incomplete account evidence")
		}
	}
}

func TestNativeX86TruthRequiresCumulativeFeatures(t *testing.T) {
	v1 := "cx8 cmov fpu fxsr mmx syscall sse sse2"
	v2 := v1 + " cx16 lahf_lm popcnt pni ssse3 sse4_1 sse4_2"
	v3 := v2 + " avx avx2 bmi1 bmi2 f16c fma abm movbe xsave"
	v4 := v3 + " avx512f avx512bw avx512cd avx512dq avx512vl"
	for _, test := range []struct{ flags, level string }{{v1, "x86-64-v1"}, {v2, "x86-64-v2"}, {v3, "x86-64-v3"}, {v4, "x86-64-v4"}, {strings.Replace(v4, "popcnt", "", 1), "x86-64-v1"}, {"avx512f", ""}} {
		if got := truthX86Level(test.flags); got != test.level {
			t.Fatalf("level = %q, want %q", got, test.level)
		}
	}
}

func TestCPUTruthSupportsFlatAndHierarchicalJSON(t *testing.T) {
	for _, data := range []string{
		`{"lscpu":[{"field":"Architecture:","data":"x86_64"},{"field":"CPU(s):","data":"2"},{"field":"Model name:","data":"test-model"}]}`,
		`{"lscpu":[{"field":"Architecture:","data":"x86_64","children":[{"field":"CPU(s):","data":"2"}]},{"field":"Vendor ID:","data":"test-vendor","children":[{"field":"Model name:","data":"test-model"}]}]}`,
	} {
		fields, err := parseCPUTruth([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if fields["Architecture"] != "x86_64" || fields["CPU(s)"] != "2" || fields["Model name"] != "test-model" {
			t.Fatalf("lost CPU truth fields: %v", fields)
		}
	}
}

func nativeDetailsFixture() *inventoryv1.NativeDetails {
	return &inventoryv1.NativeDetails{
		Cpu:               &inventoryv1.CpuDetails{Model: truthString("private-model"), LogicalCores: truthUint(4), PhysicalCores: truthUint(2), X86_64Level: truthString("x86-64-v3")},
		Memory:            &inventoryv1.MemoryDetails{TotalBytes: truthUint(2 << 30), AvailableBytes: truthUint(1 << 30), SwapTotalBytes: truthUint(0)},
		Storage:           &inventoryv1.StorageDetails{Status: truthSuccess, Devices: []*inventoryv1.BlockDevice{{Name: "private-disk", Type: truthString("part"), Parent: truthString("vda"), SizeBytes: truthUint(10 << 30), Filesystem: truthString("ext4"), Mountpoint: truthString("/"), Encryption: truthString("none")}}},
		Network:           &inventoryv1.NetworkDetails{Status: truthSuccess, Interfaces: []*inventoryv1.NetworkInterface{{Name: "private-interface", Mac: truthString("02:00:00:00:00:01"), Link: truthString("UP"), Addresses: &inventoryv1.ObservedStrings{Status: truthSuccess, Values: []string{"192.0.2.1/24", "2001:db8::1/64"}}}}},
		Firmware:          &inventoryv1.FirmwareDetails{Mode: truthString("bios"), SecureBoot: truthString("")},
		Tpm:               &inventoryv1.TpmDetails{Present: truthBool(false), Version: truthString("")},
		Power:             &inventoryv1.PowerDetails{Chassis: truthString("1"), Batteries: &inventoryv1.BatteryDetails{Status: truthSuccess}},
		Sessions:          &inventoryv1.SessionCounts{Users: truthUint(1), Sessions: truthUint(1)},
		LocalUsers:        &inventoryv1.LocalUsers{Status: truthSuccess, Users: []*inventoryv1.LocalUser{{Name: "root", Uid: 0, Shell: "/bin/sh"}, {Name: "private-user", Uid: 1000, Shell: "/bin/bash"}}},
		KernelModuleCount: truthUint(32), UptimeSeconds: truthUint(60), BootTimeUnixSeconds: truthUint(1700000000),
		Backends: &inventoryv1.BackendDetails{Dpkg: truthBool(true), Rpm: truthBool(false), Pacman: truthBool(false), Zypper: truthBool(false), RpmOstree: truthBool(false), Nix: truthBool(false), Flatpak: truthBool(false), Snap: truthBool(false)},
		Flatpak:  &inventoryv1.ApplicationDetails{Status: truthUnavailable}, Snap: &inventoryv1.ApplicationDetails{Status: truthUnavailable},
	}
}

func TestNativeDetailsComparisonChecksValuesAndStatuses(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*inventoryv1.NativeDetails)
	}{
		{"cpu", func(d *inventoryv1.NativeDetails) { d.Cpu.PhysicalCores.Value++ }},
		{"feature level", func(d *inventoryv1.NativeDetails) { d.Cpu.X86_64Level.Value = "x86-64-v2" }},
		{"memory", func(d *inventoryv1.NativeDetails) { d.Memory.TotalBytes.Value++ }},
		{"disk", func(d *inventoryv1.NativeDetails) { d.Storage.Devices[0].SizeBytes.Value++ }},
		{"encryption", func(d *inventoryv1.NativeDetails) { d.Storage.Devices[0].Encryption.Value = "dm-crypt" }},
		{"link", func(d *inventoryv1.NativeDetails) { d.Network.Interfaces[0].Link.Value = "DOWN" }},
		{"address", func(d *inventoryv1.NativeDetails) { d.Network.Interfaces[0].Addresses.Values[0] = "192.0.2.2/24" }},
		{"Secure Boot", func(d *inventoryv1.NativeDetails) { d.Firmware.SecureBoot = truthString("disabled") }},
		{"TPM", func(d *inventoryv1.NativeDetails) { d.Tpm.Present.Value = true }},
		{"battery status", func(d *inventoryv1.NativeDetails) { d.Power.Batteries.Status = truthUnavailable }},
		{"sessions", func(d *inventoryv1.NativeDetails) { d.Sessions.Sessions.Value++ }},
		{"local account", func(d *inventoryv1.NativeDetails) { d.LocalUsers.Users[0].Uid++ }},
		{"module count", func(d *inventoryv1.NativeDetails) { d.KernelModuleCount.Value++ }},
		{"backend", func(d *inventoryv1.NativeDetails) { d.Backends.Flatpak.Value = true }},
		{"empty success", func(d *inventoryv1.NativeDetails) { d.Flatpak.Status = truthSuccess }},
		{"missing detail", func(d *inventoryv1.NativeDetails) { d.Memory = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
			test.mutate(actual)
			err := compareVMDetails(before, after, actual)
			if err == nil {
				t.Fatal("accepted mismatched native detail")
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("comparison leaked guest data")
			}
		})
	}
}

func TestNativeDetailsComparisonAllowsOnlyBoundedChanges(t *testing.T) {
	before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
	after.UptimeSeconds.Value = 80
	actual.UptimeSeconds.Value = 70
	actual.Memory.AvailableBytes.Value += 64 << 20
	actual.LocalUsers.Users[0], actual.LocalUsers.Users[1] = actual.LocalUsers.Users[1], actual.LocalUsers.Users[0]
	actual.Network.Interfaces[0].Addresses.Values[0], actual.Network.Interfaces[0].Addresses.Values[1] = actual.Network.Interfaces[0].Addresses.Values[1], actual.Network.Interfaces[0].Addresses.Values[0]
	if err := compareVMDetails(before, after, actual); err != nil {
		t.Fatal(err)
	}
	actual.UptimeSeconds.Value = 83
	if err := compareVMDetails(before, after, actual); err == nil {
		t.Fatal("accepted out-of-window uptime")
	}
	actual.UptimeSeconds.Value = 70
	after.KernelModuleCount.Value++
	if err := compareVMDetails(before, after, actual); err == nil || !strings.Contains(err.Error(), "no collector verdict") {
		t.Fatalf("unstable truth = %v", err)
	}
	if truthWithin(math.MaxUint64, 0, 1, 2) || truthWithin(0, math.MaxUint64-1, math.MaxUint64, 2) {
		t.Fatal("numeric tolerance overflow")
	}
}

func TestNativeDetailsStatusEvidenceWithholdsIdentities(t *testing.T) {
	details := nativeDetailsFixture()
	statuses := vmDetailStatuses(details)
	if statuses["details.firmware.secure_boot"] != "UNAVAILABLE" || statuses["details.power.batteries"] != "SUCCESS" {
		t.Fatalf("missing status evidence: %v", statuses)
	}
	for key, value := range statuses {
		if strings.Contains(key+value, "private-") {
			t.Fatal("status evidence leaked identity")
		}
	}
	if !proto.Equal(details, nativeDetailsFixture()) {
		t.Fatal("evidence mutated observation")
	}
}

func TestNativeMemoryTruthSelectsAvailableNotFreeOrCache(t *testing.T) {
	data := " total used free shared buffers cache available\nMem: 2048 1024 256 32 64 704 960\nSwap: 0 0 0\n"
	memory, err := parseTruthMemory([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if memory.TotalBytes.Value != 2048 || memory.AvailableBytes.Value != 960 || memory.SwapTotalBytes.Value != 0 || memory.SwapTotalBytes.Status != truthSuccess {
		t.Fatalf("wrong memory truth: %v", memory)
	}
	for _, invalid := range []string{strings.Replace(data, "available", "unexpected", 1), strings.TrimSuffix(data, "\n"), strings.Replace(data, " 960", "", 1)} {
		if _, err := parseTruthMemory([]byte(invalid)); err == nil {
			t.Fatal("accepted incomplete memory truth")
		}
	}
}

func TestNativeApplicationsCompareArchitectureAndVersion(t *testing.T) {
	before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
	for _, details := range []*inventoryv1.NativeDetails{before, after, actual} {
		details.Flatpak = &inventoryv1.ApplicationDetails{Status: truthSuccess, Applications: []*inventoryv1.Application{
			{Name: "private-app", Version: truthString("1"), Architecture: truthString("x86_64"), Scope: truthString("system")},
			{Name: "private-app", Version: truthString("2"), Architecture: truthString("aarch64"), Scope: truthString("system")},
		}}
	}
	actual.Flatpak.Applications[0], actual.Flatpak.Applications[1] = actual.Flatpak.Applications[1], actual.Flatpak.Applications[0]
	if err := compareVMDetails(before, after, actual); err != nil {
		t.Fatal(err)
	}
	actual.Flatpak.Applications[0].Version.Value = "wrong"
	if err := compareVMDetails(before, after, actual); err == nil {
		t.Fatal("accepted wrong application version")
	}
}

func TestNativeStatusMismatchIdentifiesEnumsWithoutGuestValues(t *testing.T) {
	before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
	before.Snap.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
	after.Snap.Status = before.Snap.Status
	actual.Snap.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT
	err := compareVMDetails(before, after, actual)
	if err == nil || !strings.Contains(err.Error(), "COLLECTION_STATUS_NATIVE_COMMAND_FAILURE") || !strings.Contains(err.Error(), "COLLECTION_STATUS_INVALID_OUTPUT") {
		t.Fatalf("status mismatch omitted enum evidence: %v", err)
	}
	if strings.Contains(err.Error(), "private-") {
		t.Fatal("status diagnostic leaked guest values")
	}
}
