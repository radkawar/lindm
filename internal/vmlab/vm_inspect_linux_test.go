// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestVMTruthPreservesNativePackageIdentity(t *testing.T) {
	dpkg, err := parseVMTruth([]byte("installed\tlibfoo\t2:1.0-3\tamd64\tfoo\t2:1.0-3\ninstalled\tlibfoo\t2:1.0-3\ti386\tfoo\t2:1.0-3\nconfig-files\tremoved\t1\tamd64\tremoved\t1\n"), "dpkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(dpkg) != 2 || dpkg[nativePackage{name: "libfoo", version: "2:1.0-3", architecture: "amd64", manager: "dpkg", sourceName: "foo", sourceVersion: "2:1.0-3", module: nativeModule{status: truthUnavailable}}] != 1 || dpkg[nativePackage{name: "libfoo", version: "2:1.0-3", architecture: "i386", manager: "dpkg", sourceName: "foo", sourceVersion: "2:1.0-3", module: nativeModule{status: truthUnavailable}}] != 1 {
		t.Fatalf("dpkg lost epoch, multiarch or installed-state distinction: %#v", dpkg)
	}
	rpm, err := parseVMTruth([]byte("kernel\t0:6.18-1.fc44\tx86_64\t(none)\nkernel\t0:6.19-1.fc44\tx86_64\t(none)\ngpg-pubkey\t0:1234-5678\t\t(none)\ngpg-pubkey\t0:1234-5678\t\t(none)\n"), "rpm")
	if err != nil {
		t.Fatal(err)
	}
	if len(rpm) != 3 || rpm[nativePackage{name: "gpg-pubkey", version: "0:1234-5678", manager: "rpm", module: nativeModule{status: truthSuccess}}] != 2 {
		t.Fatalf("RPM lost multiversion, multiplicity or absent ARCH: %#v", rpm)
	}
}

func TestVMTruthRejectsIncompleteEvidence(t *testing.T) {
	for _, test := range []struct{ name, manager, data string }{
		{"empty", "dpkg", ""},
		{"truncated", "rpm", "kernel\t0:1-1\tx86_64"},
		{"unknown state", "dpkg", "unknown\tpkg\t1\tamd64\tpkg\t1\n"},
		{"no installed packages", "dpkg", "config-files\tpkg\t1\tamd64\tpkg\t1\n"},
		{"missing dpkg arch", "dpkg", "installed\tpkg\t1\t\tpkg\t1\n"},
		{"missing source identity", "dpkg", "installed\tpkg\t1\tamd64\t\t\n"},
		{"extra RPM column", "rpm", "pkg\t0:1-1\tx86_64\t(none)\textra\n"},
		{"unknown manager", "other", "pkg\t1\tarch\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseVMTruth([]byte(test.data), test.manager); err == nil {
				t.Fatal("accepted incomplete native truth")
			}
		})
	}
}

func vmTestObservation() (*vmTruth, *inventoryv1.NativeObservation) {
	truth := &vmTruth{manager: "rpm", host: [6]string{"fedora", "44", "x86_64", "6.19", "private-hostname", "private-boot-id"}, packages: map[nativePackage]int{{name: "kernel", version: "0:6.19-1", architecture: "x86_64", manager: "rpm", module: nativeModule{status: truthSuccess}}: 1}}
	observed := func(s string) *inventoryv1.ObservedString {
		return &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: s}
	}
	actual := &inventoryv1.NativeObservation{
		Host:     &inventoryv1.HostObservation{OsId: observed(truth.host[0]), OsVersion: observed(truth.host[1]), Architecture: observed(truth.host[2]), KernelRelease: observed(truth.host[3]), Hostname: observed(truth.host[4]), BootId: observed(truth.host[5])},
		Packages: &inventoryv1.PackageObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Backend: "rpm", Packages: []*inventoryv1.Package{{Name: "kernel", Version: "0:6.19-1", Architecture: "x86_64", Manager: "rpm", Module: &inventoryv1.ModuleObservation{Status: truthSuccess}, Origin: &inventoryv1.PackageOrigin{Status: truthUnavailable}}}},
	}
	return truth, actual
}

func TestVMComparisonChecksEveryFieldNotCounts(t *testing.T) {
	truth, actual := vmTestObservation()
	if err := compareVMObservation(truth, actual); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*inventoryv1.NativeObservation)
	}{
		{"name", func(o *inventoryv1.NativeObservation) { o.Packages.Packages[0].Name = "other" }},
		{"version", func(o *inventoryv1.NativeObservation) { o.Packages.Packages[0].Version = "1:6.19-1" }},
		{"architecture", func(o *inventoryv1.NativeObservation) { o.Packages.Packages[0].Architecture = "aarch64" }},
		{"manager", func(o *inventoryv1.NativeObservation) { o.Packages.Packages[0].Manager = "dpkg" }},
		{"source name", func(o *inventoryv1.NativeObservation) { o.Packages.Packages[0].SourceName = "other" }},
		{"source version", func(o *inventoryv1.NativeObservation) { o.Packages.Packages[0].SourceVersion = "1:6.19-1" }},
		{"missing module", func(o *inventoryv1.NativeObservation) { o.Packages.Packages[0].Module = nil }},
		{"module status", func(o *inventoryv1.NativeObservation) { o.Packages.Packages[0].Module.Status = truthUnavailable }},
		{"module stream", func(o *inventoryv1.NativeObservation) {
			o.Packages.Packages[0].Module = &inventoryv1.ModuleObservation{Status: truthSuccess, Modular: true, Name: "nodejs", Stream: "18", Version: "20250101", Context: "abcdef"}
		}},
		{"multiplicity", func(o *inventoryv1.NativeObservation) {
			o.Packages.Packages = append(o.Packages.Packages, o.Packages.Packages[0])
		}},
		{"failed collection", func(o *inventoryv1.NativeObservation) {
			o.Packages.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
		}},
		{"boot", func(o *inventoryv1.NativeObservation) { o.Host.BootId.Value = "changed-private-id" }},
		{"hostname", func(o *inventoryv1.NativeObservation) { o.Host.Hostname.Value = "changed-private-hostname" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			truth, actual := vmTestObservation()
			test.mutate(actual)
			err := compareVMObservation(truth, actual)
			if err == nil {
				t.Fatal("accepted mismatched inventory")
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("error leaked guest identity")
			}
		})
	}
}

func TestVMChangingTruthIsNotCollectorMismatch(t *testing.T) {
	before, _ := vmTestObservation()
	after, _ := vmTestObservation()
	if err := stableVMTruth(before, after); err != nil {
		t.Fatal(err)
	}
	after.packages[nativePackage{name: "new-package", version: "0:1-1", architecture: "x86_64", manager: "rpm", module: nativeModule{status: truthSuccess}}] = 1
	if err := stableVMTruth(before, after); err == nil || !strings.Contains(err.Error(), "no collector verdict") {
		t.Fatalf("expected unstable truth classification, got %v", err)
	}
	after, _ = vmTestObservation()
	after.host[5] = "another-private-boot-id"
	if err := stableVMTruth(before, after); err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatalf("expected sanitized boot instability, got %v", err)
	}
}

func TestInspectArchitectureRequiresMatchingELFMachine(t *testing.T) {
	for _, test := range []struct {
		input, canonical string
		machine          elf.Machine
	}{
		{"amd64", "x86_64", elf.EM_X86_64},
		{"x86_64", "x86_64", elf.EM_X86_64},
		{"arm64", "aarch64", elf.EM_AARCH64},
		{"aarch64", "aarch64", elf.EM_AARCH64},
	} {
		architecture, machine, err := inspectArchitecture(test.input)
		if err != nil || architecture != test.canonical || machine != test.machine {
			t.Fatalf("architecture %q = %q, %v, %v", test.input, architecture, machine, err)
		}
	}
	for _, architecture := range []string{"", "i386", "ppc64le"} {
		if _, _, err := inspectArchitecture(architecture); err == nil {
			t.Fatalf("accepted unsupported architecture %q", architecture)
		}
	}
}

func TestInspectRequestedHardwareMustBeObserved(t *testing.T) {
	hardware := &VMHardwareOptions{Firmware: &EncryptedFirmwareOptions{SecureBoot: true}, TPM: true, ExtraDisks: 1}
	fixture := func() *inventoryv1.NativeDetails {
		details := nativeDetailsFixture()
		details.Firmware.Mode = truthString("uefi")
		details.Firmware.SecureBoot = truthString("enabled")
		details.Tpm.Present = truthBool(true)
		details.Tpm.Version = truthString("2")
		details.Storage.Devices = []*inventoryv1.BlockDevice{
			{Name: "root", Type: truthString("disk")},
			{Name: "extra", Type: truthString("disk")},
			{Name: "seed", Type: truthString("disk")},
		}
		return details
	}
	if err := compareInspectHardware(hardware, fixture()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*inventoryv1.NativeDetails){
		func(d *inventoryv1.NativeDetails) { d.Firmware.Mode = truthString("bios") },
		func(d *inventoryv1.NativeDetails) { d.Firmware.SecureBoot = truthString("disabled") },
		func(d *inventoryv1.NativeDetails) { d.Firmware.SecureBoot = truthString("") },
		func(d *inventoryv1.NativeDetails) { d.Tpm.Present = truthBool(false) },
		func(d *inventoryv1.NativeDetails) { d.Tpm.Version = truthString("1") },
	} {
		details := fixture()
		mutate(details)
		if err := compareInspectHardware(hardware, details); err == nil {
			t.Fatal("accepted requested hardware without observed evidence")
		}
	}
	disabled := fixture()
	hardware.Firmware.SecureBoot = false
	disabled.Firmware.SecureBoot = truthString("disabled")
	if err := compareInspectHardware(hardware, disabled); err != nil {
		t.Fatal(err)
	}
}

func TestInspectEncryptionRequiresActualLayers(t *testing.T) {
	details := nativeDetailsFixture()
	if err := compareInspectEncryption("none", details); err != nil {
		t.Fatal(err)
	}
	if err := compareInspectEncryption("luks2", details); err == nil {
		t.Fatal("plaintext accepted as encrypted fixture")
	}
	details.Storage.Devices = []*inventoryv1.BlockDevice{
		{Name: "encrypted", Type: truthString("disk"), Encryption: truthString("luks")},
		{Name: "opened", Type: truthString("crypt"), Encryption: truthString("dm-crypt")},
	}
	for _, fixture := range []string{"luks1", "luks2"} {
		if err := compareInspectEncryption(fixture, details); err != nil {
			t.Fatal(err)
		}
	}
	if err := compareInspectEncryption("lvm-luks2", details); err == nil {
		t.Fatal("missing LVM-on-LUKS accepted")
	}
	details.Storage.Devices = append(details.Storage.Devices, &inventoryv1.BlockDevice{Name: "logical", Type: truthString("lvm"), Encryption: truthString("inherited-dm-crypt")})
	if err := compareInspectEncryption("lvm-luks2", details); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryRecordIsPrivateExactAndExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	data := []byte("{\"host\": {\"hostname\": {\"value\": \"private-host\"}}}\n")
	result := new(VMInspectResult)
	if err := publishVMInventoryRecord(path, data, result, nil); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(data) {
		t.Fatal("inventory export reserialized or changed exact observation bytes")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("inventory permissions = %o", info.Mode().Perm())
	}
	digest := sha256.Sum256(data)
	if result.InventoryRecordPath != path || result.InventoryRecordSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("inventory record is not digest-linked to run evidence")
	}
	if err := publishVMInventoryRecord(path, []byte("replacement"), new(VMInspectResult), nil); err == nil {
		t.Fatal("overwrote existing inventory evidence")
	}
	link := filepath.Join(filepath.Dir(path), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := publishVMInventoryRecord(link, []byte("replacement"), new(VMInspectResult), nil); err == nil {
		t.Fatal("followed existing inventory symlink")
	}
	stored, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(data) {
		t.Fatal("existing evidence changed")
	}
}

func TestInventoryRecordNotPublishedAfterFailureOrWithoutOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	cleanupFailure := errors.New("owned guest cleanup failed")
	result := new(VMInspectResult)
	if err := publishVMInventoryRecord(path, []byte("private"), result, cleanupFailure); !errors.Is(err, cleanupFailure) {
		t.Fatalf("lost cleanup failure: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published evidence after failed cleanup: %v", err)
	}
	if err := publishVMInventoryRecord("", []byte("private"), result, nil); err != nil {
		t.Fatal(err)
	}
	if result.InventoryRecordPath != "" || result.InventoryRecordSHA256 != "" {
		t.Fatal("export metadata published without opt-in")
	}
	if err := publishVMInventoryRecord(path, nil, result, nil); err == nil {
		t.Fatal("published missing observation")
	}
}

func TestInspectDiskIdentitiesRetainGuestCreatedDisks(t *testing.T) {
	hardware := &VMHardwareOptions{ExtraDisks: 1}
	details := nativeDetailsFixture()
	details.Storage.Devices = []*inventoryv1.BlockDevice{
		{Name: "vda", Type: truthString("disk")},
		{Name: "vdb", Type: truthString("disk")},
		{Name: "vdc", Type: truthString("disk")},
		{Name: "zram0", Type: truthString("disk")},
	}
	// Root and extra media have harness serials. The seed and guest-created
	// zram stay inventoried but cannot satisfy a requested data-disk identity.
	data := []byte("NAME=\"vda\" TYPE=\"disk\" SERIAL=\"lindm-lab-0\"\nNAME=\"vdb\" TYPE=\"disk\" SERIAL=\"lindm-lab-1\"\nNAME=\"vdc\" TYPE=\"disk\" SERIAL=\"\"\nNAME=\"zram0\" TYPE=\"disk\" SERIAL=\"\"\n")
	if err := compareInspectDiskIdentities(data, hardware, details); err != nil {
		t.Fatal(err)
	}
	if len(details.Storage.Devices) != 4 {
		t.Fatal("hardware assertion discarded guest-created inventory")
	}
	for _, malformed := range []string{
		strings.Replace(string(data), "lindm-lab-1", "", 1),
		strings.Replace(string(data), "lindm-lab-1", "lindm-lab-0", 1),
		strings.Replace(string(data), "lindm-lab-1", "lindm-lab-9", 1),
		strings.Replace(string(data), "NAME=\"vdb\"", "NAME=\"unobserved\"", 1),
	} {
		if err := compareInspectDiskIdentities([]byte(malformed), hardware, details); err == nil {
			t.Fatal("accepted missing, duplicate or substituted configured disk")
		}
	}
}

func TestInspectReadinessRequiresNativeSettledSignals(t *testing.T) {
	for _, test := range []struct {
		name, system, network   string
		systemExit, networkExit int
		wantError               bool
	}{
		{"running", "running\n", "complete\n", 0, 0, false},
		{"degraded", "degraded\n", "complete\n", 1, 0, false},
		{"non-NetworkManager", "running\n", "not-installed\n", 0, 0, false},
		// systemd >= 240 honours --wait, so a transient answer is unsettled.
		{"starting", "starting\n", "complete\n", 1, 0, true},
		{"inconsistent-system-exit", "degraded\n", "complete\n", 0, 0, true},
		{"network-timeout", "running\n", "", 0, 1, true},
		{"truncated-system", "running", "complete\n", 0, 0, true},
		{"invalid-network-proof", "running\n", "maybe\n", 0, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			proof, err := collectInspectReadiness(t.Context(), func(ctx context.Context, command string, input io.Reader, limit int, timeout time.Duration) (guestCommandResult, error) {
				calls++
				if _, bounded := ctx.Deadline(); !bounded || input != nil || limit > 4096 || timeout > 35*time.Second {
					t.Fatal("readiness probe lost its subprocess bounds")
				}
				switch {
				case calls == 1 && command == inspectSystemReadinessCommand:
					return guestCommandResult{Stdout: []byte(test.system), ExitCode: test.systemExit}, nil
				case calls == 2 && command == inspectSystemdVersionCommand:
					return guestCommandResult{Stdout: []byte("systemd 257 (257.13+suse.131.g575b4807b7)\n+PAM +AUDIT\n")}, nil
				case calls == 2 && command == inspectFailedUnitsCommand:
					return guestCommandResult{Stdout: []byte("example.service loaded failed failed Example\n")}, nil
				case calls == 3 && strings.HasPrefix(command, "env LC_ALL=C systemctl show --property=Result"):
					return guestCommandResult{Stdout: []byte("exit-code\n")}, nil
				case calls == 4 && strings.HasPrefix(command, "sudo -n env LC_ALL=C journalctl"):
					return guestCommandResult{Stdout: []byte("example failed\n")}, nil
				case command == inspectNetworkReadinessCommand:
					return guestCommandResult{Stdout: []byte(test.network), ExitCode: test.networkExit}, nil
				}
				t.Fatal("unexpected readiness probe")
				return guestCommandResult{}, nil
			})
			if (err != nil) != test.wantError {
				t.Fatalf("readiness result: %v", err)
			}
			wantCalls := 2
			if test.system == "degraded\n" {
				wantCalls = 5
			}
			if err == nil && (calls != wantCalls || proof.SystemState == "" || proof.NetworkManagerStartup == "" || proof.CompletedAt.Before(proof.StartedAt)) {
				t.Fatalf("incomplete readiness proof: %v", proof)
			}
			if err == nil && (proof.SystemState == "degraded") != (len(proof.FailedUnits) == 1 && proof.FailedUnits[0].Unit == "example.service" && proof.FailedUnits[0].Result == "exit-code") {
				t.Fatalf("failed units not bound to degraded state: %v", proof)
			}
		})
	}
}

func TestInspectReadinessPreservesNativeFailures(t *testing.T) {
	for _, nativeError := range []error{context.DeadlineExceeded, errors.New("native SSH failure")} {
		proof, err := collectInspectReadiness(t.Context(), func(context.Context, string, io.Reader, int, time.Duration) (guestCommandResult, error) {
			return guestCommandResult{}, nativeError
		})
		if proof != nil || !errors.Is(err, nativeError) {
			t.Fatalf("native readiness failure hidden: %v", err)
		}
	}
}

// AlmaLinux 8.10 x86_64 inspection failed "native system startup is not
// settled": systemd 239 ignores is-system-running --wait (added in v240) and
// answered "starting" while boot jobs still ran. Only that manager is polled.
func TestInspectReadinessPollsSystemdWithoutWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var commands []string
		states := []string{"starting\n", "starting\n", "degraded\n"}
		proof, err := collectInspectReadiness(t.Context(), func(ctx context.Context, command string, input io.Reader, limit int, timeout time.Duration) (guestCommandResult, error) {
			commands = append(commands, command)
			switch command {
			case inspectSystemReadinessCommand:
				state := states[0]
				states = states[1:]
				return guestCommandResult{Stdout: []byte(state), ExitCode: 1}, nil
			case inspectSystemdVersionCommand:
				return guestCommandResult{Stdout: []byte("systemd 239 (239-82.el8_10.13)\n+PAM +AUDIT\n")}, nil
			case inspectFailedUnitsCommand:
				return guestCommandResult{}, nil
			case inspectNetworkReadinessCommand:
				return guestCommandResult{Stdout: []byte("complete\n")}, nil
			}
			t.Fatalf("unexpected readiness probe %q", command)
			return guestCommandResult{}, nil
		})
		if err != nil || proof.SystemState != "degraded" {
			t.Fatalf("legacy readiness = %+v, %v", proof, err)
		}
		want := []string{inspectSystemReadinessCommand, inspectSystemdVersionCommand, inspectSystemReadinessCommand, inspectSystemReadinessCommand, inspectFailedUnitsCommand, inspectNetworkReadinessCommand}
		if strings.Join(commands, "|") != strings.Join(want, "|") {
			t.Fatalf("probe order = %q", commands)
		}
	})
	// A legacy manager that never settles still fails at the readiness deadline.
	synctest.Test(t, func(t *testing.T) {
		_, err := collectInspectReadiness(t.Context(), func(ctx context.Context, command string, input io.Reader, limit int, timeout time.Duration) (guestCommandResult, error) {
			if command == inspectSystemdVersionCommand {
				return guestCommandResult{Stdout: []byte("systemd 239 (239-82.el8_10.13)\n")}, nil
			}
			return guestCommandResult{Stdout: []byte("starting\n"), ExitCode: 1}, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unsettled legacy boot = %v", err)
		}
	})
	for _, version := range []string{"", "not systemd 239\n", "systemd x\n"} {
		_, err := collectInspectReadiness(t.Context(), func(ctx context.Context, command string, input io.Reader, limit int, timeout time.Duration) (guestCommandResult, error) {
			if command == inspectSystemdVersionCommand {
				return guestCommandResult{Stdout: []byte(version)}, nil
			}
			return guestCommandResult{Stdout: []byte("starting\n"), ExitCode: 1}, nil
		})
		if err == nil {
			t.Fatalf("accepted invalid systemd version %q", version)
		}
	}
}

// Ubuntu 26.04 cloud guests settled "degraded" with no recorded cause; the
// readiness proof must name the native failed units, their native Result and
// journal tail, bounded and validated.
func TestInspectReadinessRecordsFailedUnits(t *testing.T) {
	for _, test := range []struct {
		name, listing, result string
		exit                  int
		want                  string
		wantError             bool
	}{
		{name: "two", listing: "systemd-networkd-wait-online.service loaded failed failed Wait for Network\napt-daily.timer loaded failed failed Daily apt\n", result: "exit-code\n", want: "systemd-networkd-wait-online.service=exit-code|apt-daily.timer=exit-code"},
		{name: "escaped-template", listing: "dev-disk-by\\x2dlabel-x.swap loaded failed failed Swap\n", result: "timeout\n", want: "dev-disk-by\\x2dlabel-x.swap=timeout"},
		{name: "none", result: "exit-code\n"},
		{name: "native-failure", exit: 1, wantError: true},
		{name: "not-failed", listing: "a.service loaded active running A\n", result: "success\n", wantError: true},
		{name: "shell-metacharacter", listing: "a';b.service loaded failed failed X\n", result: "exit-code\n", wantError: true},
		{name: "too-many", listing: strings.Repeat("a.service loaded failed failed A\n", maxInspectFailedUnits+1), result: "exit-code\n", wantError: true},
		{name: "invalid-result", listing: "a.service loaded failed failed A\n", result: "exit code; rm\n", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			units, err := inspectFailedUnits(t.Context(), func(ctx context.Context, command string, input io.Reader, limit int, timeout time.Duration) (guestCommandResult, error) {
				if input != nil || limit > 4096 || timeout > 10*time.Second {
					t.Fatal("failed-unit probe lost its bounds")
				}
				switch {
				case command == inspectFailedUnitsCommand:
					return guestCommandResult{Stdout: []byte(test.listing), ExitCode: test.exit}, nil
				case strings.HasPrefix(command, "env LC_ALL=C systemctl show --property=Result --value -- '"):
					return guestCommandResult{Stdout: []byte(test.result)}, nil
				case strings.HasPrefix(command, "sudo -n env LC_ALL=C journalctl -b --no-pager --quiet -o cat -n 5 -u '"):
					return guestCommandResult{Stdout: []byte("Started.\nFailed with result 'exit-code'.\n")}, nil
				}
				t.Fatalf("unexpected probe %q", command)
				return guestCommandResult{}, nil
			})
			var got []string
			for _, unit := range units {
				if len(unit.Journal) != 2 || unit.Journal[1] != "Failed with result 'exit-code'." {
					t.Fatalf("journal tail = %q", unit.Journal)
				}
				got = append(got, unit.Unit+"="+unit.Result)
			}
			if (err != nil) != test.wantError || strings.Join(got, "|") != test.want {
				t.Fatalf("failed units = %q, %v", got, err)
			}
		})
	}
}
