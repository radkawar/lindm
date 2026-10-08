//go:build linux

package vmlab

import (
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestVMTruthPreservesNativePackageIdentity(t *testing.T) {
	dpkg, err := parseVMTruth([]byte("installed\tlibfoo\t2:1.0-3\tamd64\ninstalled\tlibfoo\t2:1.0-3\ti386\nconfig-files\tremoved\t1\tamd64\n"), "dpkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(dpkg) != 2 || dpkg[nativePackage{"libfoo", "2:1.0-3", "amd64", "dpkg"}] != 1 || dpkg[nativePackage{"libfoo", "2:1.0-3", "i386", "dpkg"}] != 1 {
		t.Fatalf("dpkg lost epoch, multiarch or installed-state distinction: %#v", dpkg)
	}
	rpm, err := parseVMTruth([]byte("kernel\t0:6.18-1.fc44\tx86_64\nkernel\t0:6.19-1.fc44\tx86_64\ngpg-pubkey\t0:1234-5678\t\ngpg-pubkey\t0:1234-5678\t\n"), "rpm")
	if err != nil {
		t.Fatal(err)
	}
	if len(rpm) != 3 || rpm[nativePackage{"gpg-pubkey", "0:1234-5678", "", "rpm"}] != 2 {
		t.Fatalf("RPM lost multiversion, multiplicity or absent ARCH: %#v", rpm)
	}
}

func TestVMTruthRejectsIncompleteEvidence(t *testing.T) {
	for _, test := range []struct{ name, manager, data string }{
		{"empty", "dpkg", ""},
		{"truncated", "rpm", "kernel\t0:1-1\tx86_64"},
		{"unknown state", "dpkg", "unknown\tpkg\t1\tamd64\n"},
		{"no installed packages", "dpkg", "config-files\tpkg\t1\tamd64\n"},
		{"missing dpkg arch", "dpkg", "installed\tpkg\t1\t\n"},
		{"extra RPM column", "rpm", "pkg\t0:1-1\tx86_64\textra\n"},
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
	truth := &vmTruth{manager: "rpm", host: [6]string{"fedora", "44", "x86_64", "6.19", "private-hostname", "private-boot-id"}, packages: map[nativePackage]int{{"kernel", "0:6.19-1", "x86_64", "rpm"}: 1}}
	observed := func(s string) *inventoryv1.ObservedString {
		return &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: s}
	}
	actual := &inventoryv1.NativeObservation{
		Host:     &inventoryv1.HostObservation{OsId: observed(truth.host[0]), OsVersion: observed(truth.host[1]), Architecture: observed(truth.host[2]), KernelRelease: observed(truth.host[3]), Hostname: observed(truth.host[4]), BootId: observed(truth.host[5])},
		Packages: &inventoryv1.PackageObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Backend: "rpm", Packages: []*inventoryv1.Package{{Name: "kernel", Version: "0:6.19-1", Architecture: "x86_64", Manager: "rpm"}}},
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
	after.packages[nativePackage{"new-package", "0:1-1", "x86_64", "rpm"}] = 1
	if err := stableVMTruth(before, after); err == nil || !strings.Contains(err.Error(), "no collector verdict") {
		t.Fatalf("expected unstable truth classification, got %v", err)
	}
	after, _ = vmTestObservation()
	after.host[5] = "another-private-boot-id"
	if err := stableVMTruth(before, after); err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatalf("expected sanitized boot instability, got %v", err)
	}
}

func TestVMOutputBound(t *testing.T) {
	out := &limitedOutput{limit: 4}
	if n, err := out.Write([]byte("1234")); n != 4 || err != nil {
		t.Fatalf("bounded write: %d, %v", n, err)
	}
	if _, err := out.Write([]byte("5")); err == nil || !out.exceeded || string(out.data) != "1234" {
		t.Fatal("output overflow not bounded")
	}
}
