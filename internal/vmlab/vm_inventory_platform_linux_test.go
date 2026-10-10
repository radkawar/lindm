//go:build linux

package vmlab

import (
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestNativeModuleTruthPreservesStreamIdentity(t *testing.T) {
	module := parseTruthModule("nodejs:18:20250101010101:abcdef12")
	if module.status != truthSuccess || !module.modular || module.name != "nodejs" || module.stream != "18" || module.version != "20250101010101" || module.context != "abcdef12" {
		t.Fatalf("lost native module identity: %#v", module)
	}
	if got := parseTruthModule("(none)"); got != (nativeModule{status: truthSuccess}) {
		t.Fatalf("nonmodular package = %#v", got)
	}
	for _, label := range []string{"", "nodejs:18:abcdef", "nodejs:18:wrong:abcdef", "node js:18:20250101:abcdef", "nodejs::20250101:abcdef", "nodejs:18:20250101:"} {
		if got := parseTruthModule(label); got != (nativeModule{status: inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT}) {
			t.Fatalf("malformed label produced native identity: %#v", got)
		}
	}
	packages, err := parseVMTruth([]byte("nodejs\t1:18.0-1\tx86_64\tnodejs:18:20250101:aaaa\nnodejs\t1:18.0-1\tx86_64\tnodejs:20:20250101:bbbb\n"), "rpm")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatal("distinct module streams collapsed into one package identity")
	}
}

func TestNativeDNFConfigurationPreservesConfiguredOrder(t *testing.T) {
	directories, status, err := parseDNFConfigTruth([]byte(`{"status":"success","varsdirs":["/etc/yum/vars","/etc/dnf/vars"]}`))
	if err != nil || status != truthSuccess || strings.Join(directories, ":") != "/etc/yum/vars:/etc/dnf/vars" {
		t.Fatalf("configuration order = %v %v %v", directories, status, err)
	}
	for _, state := range []string{"unavailable", "denied", "invalid", "failure"} {
		directories, status, err := parseDNFConfigTruth([]byte(`{"status":"` + state + `"}`))
		if err != nil || status == truthSuccess || len(directories) != 0 {
			t.Fatalf("missing source became success: %v %v %v", directories, status, err)
		}
	}
	if _, status, err := parseDNFConfigTruth([]byte(`{"status":"success","varsdirs":["relative"]}`)); err != nil || status != inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT {
		t.Fatalf("relative configuration directory accepted: %v %v", status, err)
	}
	if _, _, err := parseDNFConfigTruth([]byte(`{"status":"unavailable","varsdirs":["/etc/dnf/vars"]}`)); err == nil {
		t.Fatal("failed config carried partial directories")
	}
}

func TestNativeReleaseLockDoesNotInventDetectedVersions(t *testing.T) {
	for _, value := range []string{"9.4", "9.4\n"} {
		lock, err := parseReleaseLockTruth([]byte("success\n" + value))
		if err != nil || lock.Status != truthSuccess || lock.Value != "9.4" {
			t.Fatalf("explicit lock = %v %v", lock, err)
		}
	}
	lock, err := parseReleaseLockTruth([]byte("unavailable\n"))
	if err != nil || lock.Status != truthUnavailable || lock.Value != "" {
		t.Fatalf("absent lock got a release default: %v %v", lock, err)
	}
	for _, value := range []string{"", " 9.4", "9.4 ", "9.4\n\n", "9.4\r\n"} {
		lock, err := parseReleaseLockTruth([]byte("success\n" + value))
		if err != nil || lock.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT || lock.Value != "" {
			t.Fatalf("invalid lock accepted: %v %v", lock, err)
		}
	}
}

func TestNativeRepositoriesCompareIDsNotProductNames(t *testing.T) {
	data := "repo id                                repo name\nrhel-9-for-x86_64-baseos-eus-rpms       Red Hat Enterprise Linux 9 EUS BaseOS\nprivate-appstream                     Organization AppStream\n"
	repos, err := parseDNFRepositoryTruth(guestCommandResult{Stdout: []byte(data)})
	if err != nil || repos.Status != truthSuccess || repos.Backend != "dnf4" || strings.Join(repos.Ids, ":") != "rhel-9-for-x86_64-baseos-eus-rpms:private-appstream" {
		t.Fatalf("repo ID truth = %v %v", repos, err)
	}
	for _, native := range []guestCommandResult{{}, {Stderr: []byte("No repositories available\n")}} {
		repos, err := parseDNFRepositoryTruth(native)
		if err != nil || repos.Status != truthSuccess || len(repos.Ids) != 0 {
			t.Fatalf("actual zero repositories not preserved: %v %v", repos, err)
		}
	}
	for _, native := range []guestCommandResult{{ExitCode: 1}, {Stderr: []byte("private repo configuration unreadable\n")}, {Stdout: []byte(data), Stderr: []byte("No repositories available\n")}} {
		repos, err := parseDNFRepositoryTruth(native)
		if err != nil || repos.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE || len(repos.Ids) != 0 || repos.Backend != "" {
			t.Fatalf("repository error became empty success: %v %v", repos, err)
		}
	}
	for _, invalid := range []string{"wrong header\n", "repo id repo name\nduplicate A\nduplicate B\n", "repo id repo name\n$releasever Unresolved\n"} {
		if _, err := parseDNFRepositoryTruth(guestCommandResult{Stdout: []byte(invalid)}); err == nil {
			t.Fatal("accepted malformed native repository truth")
		}
	}
}

func TestNativePlatformComparisonRequiresFreshCompleteEvidence(t *testing.T) {
	before, after, actual := nativeDetailsFixture(), nativeDetailsFixture(), nativeDetailsFixture()
	// Historical observations may all lack the optional platform category.
	if err := compareVMDetails(before, after, actual); err != nil {
		t.Fatal(err)
	}
	for _, details := range []*inventoryv1.NativeDetails{before, after, actual} {
		details.Platform = &inventoryv1.PlatformDetails{Cpe: truthString("cpe:/o:redhat:enterprise_linux:9::baseos"), ReleaseverLock: truthString("9.4"), Repositories: &inventoryv1.RepositoryObservation{Status: truthSuccess, Backend: "dnf4", Ids: []string{"rhel-9-baseos-eus", "rhel-9-appstream-eus"}}}
	}
	actual.Platform.Repositories.Ids[0], actual.Platform.Repositories.Ids[1] = actual.Platform.Repositories.Ids[1], actual.Platform.Repositories.Ids[0]
	if err := compareVMDetails(before, after, actual); err != nil {
		t.Fatal(err)
	}
	actual.Platform.ReleaseverLock = truthString("")
	if err := compareVMDetails(before, after, actual); err == nil {
		t.Fatal("lost release lock accepted")
	}
	actual.Platform = nil
	if err := compareVMDetails(before, after, actual); err == nil {
		t.Fatal("fresh expected platform accepted omitted category")
	}
}

func TestSecureBootDiagnosticReportsOnlyKnownPostureValues(t *testing.T) {
	hardware := &VMHardwareOptions{Firmware: &EncryptedFirmwareOptions{SecureBoot: false}}
	details := nativeDetailsFixture()
	details.Firmware.Mode = truthString("uefi")
	details.Firmware.SecureBoot = truthString("")
	err := compareInspectHardware(hardware, details)
	if err == nil || !strings.Contains(err.Error(), `expected "disabled"`) || !strings.Contains(err.Error(), "COLLECTION_STATUS_UNAVAILABLE") {
		t.Fatalf("missing posture diagnostic: %v", err)
	}
	details.Firmware.SecureBoot = truthString("private-unexpected-value")
	err = compareInspectHardware(hardware, details)
	if err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatalf("unsafe posture diagnostic: %v", err)
	}
}
