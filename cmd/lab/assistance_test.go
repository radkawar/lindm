// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/vmlab"
)

func TestAssistanceHoldKeepsCredentialsOutOfStreamedOutput(t *testing.T) {
	dir := t.TempDir()
	access := &vmlab.AssistanceHold{
		ConsoleOrigin: "https://localhost:19444", RelayPort: 19445,
		Username: "console-owner", EnrollmentSecret: "private-enrollment-secret",
		DesktopUser: "desktop-user", DesktopPassword: "private-desktop-password",
		ExpiresAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
		DeviceID:  "device-id", Hostname: "guest", DisplaySocket: "/private/display.sock",
	}
	var stdout bytes.Buffer
	if err := writeAssistanceHold(&stdout, dir, access); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{access.EnrollmentSecret, access.DesktopPassword} {
		if strings.Contains(stdout.String(), secret) {
			t.Fatal("streamed output disclosed owner credentials")
		}
	}
	for _, want := range []string{
		"ssh -L 19444:localhost:19444 -L 19445:localhost:19445 <user>@<this-host>",
		"ssh <user>@<this-host>", "vm assistance-respond -evidence " + dir,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing access instruction %q", want)
		}
	}
	path := filepath.Join(dir, "owner-access")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{access.EnrollmentSecret, access.DesktopPassword} {
		if !strings.Contains(string(data), secret) {
			t.Fatal("owner access file omitted credentials")
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatalf("owner access mode: %v, %v", info, err)
	}
	if err := writeAssistanceHold(&stdout, dir, access); err == nil {
		t.Fatal("existing owner access was overwritten")
	}
}

func TestAssistancePersistentOwnerAccessSurvivesResume(t *testing.T) {
	root, evidence := t.TempDir(), t.TempDir()
	access := &vmlab.AssistanceHold{
		ConsoleOrigin: "https://localhost:19444", RelayPort: 19445,
		Username: "console-owner", EnrollmentSecret: "one-time-secret",
		DesktopUser: "desktop-user", DesktopPassword: "retained-password",
		Persistent: true, OwnerAccessFile: filepath.Join(root, "owner-access"),
	}
	var stdout bytes.Buffer
	if err := writeAssistanceHold(&stdout, evidence, access); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(access.OwnerAccessFile)
	if err != nil {
		t.Fatal(err)
	}
	access.ExistingAccount, access.EnrollmentSecret = true, ""
	stdout.Reset()
	if err := writeAssistanceHold(&stdout, t.TempDir(), access); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(access.OwnerAccessFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("resume replaced existing owner access", err)
	}
	if !strings.Contains(stdout.String(), "existing owner account remains valid") || strings.Contains(stdout.String(), "Owner enrollment:") {
		t.Fatal("resume offered a new owner enrollment")
	}
	if _, err := os.Stat(filepath.Join(evidence, "owner-access")); !os.IsNotExist(err) {
		t.Fatal("persistent credentials were placed in run-scoped evidence")
	}
}

func TestAssistanceRootLockPreventsDestroyAndRecreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if err := openAssistanceDemoRoot(root); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(root, "retained-disk")
	if err := os.WriteFile(disk, []byte("owned state"), 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := lockAssistanceDemo(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := destroyAssistanceDemo(t.Context(), "", root, &bytes.Buffer{}); err == nil {
		t.Fatal("destroy accepted a running named demo")
	}
	if _, err := os.Stat(disk); err != nil {
		t.Fatal("refused destruction removed state", err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if next, err := lockAssistanceDemo(root); err == nil {
		_ = next.Close()
		t.Fatal("deleting state bypassed stable lifecycle lock")
	}
}

func TestAssistanceSchedulerLocksBeforeHostBinding(t *testing.T) {
	work := t.TempDir()
	config := filepath.Join(t.TempDir(), "lab.json")
	data, err := json.Marshal(&labv1.LabConfig{Hosts: []*labv1.LabHost{{
		Name: "local", Transport: "local", Runtime: "native",
		Architectures: []string{"amd64"}, Kvm: true, MaxGuests: 1,
		MaxVcpus: 2, MaxMemoryMib: 4096, WorkDirectory: work,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LINDM_LAB_CONFIG", config)
	root := filepath.Join(work, "demos", "concurrent")
	lock, err := lockAssistanceDemo(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	// A destructor holds the sibling lock after deleting the old root. A
	// concurrent start must not republish a marker/host binding around it.
	err = runScheduledVM(t.Context(), []string{"vm", "assistance", "-hold", "-name", "concurrent", "-manifest", "unopened.json"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "already running or being destroyed") {
		t.Fatalf("scheduler passed lifecycle lock: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("concurrent scheduler recreated demo root", err)
	}
}

// Debian's arm64 kernels cannot observe QEMU virt's TPM, so their encrypted
// goldens are TPM-absent; the assistance lane must be able to select them.
func TestAssistanceAcceptsTPMAbsentVariant(t *testing.T) {
	var stderr bytes.Buffer
	err := runVMAssistance(t.Context(), []string{"-tpm=false"}, &bytes.Buffer{}, &stderr)
	if err == nil || !strings.Contains(err.Error(), "vm assistance requires -manifest") || strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("-tpm=false was not accepted: %v: %s", err, stderr.String())
	}
}

func TestAssistanceTopologySelection(t *testing.T) {
	for _, test := range []struct {
		name, transport, runtime string
		args                     []string
		split                    bool
	}{
		{"remote defaults split", "ssh", "native", []string{"vm", "assistance"}, true},
		{"held remote defaults split", "ssh", "native", []string{"vm", "assistance", "-hold"}, true},
		{"explicit colocated", "ssh", "native", []string{"vm", "assistance", "-colocated"}, false},
		{"explicit false", "ssh", "native", []string{"vm", "assistance", "-colocated=false"}, true},
		{"local unchanged", "local", "native", []string{"vm", "assistance"}, false},
		{"container unchanged", "ssh", "container", []string{"vm", "assistance"}, false},
		{"other lane unchanged", "ssh", "native", []string{"vm", "device-actions"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := &labv1.LabHost{Transport: test.transport, Runtime: test.runtime}
			if got := splitAssistance(host, test.args); got != test.split {
				t.Fatalf("split = %t, want %t", got, test.split)
			}
		})
	}
}

func TestSplitAssistanceHoldPrivateMarkerAndInstructions(t *testing.T) {
	remote := t.TempDir()
	access := &vmlab.AssistanceHold{ConsoleOrigin: "https://localhost:19444", RelayPort: 19445, DeviceID: "device", Hostname: "guest", DesktopUser: "desktop", DesktopPassword: "private-desktop"}
	if err := publishAssistanceHeld(remote, access); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(remote, "held"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private marker: %v, %v", info, err)
	}
	data, err := os.ReadFile(filepath.Join(remote, "held"))
	if err != nil {
		t.Fatal(err)
	}
	var received vmlab.AssistanceHold
	if err := json.Unmarshal(data, &received); err != nil {
		t.Fatal(err)
	}
	if received.EnrollmentSecret != "" || received.DesktopPassword != access.DesktopPassword || received.RemoteEvidenceDir != remote {
		t.Fatal("remote marker did not separate owner enrollment from guest access")
	}
	received.ControllerAddress, received.Username, received.EnrollmentSecret = "192.0.2.10", "console-owner", "local-owner-secret"
	var stdout bytes.Buffer
	local := t.TempDir()
	if err := writeAssistanceHold(&stdout, local, &received); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-L 19445:192.0.2.10:19445 <user>@<controller-host>", "ssh <user>@<lab-host>", "-evidence " + remote} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing split instruction %q", want)
		}
	}
	for _, secret := range []string{received.EnrollmentSecret, received.DesktopPassword} {
		if strings.Contains(stdout.String(), secret) {
			t.Fatal("split handoff exposed a secret")
		}
	}
	if _, err := os.Stat(filepath.Join(remote, "owner-access")); !os.IsNotExist(err) {
		t.Fatal("owner access appeared remotely")
	}
}

func TestAssistanceControllerAddressRejectsNonRoutedAddress(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1", "0.0.0.0", "::1", "239.0.0.1", "controller.example"} {
		if _, err := assistanceControllerIPv4(address); err == nil {
			t.Errorf("accepted %q", address)
		}
	}
	if _, err := assistanceControllerIPv4("192.0.2.10"); err != nil {
		t.Fatal(err)
	}
}

func TestAssistanceNativeEnrollmentUsesGuestArchitecture(t *testing.T) {
	for _, test := range []struct{ guest, want string }{
		{"amd64", "amd64"}, {"x86_64", "amd64"},
		{"arm64", "arm64"}, {"aarch64", "arm64"},
	} {
		t.Run(test.guest, func(t *testing.T) {
			options, err := assistanceEnrollmentOptions(test.guest, "/private/source")
			if err != nil {
				t.Fatal(err)
			}
			if len(options.NativeEnrollmentArchitectures) != 1 || options.NativeEnrollmentArchitectures[0] != test.want {
				t.Fatalf("guest %s got native publication architectures %v", test.guest, options.NativeEnrollmentArchitectures)
			}
			if options.NativeEnrollmentSourceRepository != "/private/source" {
				t.Fatal("native publication lost selected build source")
			}
		})
	}
	if _, err := assistanceEnrollmentOptions("unknown", "/private/source"); err == nil {
		t.Fatal("unsupported guest architecture silently selected a host package")
	}
}

func TestRebootQualificationRejectsHeldFixturesBeforeOpeningThem(t *testing.T) {
	for _, invalid := range [][]string{{"-hold"}, {"-name", "must-not-open"}, {"-scenarios", "view"}} {
		args := append([]string{"vm", "assistance", "-reboot-policy"}, invalid...)
		var output bytes.Buffer
		// A nil host would panic if split setup reached host/fixture access.
		if err := runSplitAssistance(t.Context(), nil, "", "", args, &output, &output); err == nil || !strings.Contains(err.Error(), "disposable non-held") {
			t.Fatalf("split fixture opened for %v: %v", args, err)
		}
		if err := runVMAssistance(t.Context(), args[2:], &output, &output); err == nil || !strings.Contains(err.Error(), "disposable non-held") {
			t.Fatalf("colocated fixture opened for %v: %v", args, err)
		}
	}
	if err := validateRebootPolicyFlags(true, false, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := validateRebootPolicyFlags(false, true, "existing", "view"); err != nil {
		t.Fatal("ordinary assistance flags changed", err)
	}
}
