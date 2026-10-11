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
