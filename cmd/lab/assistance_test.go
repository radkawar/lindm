package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
