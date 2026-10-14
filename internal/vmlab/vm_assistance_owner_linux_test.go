// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAssistanceOwnerAccessRefusesIncompleteAndPublicFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner-access")
	if exists, err := AssistanceOwnerAccessExists(path); err != nil || exists {
		t.Fatalf("absent owner access: %v %v", exists, err)
	}
	if err := os.WriteFile(path, []byte("Enrollment URL: https://localhost/enroll\n"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := AssistanceOwnerAccessExists(path); err == nil {
		t.Fatal("partial access was accepted as resumable")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	access := &AssistanceHold{ConsoleOrigin: "https://localhost:19444", Username: "owner", EnrollmentSecret: "private-enrollment", DesktopUser: "desktop", DesktopPassword: "private-desktop"}
	if err := WriteAssistanceOwnerAccess(path, access); err != nil {
		t.Fatal(err)
	}
	if exists, err := AssistanceOwnerAccessExists(path); err != nil || !exists {
		t.Fatalf("complete access: %v %v", exists, err)
	}
	if err := WriteAssistanceOwnerAccess(path, access); err == nil {
		t.Fatal("replaced original enrollment")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("credential staging leaked: %v %v", entries, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := AssistanceOwnerAccessExists(path); err == nil {
		t.Fatal("public credentials accepted")
	}
}
