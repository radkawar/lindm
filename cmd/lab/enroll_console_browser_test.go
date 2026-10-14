// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/platform"
)

func TestConsoleBrowserConfigCustody(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "capture.json")
	data := []byte(`{"password":"private-owner-secret","origin":"https://localhost:18444"}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var cfg acceptanceBrowserConfig
	if err := readConsoleBrowserJSON(path, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "private-owner-secret" || cfg.Origin != "https://localhost:18444" {
		t.Fatal("browser config changed")
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := readConsoleBrowserJSON(link, &cfg); err == nil {
		t.Fatal("symlink browser credentials accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := readConsoleBrowserJSON(path, &cfg); err == nil {
		t.Fatal("public browser credentials accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"password":"private-owner-secret"`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := readConsoleBrowserJSON(path, &cfg); err == nil || strings.Contains(err.Error(), "private-owner-secret") {
		t.Fatal("malformed config accepted or credential disclosed")
	}
}

func TestConsoleEnrollmentCapturesMatchingNativeFamily(t *testing.T) {
	for _, test := range []struct {
		backend platform.Backend
		family  string
	}{
		{platform.BackendAPT, "apt"},
		{platform.BackendDNF4, "dnf"},
		{platform.BackendDNF5, "dnf"},
		{platform.BackendPacman, "pacman"},
		{platform.BackendZypper, "zypper"},
	} {
		family, err := consoleEnrollmentFamily(test.backend)
		if err != nil || family != test.family {
			t.Fatalf("clipboard capture family differs from native installer: %q %v", family, err)
		}
	}
	if _, err := consoleEnrollmentFamily(platform.BackendNone); err == nil {
		t.Fatal("unknown package family defaulted to APT")
	}
}
