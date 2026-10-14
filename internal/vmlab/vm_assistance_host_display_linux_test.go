// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAssistanceHostEnvironmentIsolatesPhysicalDesktop(t *testing.T) {
	inherited := []string{
		"PATH=/usr/bin", "HOME=/home/operator", "DISPLAY=:0", "DISPLAY=:1",
		"WAYLAND_DISPLAY=wayland-0", "XAUTHORITY=/private/physical-cookie",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"DBUS_STARTER_ADDRESS=unix:path=/run/user/1000/bus", "DBUS_STARTER_BUS_TYPE=session",
		"XDG_CURRENT_DESKTOP=GNOME", "XDG_SESSION_TYPE=wayland", "GTK_USE_PORTAL=1",
		"GDK_BACKEND=wayland", "LANG=de_DE.UTF-8", "LC_ALL=de_DE.UTF-8",
	}
	before := slices.Clone(inherited)
	got := assistanceHostEnvironment(inherited, ":12345", "/private/lane/xauthority")
	if !slices.Equal(inherited, before) {
		t.Fatal("environment filtering mutated the parent environment")
	}
	values := make(map[string]string)
	for _, item := range got {
		key, value, found := strings.Cut(item, "=")
		if !found {
			t.Fatalf("malformed environment item: %q", item)
		}
		if _, duplicate := values[key]; duplicate {
			t.Fatalf("ambiguous environment key: %s", key)
		}
		values[key] = value
	}
	for _, key := range []string{"WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE", "XDG_CURRENT_DESKTOP"} {
		if _, present := values[key]; present {
			t.Errorf("physical desktop environment retained: %s", key)
		}
	}
	for key, want := range map[string]string{
		"PATH": "/usr/bin", "HOME": "/home/operator", "DISPLAY": ":12345",
		"XAUTHORITY": "/private/lane/xauthority", "XDG_SESSION_TYPE": "x11",
		"GDK_BACKEND": "x11", "GTK_USE_PORTAL": "0", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
	} {
		if values[key] != want {
			t.Errorf("%s = %q, want %q", key, values[key], want)
		}
	}
}

// Chromium titles the File System Access save dialog with its warning, not
// "Save"; only the browser's own windows are excluded (layers-fedora44-files-05).
func TestBrowserWindowTitleExcludesOnlyBrowserWindows(t *testing.T) {
	for _, name := range []string{"lindm - Google Chrome for Testing", "Remote assistance - Chromium"} {
		if !browserWindowTitle(name) {
			t.Errorf("%q is a browser window", name)
		}
	}
	for _, name := range []string{"Warning: this site can see edits you make", "Save File", "Save"} {
		if browserWindowTitle(name) {
			t.Errorf("%q is the save picker", name)
		}
	}
}

// The browser saves outside Chromium's blocklisted ~/.cache; the result is
// moved into evidence without following links or replacing files.
func TestMoveOperatorDestination(t *testing.T) {
	dir := t.TempDir()
	staged, target := filepath.Join(dir, "staged"), filepath.Join(dir, "target")
	if err := moveOperatorDestination(staged, target); err != nil {
		t.Fatalf("a refused save moved something: %v", err)
	}
	if err := os.WriteFile(staged, []byte("saved bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := moveOperatorDestination(staged, target); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "saved bytes" {
		t.Fatalf("target = %q, %v", data, err)
	}
	if _, err := os.Lstat(staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staged file kept")
	}
	if err := os.WriteFile(staged, []byte("again"), 0o600); err != nil {
		t.Fatal(err)
	}
	if moveOperatorDestination(staged, target) == nil {
		t.Fatal("an existing evidence file was replaced")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if moveOperatorDestination(link, filepath.Join(dir, "other")) == nil {
		t.Fatal("a staged symlink was followed")
	}
}
