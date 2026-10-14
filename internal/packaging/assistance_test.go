// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestSessionHelperIsAPackagedUserUnit(t *testing.T) {
	product := agentProduct()
	if !slices.Contains(product.userUnits, sessionUnit) || slices.Contains(product.units, sessionUnit) {
		t.Fatal("session helper must be verified as a user unit, not a system unit")
	}
	files, err := product.payloadFiles()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range files {
		if file.name == sessionUnit {
			found = file.rel == "usr/lib/systemd/user/"+sessionUnit && file.mode == 0o644 && !file.conf
		}
	}
	if !found {
		t.Fatal("session helper omitted from the user unit directory")
	}
}

// Cinnamon 6.6 never activates graphical-session.target, so the WantedBy
// link alone leaves the helper stopped and the desktop silent, not even
// refusing visibly. The packaged XDG autostart entry starts the enabled user
// unit from such session managers; systemd's generator must skip it where the
// target already starts the unit.
func TestSessionHelperAutostartsWithoutGraphicalSessionTarget(t *testing.T) {
	files, err := agentProduct().payloadFiles()
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(files, func(file payloadFile) bool { return "/"+file.rel == sessionAutostartPath })
	if index < 0 || files[index].mode != 0o644 || !files[index].conf {
		t.Fatal("autostart entry must be a packaged 0644 configuration file under /etc/xdg/autostart")
	}
	body, err := asset(files[index].name)
	if err != nil {
		t.Fatal(err)
	}
	entry := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	if !scanner.Scan() || scanner.Text() != "[Desktop Entry]" {
		t.Fatal("autostart file does not start with the [Desktop Entry] group")
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "[") {
			t.Fatalf("unexpected autostart line %q", line)
		}
		entry[key] = value
	}
	if entry["Type"] != "Application" || entry["NoDisplay"] != "true" || entry["X-systemd-skip"] != "true" || entry["Hidden"] != "" || entry["OnlyShowIn"] != "" {
		t.Fatalf("autostart entry would not run under every session manager that lacks the target: %v", entry)
	}
	exec := entry["Exec"]
	if !strings.Contains(exec, "systemctl --user --quiet is-enabled "+sessionUnit+" &&") || !strings.Contains(exec, "systemctl --user start --no-block "+sessionUnit) || strings.Contains(exec, "/usr/libexec/lindm") {
		t.Fatalf("autostart must start the hardened, globally enabled user unit, never the helper directly: %q", exec)
	}
}

func TestPackagedUnitsVerifyInTheirManagerScope(t *testing.T) {
	requireNativeTools(t, "systemd-analyze")
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	ok, _, err := verifyUnits(context.Background(), work, agentProduct())
	if err != nil || !ok {
		t.Fatalf("agent system and user units: ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(work, "units-user", sessionUnit)); err != nil {
		t.Fatalf("user unit was not verified: %v", err)
	}
}

// The packaged overlay's identity must match its install directory, the GNOME
// Shell releases the platform registry supports, and the session helper's
// D-Bus contract (internal/agent/desktop/overlay_linux.go).
func TestOverlayExtensionAssetsMatchInstallAndHelperContract(t *testing.T) {
	data, err := assetFS.ReadFile("assets/lindm-overlay-metadata.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		UUID         string   `json:"uuid"`
		ShellVersion []string `json:"shell-version"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.UUID != filepath.Base(overlayExtensionDir) {
		t.Fatalf("extension uuid %q does not name its directory %s", metadata.UUID, overlayExtensionDir)
	}
	for _, version := range []string{"46", "50"} {
		if !slices.Contains(metadata.ShellVersion, version) {
			t.Fatalf("extension does not declare GNOME Shell %s: %v", version, metadata.ShellVersion)
		}
	}
	script, err := assetFS.ReadFile("assets/lindm-overlay-extension.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`const BUS_NAME = ["']dev\.lindm\.AssistOverlay["']`, `const OBJECT_PATH = ["']/dev/lindm/AssistOverlay["']`, `<interface name="dev\.lindm\.AssistOverlay1">`, `reactive: false,\s+can_focus: false`, `const HELPER = ["']` + regexp.QuoteMeta(BinaryPath) + `["']`, `ClaimAsync\(`, `DrawAsync\(`, `ClearAsync\(`} {
		if !regexp.MustCompile(want).Match(script) {
			t.Fatalf("extension lacks %s", want)
		}
	}
}
