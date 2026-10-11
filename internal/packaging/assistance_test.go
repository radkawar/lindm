//go:build linux

package packaging

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
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
