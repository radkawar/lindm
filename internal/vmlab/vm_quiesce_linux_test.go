//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: on Pop!_OS 24.04 the boot-time com.system76.SystemUpdater ran
// apt-get and held the dpkg frontend lock, so the resource lane's signed agent
// install failed with exit 100. Present units are stopped before they are
// masked; absent units are skipped.
func TestLabQuiescePackageUnitsStopsPopUpdater(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + nativeQuote(log) + "\ncase \"$1 $2\" in\n\"cat com.system76.SystemUpdater.service\"|\"cat apt-daily.timer\") exit 0 ;;\ncat\\ *) exit 1 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", labQuiescePackageUnits)
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("quiesce script failed: %v: %s", err, out)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var effects []string
	for _, call := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !strings.HasPrefix(call, "cat ") {
			effects = append(effects, call)
		}
	}
	want := []string{"stop apt-daily.timer", "mask apt-daily.timer", "stop com.system76.SystemUpdater.service", "mask com.system76.SystemUpdater.service"}
	if strings.Join(effects, "|") != strings.Join(want, "|") {
		t.Fatalf("quiesce effects %q, want %q", effects, want)
	}
}
