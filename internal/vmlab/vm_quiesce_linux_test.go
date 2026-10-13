//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

// Regression: on Pop!_OS 24.04 the boot-time com.system76.SystemUpdater ran
// apt-get and held the dpkg frontend lock, so the resource lane's signed agent
// install failed with exit 100. Present units are stopped before they are
// masked; absent units are skipped. Its KillMode=process stop leaves the
// running apt-get (which then held the APT lists lock against the lab's
// fixture repository), so the script waits until no apt-get remains.
func TestLabQuiescePackageUnitsStopsPopUpdater(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + nativeQuote(log) + "\ncase \"$1 $2\" in\n\"cat com.system76.SystemUpdater.service\"|\"cat apt-daily.timer\") exit 0 ;;\ncat\\ *) exit 1 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	// The leftover apt-get is seen twice, then exits; dpkg never runs.
	count := filepath.Join(dir, "pgrep-count")
	pgrep := "#!/bin/sh\nn=$(cat " + nativeQuote(count) + " 2>/dev/null || echo 0)\nprintf 'pgrep %s\\n' \"$*\" >> " + nativeQuote(log) + "\ntest \"$2\" = apt-get || exit 1\nn=$((n+1)); echo \"$n\" > " + nativeQuote(count) + "\ntest \"$n\" -le 2\n"
	if err := os.WriteFile(filepath.Join(dir, "pgrep"), []byte(pgrep), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sleep"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
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
	want := []string{"stop apt-daily.timer", "mask apt-daily.timer", "stop com.system76.SystemUpdater.service", "mask com.system76.SystemUpdater.service",
		"pgrep -x apt-get", "pgrep -x apt-get", "pgrep -x apt-get", "pgrep -x dpkg"}
	if strings.Join(effects, "|") != strings.Join(want, "|") {
		t.Fatalf("quiesce effects %q, want %q", effects, want)
	}
}

// Pop!_OS's pop-zram-config rewrites vm.swappiness at every boot, and
// Tumbleweed's installer assigns net.ipv4.ip_forward in 70-yast.conf, so their
// resources lanes use other keys; every registry override needs a fixture that
// records the key's prior value and a root approval.
func TestRegistryLabSysctlKeysHaveFixtures(t *testing.T) {
	config := new(agentv1.AgentConfig)
	provisionHostResourceRoots(config)
	for _, release := range platform.Releases() {
		key, prior, err := labSysctlKey(release.Lab)
		if err != nil {
			t.Fatalf("%s: %v", release.Key, err)
		}
		net, netPrior, err := labSysctlNetKey(release.Lab)
		if err != nil {
			t.Fatalf("%s: %v", release.Key, err)
		}
		for _, fixture := range [][2]string{{key, prior}, {net, netPrior}} {
			if !strings.Contains(resourceHostFixtureScript, "sysctl -n "+fixture[0]+" > "+fixture[1]+"\n") || !slices.Contains(config.GetSysctlProvider().GetAllowedKeys(), fixture[0]) {
				t.Fatalf("%s lab sysctl key %s lacks its fixture or approval", release.Key, fixture[0])
			}
		}
	}
}

// Pop!_OS's background package frontends took dpkg's frontend lock between a
// lab package's staging and apply; both vendor units are quiesced.
func TestLabQuiesceCoversPopPackageFrontends(t *testing.T) {
	units := strings.Fields(strings.TrimPrefix(strings.SplitN(labQuiescePackageUnits, ";", 2)[0], "for unit in "))
	for _, unit := range []string{"com.system76.SystemUpdater.service", "pop-upgrade.service"} {
		if !slices.Contains(units, unit) {
			t.Fatalf("quiesce units %q lack %s", units, unit)
		}
	}
}
