//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDemoPackageHolderParsesProbe(t *testing.T) {
	for _, test := range []struct {
		line string
		want demoPackageHolder
		ok   bool
	}{
		{"none", demoPackageHolder{}, true},
		{"unit apt-daily-upgrade.service 1234 unattended-upgr", demoPackageHolder{Kind: "unit", Name: "apt-daily-upgrade.service", PID: 1234, Comm: "unattended-upgr"}, true},
		{"lock /var/lib/dpkg/lock-frontend 77 apt-get", demoPackageHolder{Kind: "lock", Name: "/var/lib/dpkg/lock-frontend", PID: 77, Comm: "apt-get"}, true},
		{"unit apt-daily.service 0 unknown", demoPackageHolder{}, false},
		{"", demoPackageHolder{}, false},
		{"busy", demoPackageHolder{}, false},
	} {
		got, err := parseDemoPackageHolder(test.line)
		if (err == nil) != test.ok || got != test.want {
			t.Errorf("parse %q = %+v, %v; want %+v ok=%t", test.line, got, err, test.want, test.ok)
		}
	}
}

// The probe reports a real process holding the dpkg frontend lock through
// /proc/locks; systemd units are observed separately on the guest.
func TestDemoPackageHolderProbeNamesLockHolder(t *testing.T) {
	for _, tool := range []string{"lslocks", "flock", "systemctl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s unavailable: %v", tool, err)
		}
	}
	root := t.TempDir()
	lock := filepath.Join(root, "lock-frontend")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Isolate from the test host's own apt units and dpkg database.
	probe := strings.NewReplacer("apt-daily-upgrade.service apt-daily.service", "lindm-test-absent.service", "/var/lib/dpkg/lock-frontend", lock, "/var/lib/dpkg/lock;", filepath.Join(root, "absent")+";").Replace(demoPackageHolderProbe)
	holder := exec.Command("flock", lock, "sleep", "30")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Process.Kill(); _ = holder.Wait() })
	for range 100 {
		output, err := exec.Command("sh", "-eu", "-c", probe).Output()
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseDemoPackageHolder(strings.TrimSpace(string(output)))
		if err != nil {
			t.Fatal(err)
		}
		if got.Kind == "lock" {
			if got.Name != lock || got.PID != holder.Process.Pid {
				t.Fatalf("holder = %+v, want lock %s pid %d", got, lock, holder.Process.Pid)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("probe never observed the held lock")
}
