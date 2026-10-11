//go:build linux

package packaging

import (
	"slices"
	"strings"
	"testing"
)

func TestOSUpdateUnitsAreShippedStaticAndNeverEnabled(t *testing.T) {
	product := agentProduct()
	files, err := product.payloadFiles()
	if err != nil {
		t.Fatal(err)
	}
	for unit, want := range map[string][]string{
		osUpdateUnit: {
			"ExecStart=" + BinaryPath + " os-update run", "ConditionPathExists=/etc/lindm/os-update/policy.binpb",
			"Type=oneshot", "TimeoutStartSec=6h", "Nice=10", "IOSchedulingClass=best-effort", "Wants=network-online.target",
		},
		osUpdateNowUnit: {
			"ExecStart=" + BinaryPath + " os-update run-now", "Type=oneshot", "TimeoutStartSec=6h", "Nice=10", "Wants=network-online.target",
		},
		osUpdateStatusUnit: {
			"ExecStart=" + BinaryPath + " os-update status", "Type=oneshot", "TimeoutStartSec=5min", "PrivateNetwork=yes",
		},
	} {
		if !slices.Contains(product.units, unit) {
			t.Errorf("%s omitted from systemd unit verification", unit)
		}
		found := false
		for _, file := range files {
			if file.name == unit {
				found = file.rel == "usr/lib/systemd/system/"+unit && file.mode == 0o644 && !file.conf
			}
		}
		if !found {
			t.Errorf("%s omitted from the system unit directory", unit)
		}
		data, err := asset(unit)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, line := range want {
			if !strings.Contains(text, "\n"+line+"\n") {
				t.Errorf("%s lacks %q", unit, line)
			}
		}
		// Static units: only the provider timer or the executor starts them.
		// The run units need full package-manager write access.
		for _, forbidden := range []string{"[Install]", "KillMode=", "Restart="} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s must not contain %q", unit, forbidden)
			}
		}
		if unit != osUpdateStatusUnit && strings.Contains(text, "\nProtectSystem=") {
			t.Errorf("%s must not sandbox the native package manager", unit)
		}
	}
	lifecycle, err := asset(product.lifecycleAsset)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(lifecycle), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, "lindm-os-update") {
			t.Errorf("package lifecycle must not manage os-update units: %q", line)
		}
	}
}

func TestOSUpdateParentDirectoriesComeFromTmpfiles(t *testing.T) {
	data, err := asset("tmpfiles.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{
		"d /etc/lindm/os-update 0755 root root -",
		"d /etc/systemd/system/timers.target.d 0755 root root -",
		"d /var/lib/lindm/os-update 0700 root root -",
		"d /run/lindm/os-update 0700 root root -",
	} {
		if !strings.Contains(string(data), "\n"+entry+"\n") {
			t.Errorf("tmpfiles lacks %q", entry)
		}
	}
	lifecycle, err := asset(agentProduct().lifecycleAsset)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lifecycle), `systemd-tmpfiles --create "$TMPFILES"`) {
		t.Fatal("package lifecycle must apply tmpfiles.conf on install")
	}
}
