//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvisoryRPMOracleNeverInterpolatesVendorCode(t *testing.T) {
	payload := "%{lua:os.execute('touch /tmp/forbidden')}"
	command, err := vmAdvisoryCompareCommand("rpm", payload, "1:2-3")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(command, payload) || strings.Contains(command, "os.execute") || strings.Contains(command, "/tmp/forbidden") || !strings.Contains(command, "rpm.ver(string.char(") {
		t.Fatalf("vendor version was interpreted as RPM/Lua code: %s", command)
	}
	if got := advisoryLuaBytes("1:2-3"); got != "string.char(49,58,50,45,51)" {
		t.Fatalf("native EVR changed in literal transport: %s", got)
	}
	if _, err := vmAdvisoryCompareCommand("unknown", "1", "2"); err == nil {
		t.Fatal("unsupported native comparator accepted")
	}
}

// The dpkg oracle runs the same command line natively; vendor strings stay
// shell data and dpkg's exit-status ordering becomes the -1/0/1 contract.
func TestAdvisoryDpkgOracleOrdersNativelyWithoutInterpolation(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("native dpkg unavailable")
	}
	marker := filepath.Join(t.TempDir(), "forbidden")
	for _, payload := range []string{"$(touch " + marker + ")", "'; touch " + marker + "; '", "`touch " + marker + "`"} {
		command, err := vmAdvisoryCompareCommand("dpkg", payload, "1.0")
		if err != nil {
			t.Fatal(err)
		}
		_ = exec.Command("sh", "-c", command).Run()
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("vendor version was executed: %s", command)
		}
	}
	for _, c := range []struct {
		a, b string
		want string
	}{
		{"3.5.5-1ubuntu3.5", "3.5.5-1ubuntu3.7", "-1"},
		{"1:2.0~rc1-1", "1:2.0~rc1-1", "0"},
		{"1:1.0-1", "2.0-1", "1"},
	} {
		command, err := vmAdvisoryCompareCommand("dpkg", c.a, c.b)
		if err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("sh", "-c", command).Output()
		if err != nil || strings.TrimSpace(string(output)) != c.want {
			t.Fatalf("dpkg %s vs %s = %q, %v; want %s", c.a, c.b, output, err, c.want)
		}
	}
}
