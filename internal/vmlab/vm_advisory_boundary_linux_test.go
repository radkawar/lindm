// SPDX-License-Identifier: Apache-2.0

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
	if strings.Contains(command, payload) || strings.Contains(command, "os.execute") || strings.Contains(command, "/tmp/forbidden") || !strings.Contains(command, "print(cmp(string.char(") {
		t.Fatalf("vendor version was interpreted as RPM/Lua code: %s", command)
	}
	if got := advisoryLuaBytes("1:2-3"); got != "string.char(49,58,50,45,51)" {
		t.Fatalf("native EVR changed in literal transport: %s", got)
	}
	if _, err := vmAdvisoryCompareCommand("unknown", "1", "2"); err == nil {
		t.Fatal("unsupported native comparator accepted")
	}
}

// The RPM oracle runs natively with rpm.ver (RPM >=4.17) and, as on EL 9's
// RPM 4.16, without it; both paths must give rpmVersionCompare's ordering.
func TestAdvisoryRPMOracleOrdersWithAndWithoutRPMVer(t *testing.T) {
	if _, err := exec.LookPath("rpm"); err != nil {
		t.Skip("native rpm unavailable")
	}
	for _, c := range []struct{ a, b, want string }{
		{"1:3.0.7-27.el9_4", "1:3.0.7-28.el9_4", "-1"},
		{"1:3.0.7-28.el9_4", "1:3.0.7-28.el9_4", "0"},
		{"1:3.0.7-29.el9_4", "1:3.0.7-28.el9_4", "1"},
		{"3.0.7-29.el9", "1:3.0.7-1.el9", "-1"},
		{"0:2.9-1", "2.10-1", "-1"},
		{"1.0~rc1-1", "1.0-1", "-1"},
		{"5.14.0-503.11.1.el9_5", "5.14.0-503.9.1.el9_5", "1"},
	} {
		command, err := vmAdvisoryCompareCommand("rpm", c.a, c.b)
		if err != nil {
			t.Fatal(err)
		}
		for _, variant := range []string{command, strings.Replace(command, "%{lua:", "%{lua:rpm.ver=nil;", 1)} {
			output, err := exec.Command("sh", "-c", variant).Output()
			if err != nil || strings.TrimSpace(string(output)) != c.want {
				t.Fatalf("rpm %s vs %s = %q, %v; want %s (%s)", c.a, c.b, output, err, c.want, variant)
			}
		}
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
