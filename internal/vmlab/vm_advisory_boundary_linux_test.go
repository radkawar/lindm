//go:build linux

package vmlab

import (
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
