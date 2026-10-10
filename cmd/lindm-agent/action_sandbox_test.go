//go:build linux

package main

import (
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// The generated exception is a privilege boundary: an escaped device name must
// not admit another device or inject a systemd directive.
func TestActionSandboxRejectsDeviceDirectiveInjection(t *testing.T) {
	for _, path := range []string{"/dev/vda\nPrivateDevices=no", "/dev/vda:/etc", "/dev/%i", "/dev/../etc", "/dev/vda /dev/vdb", "/dev/\"vda", "/etc/passwd"} {
		if _, err := actionSandboxText(&agentv1.DeviceActionProviderConfig{}, []string{path}); err == nil {
			t.Fatalf("admitted device directive injection %q", path)
		}
	}
}

func TestActionSandboxRetainsIsolationAndExactDevices(t *testing.T) {
	cfg := &agentv1.DeviceActionProviderConfig{}
	text, err := actionSandboxText(cfg, []string{"/dev/vda3", "/dev/mapper/control", "/dev/vda3"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "PrivateDevices=yes\nDevicePolicy=closed\n") || strings.Contains(text, "CAP_NET_ADMIN") || strings.Contains(text, "AF_NETLINK") || strings.Contains(text, "AF_INET") {
		t.Fatal("unconfigured action expanded native networking or device access")
	}
	if strings.Count(text, "DeviceAllow=/dev/vda3 rw\n") != 1 || strings.Count(text, "BindPaths=/dev/vda3\n") != 1 || strings.Contains(text, "block-") {
		t.Fatal("device allowlist not exact")
	}
	cfg.AllowQuarantine = true
	text, err = actionSandboxText(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "CAP_NET_ADMIN") || !strings.Contains(text, "AF_NETLINK") || strings.Contains(text, "AF_INET") {
		t.Fatal("quarantine requires netlink but must not enable executor outbound IP")
	}
}
