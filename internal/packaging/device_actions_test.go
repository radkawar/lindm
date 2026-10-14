// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"slices"
	"strings"
	"testing"
)

func TestLiveRootPoweroffUnitIsPackagedButNeverAutoStarted(t *testing.T) {
	product := agentProduct()
	if !slices.Contains(product.units, poweroffUnit) {
		t.Fatal("poweroff helper omitted from systemd unit verification")
	}
	files, err := product.payloadFiles()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range files {
		if file.name == poweroffUnit {
			found = file.rel == "usr/lib/systemd/system/"+poweroffUnit && file.mode == 0o644
		}
	}
	if !found {
		t.Fatal("poweroff helper omitted from package payload")
	}
	unit, err := asset(poweroffUnit)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"Type=notify", "NotifyAccess=main", "DefaultDependencies=no",
		"IgnoreOnIsolate=yes", "RefuseManualStop=yes", "Restart=no",
		"FailureAction=poweroff-force", "SuccessAction=poweroff-force", "RuntimeMaxSec=120s",
		"ExecStart=" + BinaryPath + " live-root-poweroff",
		"CapabilityBoundingSet=CAP_SYS_BOOT CAP_IPC_LOCK CAP_WAKE_ALARM", "PrivateDevices=yes",
		"RestrictAddressFamilies=AF_UNIX", "MemorySwapMax=0",
		"LimitMEMLOCK=infinity", "LimitCORE=0", "OOMScoreAdjust=-1000",
		"ProtectClock=no", "SystemCallFilter=@system-service reboot", "SystemCallFilter=~@clock",
	} {
		if !strings.Contains(string(unit), "\n"+required+"\n") {
			t.Errorf("missing armed helper boundary %q", required)
		}
	}
	for _, forbidden := range []string{"[Install]", "PartOf=", "Requires=", "DeviceAllow=", "\nProtectClock=yes\n", "CAP_SYS_TIME"} {
		if strings.Contains(string(unit), forbidden) {
			t.Errorf("armed helper must not inherit dependency/device authority %q", forbidden)
		}
	}
	lifecycle, err := asset(product.lifecycleAsset)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(lifecycle), poweroffUnit) {
		t.Fatal("package lifecycle must never arm the irreversible poweroff deadline")
	}
}
