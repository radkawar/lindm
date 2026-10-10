package vmlab

import (
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestHardwareForManifest(t *testing.T) {
	for _, tc := range []struct{ guest, host, canonical, accelerator string }{
		{"arm64", "arm64", "aarch64", "kvm"},
		{"aarch64", "arm64", "aarch64", "kvm"},
		{"amd64", "amd64", "x86_64", "kvm"},
		{"arm64", "amd64", "aarch64", "tcg"},
	} {
		options := &VMHardwareOptions{Firmware: &EncryptedFirmwareOptions{Code: "/firmware/code", Vars: "/firmware/vars", Package: "test-firmware", Version: "1"}}
		h, err := hardwareForManifest(&labv1.ImageManifest{Architecture: tc.guest}, options, tc.host)
		if err != nil || h.Architecture != tc.canonical || h.Accelerator != tc.accelerator {
			t.Fatalf("%+v: hardware=%+v error=%v", tc, h, err)
		}
	}
	explicit := &VMHardwareOptions{Architecture: "x86_64", Accelerator: "tcg"}
	if _, err := hardwareForManifest(&labv1.ImageManifest{Architecture: "arm64"}, explicit, "arm64"); err == nil {
		t.Fatal("accepted explicit architecture mismatch")
	}
	if explicit.Architecture != "x86_64" {
		t.Fatal("mutated caller options")
	}
	if _, err := hardwareForManifest(nil, nil, "arm64"); err == nil {
		t.Fatal("accepted nil manifest")
	}
}
