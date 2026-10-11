//go:build linux

package main

import (
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestVMRequiresKVMNeverFallsBackToForeignTCGForCapacity(t *testing.T) {
	cfg := &labv1.LabConfig{Hosts: []*labv1.LabHost{
		{Name: "local", Architectures: []string{"amd64"}, Kvm: true},
		{Name: "dgx20", Architectures: []string{"arm64"}, Kvm: true},
	}}
	for _, tc := range []struct {
		command, accelerator, architecture string
		want                               bool
	}{
		// Lanes whose own flag defaults to kvm stay native while local is full.
		{"encrypted", "", "amd64", true},
		{"device-actions", "", "amd64", true},
		{"assistance", "", "amd64", true},
		{"inspect-storage", "", "amd64", true},
		// Architecture-defaulted lanes stay native when a native host exists.
		{"inspect", "", "amd64", true},
		{"resources", "", "arm64", true},
		// Only an architecture no configured host runs natively may use TCG.
		{"inspect", "", "riscv64", false},
		// Explicit operator choices are honoured.
		{"encrypted", "tcg", "amd64", false},
		{"lifecycle", "kvm", "arm64", true},
		// Fixed-hardware lanes always require native KVM.
		{"updates", "", "amd64", true},
	} {
		if got := vmRequiresKVM(cfg, tc.command, tc.accelerator, tc.architecture); got != tc.want {
			t.Errorf("%s accelerator=%q arch=%s: requireKVM=%v, want %v", tc.command, tc.accelerator, tc.architecture, got, tc.want)
		}
	}
}
