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

// Only an assistance run with -hold escapes the lane deadline and remote hosts;
// the last occurrence wins, as in the flag package.
func TestVMHoldsOnlyHeldAssistance(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"vm", "assistance", "-manifest", "m", "-hold"}, true},
		{[]string{"vm", "assistance", "--hold=true"}, true},
		{[]string{"vm", "assistance", "-hold", "-hold=false"}, false},
		{[]string{"vm", "assistance", "-hold=maybe"}, false},
		{[]string{"vm", "assistance", "-evidence", "dir"}, false},
		{[]string{"vm", "device-actions", "-hold"}, false},
	} {
		if got := vmHolds(tc.args); got != tc.want {
			t.Errorf("vmHolds(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
