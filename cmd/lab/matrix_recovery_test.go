// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
)

// A release whose owned-boot UKI fixture is unavailable (Debian 12, Ubuntu
// 22.04, or only on one architecture: Ubuntu 24.04 aarch64) runs the matrix
// recovery cell through measured GRUB; others keep the cell's owned-boot
// arguments, and non-recovery cells are untouched.
func TestMatrixRecoveryCellUsesMeasuredGRUBWithoutOwnedBoot(t *testing.T) {
	recovery := &labv1.MatrixCell{Name: "recovery-sanitize", Lane: "device-actions", Args: []string{"-scenario=wipe", "-wipe-phase=recovery-nvme"}}
	wipe := &labv1.MatrixCell{Name: "device-actions", Lane: "device-actions", Args: []string{"-scenario=wipe"}}
	run := &matrixRun{root: t.TempDir(), cache: t.TempDir()}
	for _, tc := range []struct {
		key, architecture string
		spec              *labv1.MatrixCell
		want              string
	}{
		{"debian-12", "x86_64", recovery, "measured-grub"},
		{"ubuntu-22.04", "x86_64", recovery, "measured-grub"},
		{"ubuntu-24.04", "aarch64", recovery, "measured-grub"},
		{"ubuntu-24.04", "x86_64", recovery, ""},
		{"debian-13", "x86_64", recovery, ""},
		{"debian-12", "x86_64", wipe, ""},
	} {
		release, ok := platform.Lookup(tc.key)
		if !ok {
			t.Fatalf("%s missing from the registry", tc.key)
		}
		image := &labmatrix.Manifest{Path: "lab/images/x.json"}
		args, err := run.laneArgs(&labmatrix.Cell{Release: release, Spec: tc.spec, Architecture: tc.architecture, Manifest: image, Recovery: image}, "base")
		if err != nil {
			t.Fatal(err)
		}
		if got := labhost.FlagValue(args, "recovery-boot-mode"); got != tc.want {
			t.Fatalf("%s %s %s: recovery boot mode %q, want %q", tc.key, tc.architecture, tc.spec.GetName(), got, tc.want)
		}
	}
}

// The recovery-sanitize cell selects measured GRUB from a declared stock GRUB
// chain, except on an architecture whose signed GRUB records no measurements
// (EL aarch64) or whose kernel cannot bind the lab's TPM (Debian aarch64):
// there the owned-boot UKI fixture runs.
func TestMatrixRecoverySanitizeSkipsUnmeasuredGRUB(t *testing.T) {
	cell := &labv1.MatrixCell{Name: "recovery-sanitize", Lane: "device-actions", Capabilities: []string{string(platform.RecoverySanitize)}, Args: []string{"-scenario=wipe", "-wipe-phase=recovery-nvme"}}
	run := &matrixRun{root: t.TempDir(), cache: t.TempDir()}
	for _, tc := range []struct{ key, architecture, want string }{
		{"rhel-9", "x86_64", "measured-grub"},
		{"rhel-9", "aarch64", ""},
		{"rhel-10", "aarch64", ""},
		{"almalinux-10", "aarch64", ""},
		{"ubuntu-24.04", "aarch64", "measured-grub"},
		{"opensuse-tumbleweed", "aarch64", "measured-grub"},
		{"debian-13", "x86_64", "measured-grub"},
		{"debian-13", "aarch64", ""},
	} {
		release, ok := platform.Lookup(tc.key)
		if !ok {
			t.Fatalf("%s missing from the registry", tc.key)
		}
		image := &labmatrix.Manifest{Path: "lab/images/x.json"}
		args, err := run.laneArgs(&labmatrix.Cell{Release: release, Spec: cell, Architecture: tc.architecture, Manifest: image, Recovery: image}, "base")
		if err != nil {
			t.Fatal(err)
		}
		if got := labhost.FlagValue(args, "recovery-boot-mode"); got != tc.want {
			t.Fatalf("%s %s: recovery boot mode %q, want %q", tc.key, tc.architecture, got, tc.want)
		}
	}
}
