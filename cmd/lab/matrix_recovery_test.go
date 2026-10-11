package main

import (
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
)

// A release whose owned-boot UKI fixture is unavailable (Debian 12, Ubuntu
// 22.04) runs the matrix recovery cell through measured GRUB; others keep the
// cell's owned-boot arguments, and non-recovery cells are untouched.
func TestMatrixRecoveryCellUsesMeasuredGRUBWithoutOwnedBoot(t *testing.T) {
	recovery := &labv1.MatrixCell{Name: "recovery-sanitize", Lane: "device-actions", Args: []string{"-scenario=wipe", "-wipe-phase=recovery-nvme"}}
	wipe := &labv1.MatrixCell{Name: "device-actions", Lane: "device-actions", Args: []string{"-scenario=wipe"}}
	run := &matrixRun{root: t.TempDir(), cache: t.TempDir()}
	for _, tc := range []struct {
		key  string
		spec *labv1.MatrixCell
		want string
	}{
		{"debian-12", recovery, "measured-grub"},
		{"ubuntu-22.04", recovery, "measured-grub"},
		{"debian-13", recovery, ""},
		{"debian-12", wipe, ""},
	} {
		release, ok := platform.Lookup(tc.key)
		if !ok {
			t.Fatalf("%s missing from the registry", tc.key)
		}
		image := &labmatrix.Manifest{Path: "lab/images/x.json"}
		args, err := run.laneArgs(&labmatrix.Cell{Release: release, Spec: tc.spec, Architecture: "x86_64", Manifest: image, Recovery: image}, "base")
		if err != nil {
			t.Fatal(err)
		}
		if got := labhost.FlagValue(args, "recovery-boot-mode"); got != tc.want {
			t.Fatalf("%s %s: recovery boot mode %q, want %q", tc.key, tc.spec.GetName(), got, tc.want)
		}
	}
}
