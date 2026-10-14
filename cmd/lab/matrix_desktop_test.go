// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
)

// Desktop lanes default to GNOME. Matrix cells of a release whose media
// install only another desktop boot that desktop (Linux Mint 22.3's
// tpm-reference-repair cell ran with GNOME, which its Ubiquity recipe
// refuses); GNOME releases and non-desktop lanes are unchanged.
func TestMatrixDesktopCellsBootTheReleaseDesktop(t *testing.T) {
	repair := &labv1.MatrixCell{Name: "tpm-reference-repair", Lane: "device-actions", Args: []string{"-scenario=encryption", "-encryption-phase=tpm-repair"}}
	assistance := &labv1.MatrixCell{Name: "assistance", Lane: "assistance"}
	services := &labv1.MatrixCell{Name: "services", Lane: "services"}
	run := &matrixRun{root: t.TempDir(), cache: t.TempDir()}
	for _, tc := range []struct {
		key  string
		spec *labv1.MatrixCell
		want string
	}{
		{"linuxmint-22.3", repair, "cinnamon"},
		{"linuxmint-22.3", assistance, "cinnamon"},
		{"pop-24.04", repair, "cosmic"},
		{"omarchy-4.0.4", repair, "hyprland"},
		{"ubuntu-24.04", repair, ""},
		{"fedora-44", assistance, ""},
		{"linuxmint-22.3", services, ""},
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
		if got := labhost.FlagValue(args, "desktop"); got != tc.want {
			t.Fatalf("%s %s: desktop %q, want %q", tc.key, tc.spec.GetName(), got, tc.want)
		}
	}
}
