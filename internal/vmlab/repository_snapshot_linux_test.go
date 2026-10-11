//go:build linux

package vmlab

import "testing"

func TestSnapshotSolverInputsRequireExactVersionSelectors(t *testing.T) {
	for _, input := range []string{"kernel-default", "kernel-default=7.2.9-1.1", "kernel-default=0:7.2.9-1.1", "package=2:1.0~rc1+git.2-3", "libtss2-esys0", "patterns-base-base", "grub2-x86_64-efi-bls"} {
		if !validSnapshotSolverInput(input) {
			t.Errorf("valid exact input rejected: %q", input)
		}
	}
	for _, input := range []string{"", "=7.2.9-1.1", "kernel-default=", "kernel-default==7.2.9-1.1", "kernel-default>=7.2.9", "kernel-default<7.2.9", "kernel-default=*", "kernel-default=*:7.2.9", "kernel-default=1:2:7.2.9", "kernel-default=7.2.9;id", "kernel-default=7.2.9\n", "kernel-default=7.2.9 1.1", "--force", "kernel-default=--force"} {
		if validSnapshotSolverInput(input) {
			t.Errorf("unsafe or nonexact selector accepted: %q", input)
		}
	}
	if snapshotPackageName.MatchString("kernel-default=7.2.9-1.1") {
		t.Fatal("base inventory package-name validation accepted a solver selector")
	}
}
