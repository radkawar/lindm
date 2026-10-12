//go:build linux

package vmlab

import (
	"strings"
	"testing"
)

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

// Closure capture requests the installer's locale; a different AutoYaST
// <language> would let YaST select "-lang" RPMs the closure lacks.
func TestCaptureLocaleMatchesTumbleweedInstaller(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	recipe, err := tumbleweedInstallerRecipe("/dev/vda", "aarch64", strings.Repeat("a", 64), login, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(recipe), "<language><language>"+tumbleweedInstallerLocale+"</language></language>") {
		t.Fatalf("installer language differs from capture locale %q", tumbleweedInstallerLocale)
	}
}
