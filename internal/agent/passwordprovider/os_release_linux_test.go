//go:build linux

package passwordprovider

import (
	"bytes"
	"os"
	"testing"
)

// Pop!_OS 24.04 ships /usr/lib/os-release -> ../../etc/pop-os/os-release, so
// the platform check must follow root-owned vendor symlinks; a no-follow read
// refused every password action there (ELOOP). This host's /etc/os-release is
// the same shape of root-owned symlink.
func TestOSReleaseFollowsRootOwnedVendorSymlink(t *testing.T) {
	if info, err := os.Lstat("/etc/os-release"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Skip("/etc/os-release is not a symlink on this host")
	}
	if _, err := readNative("/etc/os-release", 32768); err == nil {
		t.Fatal("no-follow read accepted a symlink")
	}
	got, err := readOSRelease("/etc/os-release")
	if err != nil {
		t.Fatalf("resolved os-release: %v", err)
	}
	target, err := os.ReadFile("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, target) || !bytes.Contains(got, []byte("ID=")) {
		t.Fatalf("resolved os-release differs from its target")
	}
}
