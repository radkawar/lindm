// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

// Leap 16.0 Build18.75 aarch64 failed its first signed RPM install with
// "needs 27MB more space on the / filesystem" on a 1.5 GiB overlay. Small vendor
// bases get the floor; bases already larger keep their geometry.
func TestGuestOverlayDiskFloor(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("native overlay oracle requires qemu-img")
	}
	for _, tc := range []struct {
		base    string
		minimum int64
		want    int64
	}{
		{"1619001344", 0, minGuestDiskBytes},
		{"12G", 0, 12 << 30},
		{"1619001344", coldReleaseDiskBytes, coldReleaseDiskBytes},
		{"48G", coldReleaseDiskBytes, 48 << 30},
	} {
		t.Run(tc.base, func(t *testing.T) {
			dir := t.TempDir()
			if output, err := exec.CommandContext(t.Context(), "qemu-img", "create", "-f", "qcow2", filepath.Join(dir, "base.qcow2"), tc.base).CombinedOutput(); err != nil {
				t.Fatalf("base fixture: %v: %s", err, output)
			}
			base, err := openRegular(filepath.Join(dir, "base.qcow2"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = base.Close() })
			if err := createGuestOverlay(t.Context(), dir, base, tc.minimum); err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(t.Context(), "qemu-img", "info", "--output=json", "-f", "qcow2", filepath.Join(dir, "overlay.qcow2")).Output()
			if err != nil {
				t.Fatal(err)
			}
			var info struct {
				Size    int64  `json:"virtual-size"`
				Backing string `json:"backing-filename"`
			}
			if err := json.Unmarshal(output, &info); err != nil {
				t.Fatal(err)
			}
			if info.Size != tc.want || info.Backing != "/proc/self/fd/3" {
				t.Fatalf("overlay geometry %d backing %q, want %d over inherited base", info.Size, info.Backing, tc.want)
			}
		})
	}
}
