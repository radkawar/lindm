// SPDX-License-Identifier: Apache-2.0
//go:build linux

package custody

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReleaseSwapBlockStack(t *testing.T) {
	root := t.TempDir()
	block := func(name string) string {
		t.Helper()
		path := filepath.Join(root, "devices", "block", name)
		if err := os.MkdirAll(filepath.Join(path, "slaves"), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write := func(path, value string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(parent, child string) {
		t.Helper()
		if err := os.Symlink(child, filepath.Join(parent, "slaves", filepath.Base(child))); err != nil {
			t.Fatal(err)
		}
	}
	plain := block("disk")
	encrypted := block("dm-0")
	write(filepath.Join(encrypted, "dm", "uuid"), "CRYPT-LUKS2-operator-volume\n")
	link(encrypted, plain)
	zram := block("zram0")
	write(filepath.Join(zram, "comp_algorithm"), "lzo [zstd]\n")
	zramWriteback := block("zram1")
	write(filepath.Join(zramWriteback, "comp_algorithm"), "[zstd]\n")
	write(filepath.Join(zramWriteback, "backing_dev"), "disk\n")
	if err := os.MkdirAll(filepath.Join(root, "class", "block"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(plain, filepath.Join(root, "class", "block", "disk")); err != nil {
		t.Fatal(err)
	}
	stack := block("dm-1")
	link(stack, encrypted)
	mixed := block("md0")
	link(mixed, encrypted)
	link(mixed, plain)
	cycle := block("cycle")
	link(cycle, cycle)
	for _, item := range []struct {
		name    string
		path    string
		want    bool
		wantErr bool
	}{
		{"plain refuses", plain, false, false},
		{"dmcrypt admits", encrypted, true, false},
		{"ram admits", zram, true, false},
		{"unencrypted zram writeback refuses", zramWriteback, false, false},
		{"encrypted backing admits", stack, true, false},
		{"mixed backing refuses", mixed, false, false},
		{"cycle refuses", cycle, false, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			got, err := protectedBlockPath(root, item.path, map[string]bool{})
			if got != item.want || (err != nil) != item.wantErr {
				t.Fatalf("protected=%v err=%v; want %v error=%v", got, err, item.want, item.wantErr)
			}
		})
	}
}

func TestReleaseNoSwapAndMalformedInventory(t *testing.T) {
	for _, item := range []struct {
		name, data string
		wantErr    bool
	}{
		{"no swap", "Filename\tType\tSize\tUsed\tPriority\n", false},
		{"malformed header", "\n", true},
		{"malformed record", "Filename\tType\tSize\tUsed\tPriority\n/dev/swap file\n", true},
	} {
		t.Run(item.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "swaps")
			if err := os.WriteFile(path, []byte(item.data), 0600); err != nil {
				t.Fatal(err)
			}
			unsafe, err := unprotectedSwaps(path, t.TempDir())
			if (err != nil) != item.wantErr || len(unsafe) != 0 {
				t.Fatalf("unsafe=%v err=%v", unsafe, err)
			}
		})
	}
}

func TestSecretBufferProtectsOwnedInput(t *testing.T) {
	buffer, err := NewSecretBuffer(128)
	if err != nil {
		t.Fatal(err)
	}
	copy(buffer.Bytes(), "private-key-input")
	if string(buffer.Bytes()[:17]) != "private-key-input" {
		t.Fatal("secret buffer did not retain input")
	}
	if err := buffer.Close(); err != nil {
		t.Fatal(err)
	}
	if len(buffer.Bytes()) != 0 {
		t.Fatal("closed secret buffer remains available")
	}
	if err := buffer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBtrfsSwapfileIncludesEveryBackingDevice(t *testing.T) {
	root := t.TempDir()
	for name, dev := range map[string]string{"encrypted-member": "253:0\n", "plain-member": "8:1\n"} {
		path := filepath.Join(root, "fs", "btrfs", "filesystem-id", "devices", name)
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "dev"), []byte(dev), 0600); err != nil {
			t.Fatal(err)
		}
	}
	devices, err := btrfsDevices(root, unix.Mkdev(253, 0))
	if err != nil || len(devices) != 2 {
		t.Fatalf("swapfile member enumeration=%v error=%v", devices, err)
	}
	foundPlain := false
	for _, dev := range devices {
		foundPlain = foundPlain || dev == unix.Mkdev(8, 1)
	}
	if !foundPlain {
		t.Fatal("swapfile enumeration trusted only its first encrypted device")
	}
	if _, err := btrfsDevices(root, unix.Mkdev(1, 1)); err == nil {
		t.Fatal("unknown backing filesystem accepted")
	}
}
