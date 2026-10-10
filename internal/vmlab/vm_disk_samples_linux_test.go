//go:build linux

package vmlab

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVMStoppedDiskSampleOffsets(t *testing.T) {
	for _, size := range []int64{0, 4096, 12289, 65 << 30} {
		if _, err := stoppedDiskSampleOffsets(size); err == nil {
			t.Fatalf("accepted invalid size %d", size)
		}
	}
	offsets, err := stoppedDiskSampleOffsets(12288)
	if err != nil || offsets != [3]int64{0, 4096, 8192} {
		t.Fatalf("sample geometry: %v, %v", offsets, err)
	}
	vm := &guestVM{done: make(chan struct{})}
	if _, err := vm.stoppedDiskSamples(t.Context()); err == nil {
		t.Fatal("accepted unowned live disk observation")
	}
}

func TestVMStoppedDiskSamplesNativeBacking(t *testing.T) {
	for _, name := range []string{"qemu-img", "qemu-io"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("native file oracle requires %s", name)
		}
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	command := func(files []*os.File, name string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), name, args...)
		cmd.Dir, cmd.ExtraFiles = dir, files
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native file fixture %s: %v: %s", name, err, output)
		}
	}
	command(nil, "qemu-img", "create", "-f", "qcow2", "base.qcow2", "1M")
	command(nil, "qemu-io", "-f", "qcow2", "-c", "write -P 0x5a 0 1048576", "base.qcow2")
	base, err := openRegular(filepath.Join(dir, "base.qcow2"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	command(nil, "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", "/proc/self/fd/3", "-u", "overlay.qcow2", "1M")
	vm := &guestVM{dir: dir, base: base, done: make(chan struct{})}
	close(vm.done)
	check := func(first byte) {
		t.Helper()
		result, err := vm.stoppedDiskSamples(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if result.SizeBytes != 1048576 || len(result.Samples) != 3 {
			t.Fatalf("incomplete sample evidence: %+v", result)
		}
		for i, sample := range result.Samples {
			value := byte(0x5a)
			if i == 0 {
				value = first
			}
			want := fmt.Sprintf("%x", sha256.Sum256(bytes.Repeat([]byte{value}, 4096)))
			if sample.Length != 4096 || sample.SHA256 != want {
				t.Fatalf("sample %d ignored logical backing/overlay content: %+v", i, sample)
			}
		}
	}
	check(0x5a)
	command([]*os.File{base}, "qemu-io", "-f", "qcow2", "-c", "write -P 0x00 0 4096", "overlay.qcow2")
	check(0)
}
