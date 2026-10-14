// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func hostQEMUArchitecture(t *testing.T) (architecture, machine string) {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		architecture, machine = "x86_64", "q35"
	case "arm64":
		architecture, machine = "aarch64", "virt"
	default:
		t.Skipf("no QEMU TPM machine for %s", runtime.GOARCH)
	}
	for _, tool := range []string{"qemu-system-" + architecture, "swtpm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("swtpm lifetime oracle requires %s", tool)
		}
	}
	return architecture, machine
}

// TestSwtpmLabProcess stands in for a lab run when re-executed by
// TestSwtpmEndsWithKilledLabProcess: it starts a paused QEMU and its swtpm
// exactly as a guest boot does, reports both, and waits to be SIGKILLed.
func TestSwtpmLabProcess(t *testing.T) {
	dir := os.Getenv("LINDM_TEST_SWTPM_LAB_DIR")
	if dir == "" {
		return
	}
	architecture, machine := hostQEMUArchitecture(t)
	control, err := newSwtpmControl()
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-no-user-config", "-nodefaults", "-display", "none", "-monitor", "none", "-S", "-machine", machine + ",accel=tcg"}, swtpmArguments(architecture, 3)...)
	qemu, err := startEncryptedProcessFiles(t.Context(), dir, []*os.File{control.qemu}, "qemu-system-"+architecture, args...)
	if err != nil {
		t.Fatal(err)
	}
	tpm, err := control.start(t.Context(), t.Context(), dir, qemu.done)
	if err != nil {
		t.Fatal(err, qemu.stop())
	}
	fmt.Printf("lab qemu=%d swtpm=%d\n", qemu.cmd.Process.Pid, tpm.cmd.Process.Pid)
	<-qemu.done
	t.Fatalf("QEMU exited: %v: %s", qemu.err, qemu.log.diagnostic(dir))
}

// swtpm's AppArmor profile clears its Pdeathsig, so a SIGKILLed lab run used
// to leave swtpm running forever. Its lifetime now follows QEMU's, which
// follows the lab process's.
func TestSwtpmEndsWithKilledLabProcess(t *testing.T) {
	hostQEMUArchitecture(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "tpm"), 0700); err != nil {
		t.Fatal(err)
	}
	lab := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSwtpmLabProcess$")
	lab.Env = append(os.Environ(), "LINDM_TEST_SWTPM_LAB_DIR="+dir)
	lab.Stderr = os.Stderr
	stdout, err := lab.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.Start(); err != nil {
		t.Fatal(err)
	}
	var qemu, swtpm int
	for lines := bufio.NewScanner(stdout); lines.Scan(); {
		if _, err := fmt.Sscanf(lines.Text(), "lab qemu=%d swtpm=%d", &qemu, &swtpm); err == nil {
			break
		}
	}
	if qemu == 0 {
		t.Fatalf("lab process reported no QEMU and swtpm: %v", lab.Wait())
	}
	t.Cleanup(func() {
		for _, pid := range []int{qemu, swtpm} {
			if processRunning(pid) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	if !processRunning(qemu) || !processRunning(swtpm) {
		t.Fatal("QEMU and swtpm must run until the lab process dies")
	}
	if err := lab.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = lab.Wait()
	// Both normally end within milliseconds; the bound only turns a survivor
	// into a failure instead of a hung test.
	deadline := time.Now().Add(30 * time.Second)
	for _, child := range []struct {
		name string
		pid  int
	}{{"QEMU", qemu}, {"swtpm", swtpm}} {
		for processRunning(child.pid) {
			if time.Now().After(deadline) {
				t.Fatalf("%s %d outlived the SIGKILLed lab process", child.name, child.pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// processRunning reports whether pid is a live (not zombie) QEMU or swtpm.
func processRunning(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	name, state, ok := strings.Cut(string(stat), ") ")
	if !ok || strings.HasPrefix(state, "Z") || strings.HasPrefix(state, "X") {
		return false
	}
	return strings.HasSuffix(name, "(swtpm") || strings.Contains(name, "(qemu-system-")
}

// A QEMU that dies before queuing its first TPM control command never gets an
// swtpm, which would otherwise wait for it forever.
func TestSwtpmNotStartedForQEMUThatNeverUsedControl(t *testing.T) {
	control, err := newSwtpmControl()
	if err != nil {
		t.Fatal(err)
	}
	gone, err := startEncryptedProcessFiles(t.Context(), t.TempDir(), []*os.File{control.qemu}, "true")
	if err != nil {
		t.Fatal(err)
	}
	tpm, err := control.start(t.Context(), t.Context(), t.TempDir(), gone.done)
	if err == nil || tpm != nil || !strings.Contains(err.Error(), "QEMU") {
		t.Fatalf("swtpm %v started for a QEMU that never used its control channel: %v", tpm, err)
	}
	if control.qemu != nil || control.swtpm != nil {
		t.Fatal("control channel ends must be closed")
	}
}
