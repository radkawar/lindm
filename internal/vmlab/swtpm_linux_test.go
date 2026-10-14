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
// TestSwtpmEndsWithKilledLabProcess: it starts a QEMU and its swtpm exactly as
// a guest boot does, reports both, and waits to be SIGKILLed. The QEMU is a
// real paused one, or a stand-in that queues QEMU's first control command
// (CMD_GET_CAPABILITY) and never reaches CMD_SET_DATAFD, so swtpm's
// --terminate has no data channel to lose.
func TestSwtpmLabProcess(t *testing.T) {
	dir := os.Getenv("LINDM_TEST_SWTPM_LAB_DIR")
	if dir == "" {
		return
	}
	control, err := newSwtpmControl()
	if err != nil {
		t.Fatal(err)
	}
	name, args := "/bin/sh", []string{"-c", `printf '\000\000\000\001' >&3 && exec sleep 600`}
	if os.Getenv("LINDM_TEST_SWTPM_LAB_QEMU") == "real" {
		architecture, machine := hostQEMUArchitecture(t)
		name, args = "qemu-system-"+architecture, append([]string{"-no-user-config", "-nodefaults", "-display", "none", "-monitor", "none", "-S", "-machine", machine + ",accel=tcg"}, swtpmArguments(architecture, 3)...)
	}
	qemu, err := startEncryptedProcessFiles(t.Context(), dir, []*os.File{control.qemu}, name, args...)
	if err != nil {
		t.Fatal(err)
	}
	tpm, err := control.start(t.Context(), t.Context(), dir, qemu.done)
	if err != nil {
		t.Fatal(err, qemu.stop())
	}
	fmt.Printf("lab qemu=%d swtpm=%d\n", qemu.pid, tpm.pid)
	<-qemu.done
	t.Fatalf("QEMU exited: %v: %s", qemu.err, qemu.log.diagnostic(dir))
}

// swtpm's AppArmor profile clears its Pdeathsig, so a SIGKILLed lab run used
// to leave swtpm running forever, including while QEMU had not yet handed
// swtpm its data channel.
func TestSwtpmEndsWithKilledLabProcess(t *testing.T) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm lifetime oracle requires swtpm")
	}
	for _, qemu := range []string{"real", "before-data-channel"} {
		t.Run(qemu, func(t *testing.T) {
			if qemu == "real" {
				hostQEMUArchitecture(t)
			}
			killLabProcess(t, qemu)
		})
	}
}

func killLabProcess(t *testing.T, qemuKind string) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "tpm"), 0700); err != nil {
		t.Fatal(err)
	}
	lab := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSwtpmLabProcess$")
	lab.Env = append(os.Environ(), "LINDM_TEST_SWTPM_LAB_DIR="+dir, "LINDM_TEST_SWTPM_LAB_QEMU="+qemuKind)
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
	qemuName := "(qemu-system-"
	if qemuKind != "real" {
		qemuName = "(sleep)"
	}
	t.Cleanup(func() {
		for _, pid := range []int{qemu, swtpm} {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	// The watcher reports swtpm's PID as soon as it forks, before the exec.
	for started := time.Now(); !processRunning(qemu, qemuName) || !processRunning(swtpm, "(swtpm)"); time.Sleep(10 * time.Millisecond) {
		if time.Since(started) > 30*time.Second {
			t.Fatal("QEMU and swtpm must run until the lab process dies")
		}
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
	}{{qemuName, qemu}, {"(swtpm)", swtpm}} {
		for processRunning(child.pid, child.name) {
			if time.Now().After(deadline) {
				t.Fatalf("%s %d outlived the SIGKILLed lab process", child.name, child.pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// processRunning reports whether pid is a live (not zombie) process whose
// /proc/PID/stat name starts with prefix, so a reused PID is not mistaken.
func processRunning(pid int, prefix string) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	_, rest, _ := strings.Cut(string(stat), " ")
	name, state, ok := strings.Cut(rest, ") ")
	if !ok || strings.HasPrefix(state, "Z") || strings.HasPrefix(state, "X") {
		return false
	}
	return strings.HasPrefix(name+")", prefix)
}

// A QEMU that dies before queuing its first TPM control command never gets an
// swtpm, which would otherwise wait for it forever. Its closed end reads as
// end of file, which poll also reports as readable; a QEMU already gone when
// the poll runs once started swtpm under load.
func TestSwtpmNotStartedForQEMUThatNeverUsedControl(t *testing.T) {
	for _, exited := range []bool{false, true} {
		t.Run(fmt.Sprintf("exited=%v", exited), func(t *testing.T) {
			control, err := newSwtpmControl()
			if err != nil {
				t.Fatal(err)
			}
			gone, err := startEncryptedProcessFiles(t.Context(), t.TempDir(), []*os.File{control.qemu}, "true")
			if err != nil {
				t.Fatal(err)
			}
			if exited {
				<-gone.done
			}
			tpm, err := control.start(t.Context(), t.Context(), t.TempDir(), gone.done)
			if err == nil || tpm != nil || !strings.Contains(err.Error(), "QEMU") {
				t.Fatalf("swtpm %v started for a QEMU that never used its control channel: %v", tpm, err)
			}
			if control.qemu != nil || control.swtpm != nil {
				t.Fatal("control channel ends must be closed")
			}
		})
	}
}
