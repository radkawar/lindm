// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"testing"
)

func TestVMCloseExpectedExitRequiresSuccessfulReap(t *testing.T) {
	live := &guestVM{dir: t.TempDir(), cmd: exec.Command("true"), done: make(chan struct{})}
	if err := live.closeAfterExpectedExit(); err == nil {
		t.Fatal("accepted a process not observed exited")
	}
	for _, program := range []string{"true", "false"} {
		t.Run(program, func(t *testing.T) {
			vm := &guestVM{dir: t.TempDir(), cmd: exec.Command(program), done: make(chan struct{}), log: new(vmLog)}
			if err := vm.cmd.Start(); err != nil {
				t.Fatal(err)
			}
			vm.waitErr = vm.cmd.Wait()
			close(vm.done)
			err := vm.closeAfterExpectedExit()
			if program == "true" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(vm.dir); !os.IsNotExist(err) {
					t.Fatalf("successful expected exit retained private state: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("unsuccessful process exit was accepted")
				}
				if _, err := os.Stat(vm.dir); err != nil {
					t.Fatalf("rejected exit discarded diagnostic state: %v", err)
				}
			}
		})
	}
}
