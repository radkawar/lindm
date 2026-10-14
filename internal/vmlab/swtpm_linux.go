// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// swtpm cannot be reaped through Pdeathsig: its AppArmor profile turns its exec
// into a secure exec, which clears the parent-death signal, so swtpm outlived
// every SIGKILLed lab run. Its lifetime is tied to QEMU's instead, whose
// Pdeathsig holds. QEMU starts first on one end of a control socketpair and
// queues CMD_SET_DATAFD there; only then does swtpm start on the other end with
// --terminate, which ends it when that data channel closes: QEMU powered off,
// crashed, or died with the lab process. Starting swtpm before QEMU's data
// channel exists, or on a control path a dead QEMU never reached, would leave
// it waiting forever.
type swtpmControl struct {
	qemu, swtpm *os.File
}

func newSwtpmControl() (*swtpmControl, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("swtpm control socketpair: %w", err)
	}
	return &swtpmControl{qemu: os.NewFile(uintptr(fds[0]), "swtpm-control-qemu"), swtpm: os.NewFile(uintptr(fds[1]), "swtpm-control")}, nil
}

// swtpmArguments are the QEMU arguments for a TPM whose control channel is
// QEMU's descriptor fd.
func swtpmArguments(architecture string, fd int) []string {
	device := "tpm-tis"
	if architecture == "aarch64" {
		device = "tpm-tis-device"
	}
	return []string{"-chardev", fmt.Sprintf("socket,id=tpm,fd=%d", fd), "-tpmdev", "emulator,id=tpm0,chardev=tpm", "-device", device + ",tpmdev=tpm0"}
}

// close releases whichever ends were not handed to their processes.
func (c *swtpmControl) close() error {
	var err error
	for _, file := range []**os.File{&c.qemu, &c.swtpm} {
		if *file != nil {
			err = errors.Join(err, (*file).Close())
			*file = nil
		}
	}
	return err
}

// start starts swtpm on the guest's TPM state in dir once the QEMU started on
// c.qemu has queued its first control command. ctx bounds the wait; process
// bounds swtpm like its QEMU. qemu closes when QEMU exits. Both ends are
// closed on return; the caller stops QEMU on error.
func (c *swtpmControl) start(ctx, process context.Context, dir string, qemu <-chan struct{}) (_ *encryptedProcess, err error) {
	defer func() { err = errors.Join(err, c.close()) }()
	if err := c.qemu.Close(); err != nil {
		return nil, err
	}
	c.qemu = nil
	raw, err := c.swtpm.SyscallConn()
	if err != nil {
		return nil, err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var events int16
		var pollErr error
		if err := raw.Control(func(fd uintptr) {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, pollErr = unix.Poll(fds, 0)
			events = fds[0].Revents
		}); err != nil {
			return nil, err
		}
		if pollErr != nil && !errors.Is(pollErr, unix.EINTR) {
			return nil, fmt.Errorf("poll swtpm control: %w", pollErr)
		}
		if events&unix.POLLIN != 0 {
			break
		}
		if events&(unix.POLLHUP|unix.POLLERR) != 0 {
			return nil, errors.New("QEMU closed its TPM control channel before using it")
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("await QEMU TPM control: %w", ctx.Err())
		case <-qemu:
			return nil, errors.New("QEMU exited before using its TPM control channel")
		case <-ticker.C:
		}
	}
	p, err := startEncryptedProcessFiles(process, dir, []*os.File{c.swtpm}, "swtpm", "socket", "--tpm2", "--tpmstate", "dir=tpm", "--ctrl", "type=unixio,clientfd=3", "--terminate", "--flags", "not-need-init")
	if err != nil {
		return nil, err
	}
	if err := c.close(); err != nil {
		return nil, errors.Join(err, p.stop())
	}
	return p, nil
}
