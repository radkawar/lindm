// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// swtpm cannot be reaped through its own Pdeathsig: its AppArmor profile turns
// its exec into a secure exec, which clears the parent-death signal, so swtpm
// outlived every SIGKILLed lab run. It runs under a watcher whose Pdeathsig
// holds (startSwtpm). QEMU starts first on one end of a control socketpair;
// swtpm starts on the other end only once QEMU has queued its first control
// command, so it never serves a QEMU that already exited, and with --terminate
// it also ends when QEMU's data channel closes.
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
		// A closed peer also reads as POLLIN (end of file), so hangup is checked
		// first: QEMU holds its end for its whole life, and an swtpm started
		// on a channel whose QEMU is gone would only fail. Only a live QEMU's
		// queued command makes the end readable without a hangup.
		if events&(unix.POLLHUP|unix.POLLERR) != 0 {
			return nil, errors.New("QEMU closed its TPM control channel before using it")
		}
		if events&unix.POLLIN != 0 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("await QEMU TPM control: %w", ctx.Err())
		case <-qemu:
			return nil, errors.New("QEMU exited before using its TPM control channel")
		case <-ticker.C:
		}
	}
	p, err := startSwtpm(process, dir, c.swtpm)
	if err != nil {
		return nil, err
	}
	if err := c.close(); err != nil {
		return nil, errors.Join(err, p.stop())
	}
	return p, nil
}

// swtpmWatcher runs swtpm ("$@", its control channel on descriptor 3) as a
// child, reports its PID on descriptor 4, and SIGKILLs it on SIGTERM, the
// watcher's parent-death signal; it exits with swtpm's status. A TERM before
// swtpm's PID is known is remembered and acted on once it is.
const swtpmWatcher = `trap 'dead=1' TERM
"$@" 4>&- & pid=$!
trap 'kill -KILL $pid; exit 143' TERM
exec 3<&-
if [ -n "${dead-}" ]; then kill -KILL $pid; exit 143; fi
echo $pid >&4
exec 4>&-
wait $pid`

// startSwtpm starts swtpm on control under a /bin/sh watcher. The watcher is
// unconfined, so its parent-death signal holds and takes swtpm with it when
// the lab process dies, even before QEMU's data channel exists (swtpm's
// --terminate covers only a lost data channel, and before CMD_SET_DATAFD a
// dead QEMU left it waiting forever). Stopping kills the watcher's group,
// swtpm included.
func startSwtpm(ctx context.Context, dir string, control *os.File) (_ *encryptedProcess, err error) {
	pidRead, pidWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, pidRead.Close()) }()
	p, err := startProcessGroup(ctx, dir, []*os.File{control, pidWrite}, nil, syscall.SIGTERM, "/bin/sh", "-c", swtpmWatcher, "swtpm-watcher",
		"swtpm", "socket", "--tpm2", "--tpmstate", "dir=tpm", "--ctrl", "type=unixio,clientfd=3", "--terminate", "--flags", "not-need-init")
	if closeErr := pidWrite.Close(); err != nil || closeErr != nil {
		if err == nil {
			err = errors.Join(closeErr, p.stop())
		}
		return nil, err
	}
	// The watcher writes the PID at once or exits, closing the pipe.
	line, readErr := bufio.NewReader(pidRead).ReadString('\n')
	pid, parseErr := strconv.Atoi(strings.TrimSpace(line))
	if readErr != nil || parseErr != nil || pid <= 0 {
		stopErr := p.stop()
		return nil, errors.Join(fmt.Errorf("swtpm watcher reported no swtpm: %s", p.log.diagnostic(dir)), stopErr)
	}
	p.pid = pid
	return p, nil
}
