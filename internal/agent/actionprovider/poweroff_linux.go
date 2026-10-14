// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const LiveRootPoweroffService = "lindm-live-root-poweroff.service"
const LiveRootPoweroffDelay = 120 * time.Second
const liveRootEffectTimeout = 90 * time.Second

// PinLiveRootMemory prevents current signer, proof and native working pages from
// being swapped or dumped after the journal is closed. The packaged executor
// requires unlimited locked memory; failure is a pre-effect rejection.
func PinLiveRootMemory() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
}

// RunLiveRootPoweroffHelper is only the fixed root-owned Type=notify service
// entrypoint. It has no caller-selected deadline, device, executable or action.
// PID 1 owns its lifetime independently from both executor and network services.
// Readiness is sent only after a wake-capable BOOTTIME_ALARM timer has been armed
// and all memory pinned. Unsupported alarm/RTC kernels fail before any erase;
// suspend must not extend the active mapping's lifetime. No disk writes, sync,
// journal or acknowledgment are used.
func RunLiveRootPoweroffHelper() error {
	if os.Geteuid() != 0 {
		return ErrUnsupported
	}
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" || (address[0] != '/' && address[0] != '@') {
		return ErrUnsupported
	}
	fd, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME_ALARM, unix.TFD_CLOEXEC)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.TimerfdSettime(fd, 0, &unix.ItimerSpec{Value: unix.NsecToTimespec(int64(LiveRootPoweroffDelay))}, nil); err != nil {
		return err
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: strings.Replace(address, "@", "\x00", 1), Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	if err := PinLiveRootMemory(); err != nil {
		return err
	}
	if _, err := connection.Write([]byte("READY=1")); err != nil {
		return err
	}
	return awaitForcedPoweroff(func() error {
		var ticks [8]byte
		_, err := unix.Read(fd, ticks[:])
		return err
	}, func() error { return unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF) })
}

// Once ready, even a timer read error forces poweroff rather than abandoning the
// deadline. EINTR only retries the read; an unexpected reboot failure retries
// without going back to the consumed one-shot timer.
func awaitForcedPoweroff(wait func() error, poweroff func() error) error {
	for {
		err := wait()
		if errors.Is(err, unix.EINTR) {
			continue
		}
		break
	}
	for {
		if err := poweroff(); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}
