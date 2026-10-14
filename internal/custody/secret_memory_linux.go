// SPDX-License-Identifier: Apache-2.0

//go:build linux

package custody

import (
	"errors"

	"golang.org/x/sys/unix"
)

// LockSecretMemory disables dumps and keeps process memory out of swap for its
// lifetime. A finite memlock allowance is not enough for future Go/KDF pages:
// it could turn allocation into a fatal error after secrets have been admitted.
func LockSecretMemory() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	if data[0].Effective&(uint32(1)<<unix.CAP_IPC_LOCK) == 0 {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}); err != nil {
			return errors.New("secret custody requires IPC_LOCK authority or an unlimited memlock allowance")
		}
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			return err
		}
		if limit.Cur != unix.RLIM_INFINITY {
			return errors.New("secret custody refuses a finite future-memory lock allowance")
		}
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return errors.New("secret custody memory could not be locked; refusing plaintext swap")
	}
	return nil
}
