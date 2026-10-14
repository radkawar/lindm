// SPDX-License-Identifier: Apache-2.0
//go:build linux

package custody

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ProtectReleaseSecrets protects Go-library heap copies, including age's
// internal allocations. Safe swap permits unprivileged use; otherwise this
// process must be wholly locked. Native private-key helpers instead require
// ProtectNativeSigningSecrets: process locks do not survive exec. Never change
// swap topology while secrets remain live. The root installer gate is unchanged.
func ProtectReleaseSecrets() error {
	if err := disableSecretDumps(); err != nil {
		return err
	}
	unsafe, err := unprotectedSwaps("/proc/swaps", "/sys")
	if err != nil {
		return fmt.Errorf("custody: inspect swap protection: %w", err)
	}
	if len(unsafe) == 0 {
		return nil
	}
	// MCL_FUTURE with a finite allowance can crash on a later KDF allocation.
	// Raise it only if the caller already has authority; never request sudo.
	lockErr := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	if lockErr == nil {
		lockErr = unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
	}
	if lockErr == nil {
		return nil
	}
	return fmt.Errorf("custody: unencrypted swap %q; memory lock unavailable: %w; for the duration run sudo swapoff %s, or once in this shell run sudo prlimit --pid $$ --memlock=unlimited:unlimited, then retry this pure-Go custody operation as your normal user", strings.Join(unsafe, ", "), lockErr, swapoffArguments(unsafe))
}

// ProtectNativeSigningSecrets fails closed on unsafe swap because opaque GPG
// and gpg-agent heap copies are not covered by this process's memory lock.
func ProtectNativeSigningSecrets() error {
	if err := disableSecretDumps(); err != nil {
		return err
	}
	unsafe, err := unprotectedSwaps("/proc/swaps", "/sys")
	if err != nil {
		return fmt.Errorf("custody: inspect native signing swap protection: %w", err)
	}
	return nativeSigningSwapPolicy(unsafe)
}

func nativeSigningSwapPolicy(unsafe []string) error {
	if len(unsafe) == 0 {
		return nil
	}
	return fmt.Errorf("custody: production native signing refuses unencrypted swap %q; for the duration run sudo swapoff %s, or use encrypted swap or RAM-only zram; process memory locks do not protect native helper heap copies", strings.Join(unsafe, ", "), swapoffArguments(unsafe))
}

func disableSecretDumps() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}

func swapoffArguments(paths []string) string {
	var result strings.Builder
	for index, path := range paths {
		if index != 0 {
			result.WriteByte(' ')
		}
		result.WriteString(shellQuote(path))
	}
	return result.String()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func unprotectedSwaps(proc, sys string) (unsafe []string, err error) {
	input, err := os.Open(proc)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "Filename\t") {
		return nil, errors.New("invalid swap inventory header")
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 5 {
			return nil, errors.New("invalid swap inventory record")
		}
		// procfs uses octal escapes for whitespace and backslashes in paths.
		path := unescapeProcPath(fields[0])
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err != nil {
			return nil, fmt.Errorf("stat active swap %s: %w", path, err)
		}
		devices := []uint64{uint64(stat.Rdev)}
		if stat.Mode&unix.S_IFMT == unix.S_IFREG {
			devices, err = swapFileDevices(path, uint64(stat.Dev), sys, "/proc/self/mountinfo")
			if err != nil {
				unsafe = append(unsafe, path)
				continue
			}
		} else if stat.Mode&unix.S_IFMT != unix.S_IFBLK {
			return nil, fmt.Errorf("unsupported active swap object %s", path)
		}
		protected := len(devices) > 0
		for _, device := range devices {
			memberProtected, inspectErr := protectedBlock(sys, device, map[string]bool{})
			if inspectErr != nil || !memberProtected {
				protected = false
				break
			}
		}
		if !protected {
			unsafe = append(unsafe, path)
		}
	}
	return unsafe, scanner.Err()
}

func protectedBlock(sys string, device uint64, visited map[string]bool) (bool, error) {
	path := filepath.Join(sys, "dev", "block", fmt.Sprintf("%d:%d", unix.Major(device), unix.Minor(device)))
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, os.ErrNotExist) {
		// Pseudo filesystems and unresolved block stacks cannot establish safety.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return protectedBlockPath(sys, resolved, visited)
}

func protectedBlockPath(sys, path string, visited map[string]bool) (bool, error) {
	if visited[path] {
		return false, errors.New("cyclic block stack")
	}
	visited[path] = true
	defer delete(visited, path)
	base := filepath.Base(path)
	if strings.HasPrefix(base, "zram") {
		// Require the kernel zram driver, not only a device name.
		_, err := os.Stat(filepath.Join(path, "comp_algorithm"))
		if err == nil {
			backing, readErr := os.ReadFile(filepath.Join(path, "backing_dev"))
			if errors.Is(readErr, os.ErrNotExist) || (readErr == nil && strings.TrimSpace(string(backing)) == "none") {
				return true, nil
			}
			if readErr != nil {
				return false, readErr
			}
			// zram with disk writeback is not RAM-only. Inspect that disk.
			backingPath, err := filepath.EvalSymlinks(filepath.Join(sys, "class", "block", filepath.Base(strings.TrimSpace(string(backing)))))
			if err != nil {
				return false, err
			}
			return protectedBlockPath(sys, backingPath, visited)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	uuid, err := os.ReadFile(filepath.Join(path, "dm", "uuid"))
	if err == nil && strings.HasPrefix(strings.TrimSpace(string(uuid)), "CRYPT-") {
		return true, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if _, err := os.Stat(filepath.Join(path, "partition")); err == nil {
		return protectedBlockPath(sys, filepath.Dir(path), visited)
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	slaves, err := os.ReadDir(filepath.Join(path, "slaves"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(slaves) == 0 {
		return false, nil
	}
	for _, slave := range slaves {
		child, err := filepath.EvalSymlinks(filepath.Join(path, "slaves", slave.Name()))
		if err != nil {
			return false, err
		}
		protected, err := protectedBlockPath(sys, child, visited)
		if err != nil || !protected {
			return false, err
		}
	}
	return true, nil
}
