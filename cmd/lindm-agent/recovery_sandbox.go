//go:build linux

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Recovery boot needs only its qualified ESP/state and the firmware loader's
// one-shot variable directory writable. Native staging independently validates
// media exclusion, firmware signer, boot entry and exact image digest. For
// measured GRUB the staging directory is /boot.
func recoverySandboxPaths(cfg *agentv1.RecoveryBootConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("recovery handoff requires locally qualified boot paths")
	}
	var result strings.Builder
	for _, path := range []string{cfg.GetEspDirectory(), cfg.GetStateDirectory(), "/sys/firmware/efi/efivars"} {
		if err := systemdSafePath(path); err != nil {
			return "", err
		}
		result.WriteString("ReadWritePaths=" + path + "\n")
	}
	return result.String(), nil
}

func systemdSafePath(path string) error {
	if !filepath.IsAbs(path) || path == "/" || filepath.Clean(path) != path {
		return errors.New("recovery write path must be a canonical non-root directory")
	}
	for _, character := range path {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && !strings.ContainsRune("/._-", character) {
			return errors.New("recovery write path contains systemd metacharacters")
		}
	}
	return nil
}

// measuredBootDevices returns only the TPM resource manager used for the
// attestation key. The executor never gains the /boot block device: its
// grub-editenv runs in a separate short-lived unit (executor grubEnvironment).
// A missing TPM is not exposed; readiness then reports the capability gate.
func measuredBootDevices() ([]string, error) {
	var stat unix.Stat_t
	switch err := unix.Lstat("/dev/tpmrm0", &stat); {
	case errors.Is(err, unix.ENOENT):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("inspect TPM resource manager: %w", err)
	case stat.Mode&unix.S_IFMT != unix.S_IFCHR:
		return nil, errors.New("TPM resource manager is not a character device")
	}
	return []string{"/dev/tpmrm0"}, nil
}
