//go:build linux

package main

import (
	"errors"
	"path/filepath"
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Recovery boot needs only its qualified ESP/state and the firmware loader's
// one-shot variable directory writable. Native staging independently validates
// media exclusion, firmware signer, boot entry and exact image digest.
func recoverySandboxPaths(cfg *agentv1.RecoveryBootConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("recovery handoff requires locally qualified boot paths")
	}
	var result strings.Builder
	for _, path := range []string{cfg.GetEspDirectory(), cfg.GetStateDirectory(), "/sys/firmware/efi/efivars"} {
		if !filepath.IsAbs(path) || path == "/" || filepath.Clean(path) != path {
			return "", errors.New("recovery write path must be a canonical non-root directory")
		}
		for _, character := range path {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && !strings.ContainsRune("/._-", character) {
				return "", errors.New("recovery write path contains systemd metacharacters")
			}
		}
		result.WriteString("ReadWritePaths=" + path + "\n")
	}
	return result.String(), nil
}
