// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// EncryptedApplianceKernelEvidence identifies an explicit supermin override.
// ModulesVersion is the selected modules-directory basename, not an assertion
// that a booted appliance reported that kernel release. KernelSHA256 identifies
// the exact readable kernel artifact without changing host boot permissions.
type EncryptedApplianceKernelEvidence struct {
	KernelPath     string `json:"kernel_path"`
	KernelSHA256   string `json:"kernel_sha256"`
	ModulesPath    string `json:"modules_path"`
	ModulesVersion string `json:"modules_version"`
}

// encryptedSuperminPaths deliberately allows only the explicit pair. It neither
// inherits arbitrary libguestfs overrides nor elevates privilege to read /boot.
func encryptedSuperminPaths() (_ string, _ string, err error) {
	kernel, modules := os.Getenv("SUPERMIN_KERNEL"), os.Getenv("SUPERMIN_MODULES")
	if kernel == "" && modules == "" {
		return "", "", nil
	}
	if kernel == "" || modules == "" {
		return "", "", errors.New("guestfish kernel override requires both SUPERMIN_KERNEL and SUPERMIN_MODULES")
	}
	kernel, err = filepath.Abs(kernel)
	if err != nil {
		return "", "", err
	}
	modules, err = filepath.Abs(modules)
	if err != nil {
		return "", "", err
	}
	file, err := openRegular(kernel)
	if err != nil {
		return "", "", fmt.Errorf("open explicit supermin kernel: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return "", "", err
	}
	if info.Size() == 0 || info.Size() > 512<<20 {
		return "", "", errors.New("explicit supermin kernel size outside supported range")
	}
	info, err = os.Stat(modules)
	if err != nil {
		return "", "", fmt.Errorf("inspect explicit supermin modules: %w", err)
	}
	if !info.IsDir() {
		return "", "", errors.New("SUPERMIN_MODULES must identify an existing directory")
	}
	if err := syscall.Access(modules, 4|1); err != nil {
		return "", "", fmt.Errorf("supermin modules directory must be readable and searchable: %w", err)
	}
	return kernel, modules, nil
}

// encryptedSuperminKernelEvidence returns nil when no override was requested.
// Callers recording lab evidence opt into the bounded hash once, rather than
// repeating the hash for each pre/post-operation header observation.
func encryptedSuperminKernelEvidence(ctx context.Context) (_ *EncryptedApplianceKernelEvidence, err error) {
	kernel, modules, err := encryptedSuperminPaths()
	if err != nil || kernel == "" {
		return nil, err
	}
	file, err := openRegular(kernel)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	if _, err := copyVMBytes(ctx, hash, file, 512<<20); err != nil {
		return nil, fmt.Errorf("hash explicit supermin kernel: %w", err)
	}
	return &EncryptedApplianceKernelEvidence{
		KernelPath:     kernel,
		KernelSHA256:   hex.EncodeToString(hash.Sum(nil)),
		ModulesPath:    modules,
		ModulesVersion: filepath.Base(modules),
	}, nil
}
