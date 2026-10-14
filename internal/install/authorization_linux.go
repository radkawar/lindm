// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"lindm/internal/platform"
)

// A native hook may consume authorization only in this installer's process tree.
// Start time prevents an abandoned token from authorizing a later reused PID.
func packageAuthorization(version string) ([]byte, error) {
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return nil, err
	}
	_, tail, ok := strings.Cut(string(stat), ") ")
	if !ok {
		return nil, errors.New("cannot bind native transaction to installer process")
	}
	fields := strings.Fields(tail)
	if len(fields) < 20 {
		return nil, errors.New("invalid installer process identity")
	}
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", version, os.Getpid(), fields[19])), nil
}

// A retry of bootstrap is still a native upgrade to the package manager. The
// authenticated pending record, checked by Run, authorizes only this process and
// the exact signed version, just as a managed upgrade does.
func authorizeInstallationPackage(ctx context.Context, packagePath string, release *platform.Release, version string) (err error) {
	if err := directory("/run/lindm-install", 0, 0, 0700); err != nil {
		return err
	}
	authorization, err := packageAuthorization(version)
	if err != nil {
		return err
	}
	path := "/run/lindm-install/authorized-version"
	// The lifecycle lock is held; an abandoned process-bound token cannot
	// authorize a different process and must not prevent recovery.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := newFile(path, authorization, 0, 0, 0600); err != nil {
		return err
	}
	defer func() {
		if removeErr := os.Remove(path); !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	if release.Packages.Backend.PackageDB() == platform.PackageDBRPM {
		// A bootstrap retry reinstalls the exact authenticated bytes, including
		// any native transaction whose payload landed before its post-hook failed.
		// --replacepkgs admits that same version, but never a downgrade.
		_, err := command(ctx, nil, "rpm", "--upgrade", "--replacepkgs", "--nosignature", packagePath)
		return err
	}
	return installPackage(ctx, packagePath, release, false)
}
