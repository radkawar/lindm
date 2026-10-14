// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"

	labv1 "lindm/gen/lindm/lab/v1"
)

func newVerifiedGuestWithHardware(ctx context.Context, manifest *labv1.ImageManifest, cacheDir, workDir string, allowReboot bool, hardware *VMHardwareOptions) (vm *guestVM, verified *VerifiedImage, err error) {
	return newVerifiedSeededGuest(ctx, manifest, cacheDir, workDir, allowReboot, hardware, nil)
}

func newVerifiedSeededGuest(ctx context.Context, manifest *labv1.ImageManifest, cacheDir, workDir string, allowReboot bool, hardware *VMHardwareOptions, seed guestUserData) (vm *guestVM, verified *VerifiedImage, err error) {
	h, err := hardwareForManifest(manifest, hardware, runtime.GOARCH)
	if err != nil {
		return nil, nil, err
	}
	// Fail on missing selected acceleration before fetching a large image.
	if err := checkVMAcceleration(h); err != nil {
		return nil, nil, err
	}
	installer, err := installerImageFor(manifest)
	if err != nil {
		return nil, nil, err
	}
	if installer != nil && h.Firmware == nil {
		return nil, nil, fmt.Errorf("%s installer requires explicit UEFI firmware", installer.label)
	}
	verified, err = (Fetcher{}).Fetch(ctx, manifest, cacheDir)
	if err != nil {
		return nil, nil, err
	}
	image := verified
	if installer != nil {
		image, err = installedImage(ctx, manifest, installer, verified, cacheDir, workDir, h)
		if err != nil {
			return nil, nil, err
		}
	}
	base, err := openRegular(image.Path)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if closeErr := base.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			if vm != nil {
				err = errors.Join(err, vm.close())
				vm = nil
			}
		}
	}()
	hash := sha256.New()
	count, err := copyVMBytes(ctx, hash, base, image.Size)
	if err != nil {
		return nil, nil, fmt.Errorf("pin verified image: %w", err)
	}
	if count != image.Size || hex.EncodeToString(hash.Sum(nil)) != image.SHA256 {
		return nil, nil, errors.New("verified image changed before VM launch")
	}
	vm, err = newSeededGuestVM(ctx, base, workDir, allowReboot, &h, seed)
	if err != nil {
		return nil, nil, err
	}
	vm.release = manifestRelease(manifest)
	// QEMU inherited its own descriptor before Start returned. A later rename
	// of the cache pathname cannot switch the machine to different image bytes.
	return vm, verified, nil
}

// The authenticated manifest, not the execution host or an x86 default,
// determines the guest architecture for every packaged/cloud-image lane.
func hardwareForManifest(manifest *labv1.ImageManifest, options *VMHardwareOptions, hostArchitecture string) (VMHardwareOptions, error) {
	if manifest == nil {
		return VMHardwareOptions{}, errors.New("VM image manifest is required")
	}
	architecture, _, err := inspectArchitecture(manifest.Architecture)
	if err != nil {
		return VMHardwareOptions{}, err
	}
	var selected VMHardwareOptions
	if options != nil {
		selected = *options
	}
	if selected.Architecture == "" {
		selected.Architecture = architecture
	}
	hardware, err := resolveVMHardware(&selected, hostArchitecture)
	if err != nil {
		return hardware, err
	}
	if hardware.Architecture != architecture {
		return hardware, errors.New("VM image and selected hardware architectures differ")
	}
	hardware.offlineRTCWaitUnit, hardware.rootRepair = "", nil
	if release := manifestRelease(manifest); release != nil {
		hardware.offlineRTCWaitUnit = release.Lab.OfflineRTCWaitUnit
		hardware.rootRepair = release.Lab.RootPermissionsRepair
	}
	return hardware, nil
}
