//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	labv1 "lindm/gen/lindm/lab/v1"
)

func newVerifiedGuest(ctx context.Context, manifest *labv1.ImageManifest, cacheDir, workDir string, allowReboot bool) (*guestVM, *VerifiedImage, error) {
	return newVerifiedGuestWithHardware(ctx, manifest, cacheDir, workDir, allowReboot, nil)
}

func newVerifiedGuestWithHardware(ctx context.Context, manifest *labv1.ImageManifest, cacheDir, workDir string, allowReboot bool, hardware *VMHardwareOptions) (vm *guestVM, verified *VerifiedImage, err error) {
	return newVerifiedSeededGuest(ctx, manifest, cacheDir, workDir, allowReboot, hardware, nil)
}

func newVerifiedSeededGuest(ctx context.Context, manifest *labv1.ImageManifest, cacheDir, workDir string, allowReboot bool, hardware *VMHardwareOptions, seed *unattendedSeed) (vm *guestVM, verified *VerifiedImage, err error) {
	h, err := defaultVMHardware(hardware)
	if err != nil {
		return nil, nil, err
	}
	if manifest == nil {
		return nil, nil, errors.New("VM image manifest is required")
	}
	architecture := manifest.Architecture
	switch architecture {
	case "amd64":
		architecture = "x86_64"
	case "arm64":
		architecture = "aarch64"
	}
	if architecture != h.Architecture {
		return nil, nil, errors.New("VM image and selected hardware architectures differ")
	}
	// Fail on missing selected acceleration before fetching a large image.
	if err := checkVMAcceleration(h); err != nil {
		return nil, nil, err
	}
	if manifest.Distribution == "debian" && manifest.Edition == "netinst" && h.Firmware == nil {
		return nil, nil, errors.New("debian netinst requires explicit UEFI firmware")
	}
	verified, err = (Fetcher{}).Fetch(ctx, manifest, cacheDir)
	if err != nil {
		return nil, nil, err
	}
	image := verified
	if manifest.Distribution == "debian" && manifest.Edition == "netinst" {
		image, err = debianInstalledImage(ctx, manifest, verified, cacheDir, workDir, h)
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
	// QEMU inherited its own descriptor before Start returned. A later rename
	// of the cache pathname cannot switch the machine to different image bytes.
	return vm, verified, nil
}
