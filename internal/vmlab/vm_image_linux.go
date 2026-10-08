//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	labv1 "lindm/gen/lindm/lab/v1"
)

func newVerifiedGuest(ctx context.Context, manifest *labv1.ImageManifest, cacheDir, workDir string, allowReboot bool) (vm *guestVM, verified *VerifiedImage, err error) {
	// Fail on missing acceleration before fetching a large official image.
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("KVM access is required (no software fallback): %w", err)
	}
	if err := kvm.Close(); err != nil {
		return nil, nil, err
	}
	verified, err = (Fetcher{}).Fetch(ctx, manifest, cacheDir)
	if err != nil {
		return nil, nil, err
	}
	base, err := openRegular(verified.Path)
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
	count, err := copyVMBytes(ctx, hash, base, verified.Size)
	if err != nil {
		return nil, nil, fmt.Errorf("pin verified image: %w", err)
	}
	if count != verified.Size || hex.EncodeToString(hash.Sum(nil)) != verified.SHA256 {
		return nil, nil, errors.New("verified image changed before VM launch")
	}
	vm, err = newGuestVM(ctx, base, workDir, allowReboot)
	if err != nil {
		return nil, nil, err
	}
	// QEMU inherited its own descriptor before Start returned. A later rename
	// of the cache pathname cannot switch the machine to different image bytes.
	return vm, verified, nil
}
