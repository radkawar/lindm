// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/measuredboot"
	"lindm/internal/platform"
)

// measuredKernelFile maps an authenticated GRUB path onto the native boot
// filesystem. Loader-interface BLS uses paths relative to the ESP, including
// the machine-ID/kernel-version directories; flattening them loses the vendor
// layout and can select an unrelated kernel with the same basename.
func measuredKernelFile(boot string, chain platform.GRUBChain, kernel string) (string, error) {
	if !strings.HasPrefix(kernel, "/") || path.Clean(kernel) != kernel || kernel == "/" || strings.ContainsAny(kernel, "\\\x00") {
		return "", errors.New("recoveryboot: invalid_measured_kernel_path")
	}
	if chain.Entries == platform.GRUBBLSLoaderEntryOneShot {
		return filepath.Join(boot, filepath.FromSlash(strings.TrimPrefix(kernel, "/"))), nil
	}
	return filepath.Join(boot, path.Base(kernel)), nil
}

func measuredOneShot(ctx context.Context, request StageRequest) (string, error) {
	if request.GRUB.Entries == platform.GRUBBLSLoaderEntryOneShot {
		value, err := readEFString("LoaderEntryOneShot", loaderGUID)
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return value, err
	}
	env, err := readGrubEnv(ctx, request.GrubEnv, request.GRUB)
	return env["next_entry"], err
}

// loaderEntryTopology requires the running GRUB to advertise the native BLI
// one-shot protocol and requires its actual ESP, not an arbitrary writable FAT
// filesystem. XBOOTLDR paths are not silently mapped onto the ESP.
func loaderEntryTopology(esp string) (string, error) {
	if info, err := os.Stat("/usr/bin/bootctl"); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("recovery_readiness_bootctl_required")
	}
	loader, err := readEFString("LoaderInfo", loaderGUID)
	if err != nil || !measuredboot.GRUBLoaderInfo(loader) {
		return "", errors.New("recovery_readiness_grub_loader_interface_required")
	}
	features, err := os.ReadFile(efivars + "LoaderFeatures-" + loaderGUID)
	if err != nil || len(features) != 12 || binary.LittleEndian.Uint64(features[4:])&(1<<3) == 0 {
		return "", errors.New("recovery_readiness_loader_oneshot_unsupported")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(esp, &filesystem); err != nil || filesystem.Type != unix.MSDOS_SUPER_MAGIC || filesystem.Flags&unix.ST_RDONLY != 0 {
		return "", errors.New("recovery_readiness_esp_unsupported")
	}
	var device unix.Stat_t
	if err := unix.Stat(esp, &device); err != nil {
		return "", err
	}
	filesystemUUID, partitionUUID, err := readinessESPIdentity(uint64(device.Dev))
	if err != nil {
		return "", err
	}
	partition, err := readEFString("LoaderDevicePartUUID", loaderGUID)
	if err != nil || !efiPartitionUUID(partition) || !strings.EqualFold(partition, partitionUUID) {
		return "", errors.New("recovery_readiness_loader_esp_mismatch")
	}
	return filesystemUUID, nil
}

// loaderEntrySnapshot binds all vendor EFI assets (including the vendor's
// optional grubenv override), BLS entries, loader.conf and persistent/default
// EFI selections. None is rewritten, backed up into a second live menu, or
// regenerated. Rollback therefore only removes our digest-checked additions.
func loaderEntrySnapshot(esp string, chain platform.GRUBChain, readString func(string, string) (string, error)) ([]byte, error) {
	if err := rootDirectory(filepath.Join(esp, chain.ConfigDirectory)); err != nil {
		return nil, err
	}
	hash := sha256.New()
	count := 0
	var total int64
	for _, directory := range []string{"loader", "EFI"} {
		root := filepath.Join(esp, directory)
		if err := rootDirectory(root); err != nil {
			return nil, err
		}
		err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			count++
			if count > 4096 {
				return errors.New("recoveryboot: too_many_boot_assets")
			}
			if entry.IsDir() {
				return rootDirectory(name)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 256<<20 || info.Size() > (1<<30)-total {
				return errors.New("recoveryboot: unsafe_boot_asset")
			}
			total += info.Size()
			digest, _, err := digestFile(name)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(hash, "%s %x\n", strings.TrimPrefix(name, esp), digest)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"LoaderEntryDefault", "LoaderEntryOneShot", "LoaderDevicePartUUID", "LoaderInfo"} {
		value, err := readString(name, loaderGUID)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if _, err := fmt.Fprintf(hash, "%s %s\n", name, value); err != nil {
			return nil, err
		}
	}
	return hash.Sum(nil), nil
}
