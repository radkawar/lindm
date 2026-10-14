// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// Classify the manifest's actual artifact, not its distro's default installer:
// Tumbleweed publishes both signed DVD media and bootable cloud disks.
func repositorySnapshotInstaller(image *labv1.ImageManifest) (*installerImage, error) {
	if strings.HasSuffix(image.GetEdition(), "encrypted-lab") {
		return nil, errors.New("repository bootstrap cannot use an encrypted golden manifest")
	}
	return installerImageFor(image)
}

// newRepositorySnapshotGuest returns a connected native solver. A DVD capture
// cannot use installedImage: final goldens require the very retained repository
// being captured. Instead install only DVD contents into a fresh, private disk.
// That bootstrap is never published to any ordinary/encrypted golden cache.
func newRepositorySnapshotGuest(ctx context.Context, image *labv1.ImageManifest, cacheDir, workDir, diagnosticsDir string, hardware *VMHardwareOptions) (vm *guestVM, verified *VerifiedImage, err error) {
	defer func() {
		if err != nil && vm != nil {
			err = errors.Join(err, vm.close())
			vm = nil
		}
	}()
	release := platform.ForManifest(image.GetDistribution(), image.GetVersion())
	spec, err := repositorySnapshotInstaller(image)
	if err != nil {
		return nil, nil, err
	}
	if spec == nil || spec.installer != platform.AutoYaST {
		vm, verified, err = newVerifiedGuestWithHardware(ctx, image, cacheDir, workDir, false, hardware)
		if err != nil {
			return nil, nil, err
		}
		if err = vm.connect(ctx); err != nil {
			return vm, nil, err
		}
		_, err = vm.run(ctx, "sudo cloud-init status --wait --long", nil, 1<<20, 5*time.Minute)
		return vm, verified, err
	}
	h, err := hardwareForManifest(image, hardware, runtime.GOARCH)
	if err != nil {
		return nil, nil, err
	}
	if h.Firmware == nil || h.TPM || h.Desktop || h.ExtraDisks != 0 {
		return nil, nil, errors.New("repository bootstrap requires UEFI and one owned disk without TPM or desktop hardware")
	}
	h.AllowNetwork = false
	if err := checkVMAcceleration(h); err != nil {
		return nil, nil, err
	}
	verified, err = (Fetcher{}).Fetch(ctx, image, cacheDir)
	if err != nil {
		return nil, nil, err
	}
	if workDir == "" {
		workDir = os.TempDir()
	}
	workDir, err = filepath.Abs(workDir)
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp(workDir, "lindm-repository-bootstrap-v1-")
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil && vm == nil {
			err = errors.Join(err, os.RemoveAll(dir))
		}
	}()
	firmware, err := prepareEncryptedFirmware(ctx, dir, *h.Firmware)
	if err != nil {
		return nil, nil, err
	}
	loginPrivate, loginPublic, err := encryptedKey()
	if err != nil {
		return nil, nil, err
	}
	hostPrivate, hostPublic, err := encryptedKey()
	if err != nil {
		return nil, nil, err
	}
	config, err := encryptedSSHConfig(loginPrivate, hostPrivate)
	if err != nil {
		return nil, nil, err
	}
	recipe, err := tumbleweedInstallerProfile(release, image.GetVersion(), installerDisk(h.StorageBus), h.Architecture, verified.SHA256, loginPublic, string(hostPrivate), hostPublic, "", "", false, nil, true)
	if err != nil {
		return nil, nil, err
	}
	iso, err := openRegular(verified.Path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, iso.Close()) }()
	actual, err := digestInstalledImage(ctx, iso)
	if err != nil {
		return nil, nil, err
	}
	if actual.SHA256 != verified.SHA256 || actual.Size != verified.Size {
		return nil, nil, errors.New("verified repository bootstrap DVD changed before remastering")
	}
	installer, err := prepareInstallerFileForMachine(ctx, dir, iso, spec.installer, recipe, h.Architecture)
	if err != nil {
		return nil, nil, err
	}
	if _, err = hostCommand(ctx, dir, "qemu-img", nil, "create", "-f", "qcow2", "image", "24G"); err != nil {
		return nil, nil, err
	}
	spec.offline = true
	spec.diagnostics = newInstallerDiagnostics(diagnosticsDir, installerFailureOffline, h.Architecture, verified.SHA256, string(loginPrivate), loginPublic, string(hostPrivate), hostPublic, string(recipe))
	if err = runImageInstaller(ctx, dir, installer, spec, h); err != nil {
		return nil, nil, err
	}
	if err = os.Rename(filepath.Join(dir, "image"), filepath.Join(dir, "disk.qcow2")); err != nil {
		return nil, nil, err
	}
	boot := &EncryptedVM{dir: dir, hardware: h, firmware: firmware, config: config}
	if err = boot.start(ctx, ""); err != nil {
		return nil, nil, err
	}
	vm = boot.guest
	if err = vm.connect(ctx); err != nil {
		return vm, nil, err
	}
	probe := "set -eu; test \"$(cat /etc/lindm-repository-bootstrap)\" = repository-bootstrap-v1; " + installerSourceMarkerProbe(installerSourceMarkerPath, verified.SHA256) + "; . /etc/os-release; test \"$ID\" = " + nativeQuote(release.ID) + "; test \"$VERSION_ID\" = " + nativeQuote(image.GetVersion()) + "; command -v rpm; command -v rpmkeys; command -v zypper; ! command -v cloud-init"
	for _, pkg := range release.Lab.InstallerPackages {
		probe += "; rpm -q -- " + nativeQuote(pkg)
	}
	if _, err = vm.run(ctx, "sudo sh -eu -c "+nativeQuote(probe), nil, 1<<20, time.Minute); err != nil {
		return vm, nil, fmt.Errorf("offline DVD repository bootstrap readiness: %w", err)
	}
	return vm, verified, nil
}
