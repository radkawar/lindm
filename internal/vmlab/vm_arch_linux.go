//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/packaging"
)

// pinArchRepositories changes only the disposable guest's mirror selection. The
// immutable signed cloud image supplies the initial package state; every later
// vendor transaction is restricted to this dated Arch Linux Archive snapshot.
func pinArchRepositories(ctx context.Context, vm *guestVM, manifest *labv1.ImageManifest) error {
	if manifest.GetDistribution() != "arch" {
		return nil
	}
	date, err := time.Parse("2006-01-02", manifest.GetRepositorySnapshotDate())
	if err != nil {
		return errors.New("arch guest requires an exact repository snapshot date")
	}
	mirror := "Server = https://archive.archlinux.org/repos/" + date.Format("2006/01/02") + "/$repo/os/$arch\n"
	_, err = vm.run(ctx, "sudo -n sh -eu -c 'test -f /etc/pacman.conf; test -d /etc/pacman.d; cat > /etc/pacman.d/mirrorlist'", strings.NewReader(mirror), 4096, time.Minute)
	return err
}

func (p *nativeGuestPackages) pacmanCommand(action string) string {
	return "pacman --noconfirm --config " + nativeGuestDir + "/pacman.conf " + action
}

func (p *nativeGuestPackages) prepareArch(ctx context.Context, fingerprint string) error {
	if err := p.command(ctx, "initialize isolated pacman trust", "install -d -m 0700 "+nativeGuestDir+"/pacman-gnupg; pacman-key --gpgdir "+nativeGuestDir+"/pacman-gnupg --init; pacman-key --gpgdir "+nativeGuestDir+"/pacman-gnupg --add "+p.keyPath+"; pacman-key --gpgdir "+nativeGuestDir+"/pacman-gnupg --lsign-key "+nativeQuote(fingerprint), nil); err != nil {
		return err
	}
	// The only admitted package signer was explicitly pinned above. Negative
	// fixtures must not discover keys through an operator's public keyserver.
	if err := p.uploadBytes(ctx, nativeGuestDir+"/pacman-gnupg/gpg.conf", []byte("no-auto-key-retrieve\nauto-key-locate clear\nkeyserver hkp://127.0.0.1:9\nkeyserver-options timeout=5\n")); err != nil {
		return err
	}
	config := "[options]\nArchitecture = auto\nGPGDir = " + nativeGuestDir + "/pacman-gnupg\nCacheDir = " + nativeGuestDir + "/archives\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n[lindm]\nSigLevel = Required TrustedOnly\nServer = file://" + nativeGuestDir + "/repo\n"
	return p.uploadBytes(ctx, nativeGuestDir+"/pacman.conf", []byte(config))
}

func (p *nativeGuestPackages) installArch(ctx context.Context, artifact packaging.Artifact) error {
	var repository *packaging.ArchRepository
	for _, candidate := range p.arch {
		if candidate == nil {
			continue
		}
		if info, err := os.Stat(filepath.Join(candidate.Root, filepath.Base(artifact.Path))); err == nil && info.Mode().IsRegular() {
			repository = candidate
			break
		}
	}
	if repository == nil {
		return errors.New("arch lifecycle requires a signed repository for each package version")
	}
	if err := p.command(ctx, "prepare signed pacman repository", "install -d -m 0755 "+nativeGuestDir+"/repo", nil); err != nil {
		return err
	}
	for _, name := range []string{"lindm.db", "lindm.db.sig", filepath.Base(artifact.Path) + ".sig"} {
		data, err := readRegular(filepath.Join(repository.Root, name), 4<<20)
		if err != nil {
			return fmt.Errorf("read signed pacman repository entry: %w", err)
		}
		if err := p.uploadBytes(ctx, nativeGuestDir+"/repo/"+name, data); err != nil {
			return err
		}
	}
	if err := p.uploadArtifact(ctx, artifact, nativeGuestDir+"/repo/"+filepath.Base(artifact.Path)); err != nil {
		return err
	}
	return p.command(ctx, "install from authenticated pacman repository", p.pacmanCommand("-Syy lindm/lindm-agent"), nil)
}

func (p *nativeGuestPackages) rejectArch(ctx context.Context, artifact packaging.Artifact) (guestCommandResult, error) {
	destination := nativeGuestDir + "/rejected.pkg.tar.zst"
	if err := p.uploadArtifact(ctx, artifact, destination); err != nil {
		return guestCommandResult{}, err
	}
	if err := p.command(ctx, "clear prior detached signature", "rm -f "+destination+".sig", nil); err != nil {
		return guestCommandResult{}, err
	}
	if artifact.SignaturePath != "" {
		data, err := readRegular(artifact.SignaturePath, 1<<20)
		if err != nil {
			return guestCommandResult{}, err
		}
		if err := p.uploadBytes(ctx, destination+".sig", data); err != nil {
			return guestCommandResult{}, err
		}
	}
	return p.result(ctx, p.pacmanCommand("-U "+destination), nil)
}
