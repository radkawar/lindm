// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func buildArchRejectionFixtures(ctx context.Context, req RejectionRequest) (result *RejectionFixtures, err error) {
	if req.Arch.Format != FormatArch || req.DEB.Format != "" || req.RPM.Format != "" || req.APT != nil {
		return nil, fmt.Errorf("%w: Arch rejection inputs must be Arch-only", ErrArtifact)
	}
	if req.Signer.Custody != CustodyDevelopment {
		return nil, fmt.Errorf("%w: rejection fixtures require development custody", ErrSigner)
	}
	out, err := openPrivate(req.OutputDir)
	if err != nil {
		return nil, err
	}
	entries, readErr := out.Readdirnames(1)
	closeErr := out.Close()
	if closeErr != nil || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return nil, errors.Join(closeErr, readErr)
	}
	if len(entries) != 0 || within(req.Arch.Path, req.OutputDir) || within(req.OutputDir, req.Signer.Home) {
		return nil, fmt.Errorf("%w: rejection output must be empty and separate", ErrUnsafePath)
	}
	work, cleanup, err := privateWork(req.OutputDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, cleanup())
		if err != nil {
			result = nil
		}
	}()
	key, guard, err := validateSigner(ctx, work, req.Signer)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, guard.close(ctx, work))
		if err != nil {
			result = nil
		}
	}()
	artifact := req.Arch
	positive, size, err := snapshotPositiveArch(ctx, work, key, artifact)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(positive)
	wrong, wrongGuard, err := generateDevelopmentSigner(ctx, work)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, wrongGuard.close(ctx, work))
		if err != nil {
			result = nil
		}
	}()
	if wrong.Fingerprint == key.Fingerprint {
		return nil, ErrSigner
	}
	staged := filepath.Join(work, "fixtures")
	result = &RejectionFixtures{WrongSignerFingerprint: wrong.Fingerprint}
	for _, kind := range []string{"unsigned", "tampered", "wrong-signer"} {
		dir := filepath.Join(staged, kind, string(FormatArch))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		variant := artifact
		variant.Path = filepath.Join(dir, name)
		variant.SignaturePath = ""
		variant.Signed = false
		variant.SignerFingerprint = ""
		if err := archCopyInput(positive, variant.Path, maxBinaryBytes+(8<<20), DefaultSourceDateEpoch); err != nil {
			return nil, err
		}
		switch kind {
		case "tampered":
			if err := archCopyInput(positive+".sig", variant.Path+".sig", 64<<10, DefaultSourceDateEpoch); err != nil {
				return nil, err
			}
			if err := rejectionFlipByte(variant.Path, size/2); err != nil {
				return nil, err
			}
			variant.PayloadSHA256 = ""
			variant.SignaturePath = variant.Path + ".sig"
			variant.SignerFingerprint = key.Fingerprint
		case "wrong-signer":
			if err := signArchFile(ctx, work, variant.Path, *wrong, DefaultSourceDateEpoch); err != nil {
				return nil, err
			}
			variant.SignaturePath = variant.Path + ".sig"
			variant.SignerFingerprint = wrong.Fingerprint
		}
		variant.SHA256, variant.Size, err = hashFile(variant.Path)
		if err != nil {
			return nil, err
		}
		variant.UnsignedSHA256 = variant.SHA256
		result.Cases = append(result.Cases, RejectionCase{Name: kind, Artifact: variant})
	}
	if err := errors.Join(wrongGuard.close(ctx, work), guard.close(ctx, work)); err != nil {
		return nil, err
	}
	final := filepath.Join(req.OutputDir, "fixtures")
	if err := os.Rename(staged, final); err != nil {
		return nil, err
	}
	for i := range result.Cases {
		artifact := &result.Cases[i].Artifact
		artifact.Path = final + strings.TrimPrefix(artifact.Path, staged)
		if artifact.SignaturePath != "" {
			artifact.SignaturePath = artifact.Path + ".sig"
		}
	}
	return result, syncDir(req.OutputDir)
}

// snapshotPositiveArch copies the canonical positive Arch package and signature
// into work and proves they are the development signer's matching build. It
// returns the copied package path and size.
func snapshotPositiveArch(ctx context.Context, work string, key SigningKey, artifact Artifact) (string, int64, error) {
	if !artifact.Signed || artifact.SignerFingerprint != key.Fingerprint || artifact.SignaturePath != artifact.Path+".sig" {
		return "", 0, fmt.Errorf("%w: positive Arch input must have the development signer", ErrSigner)
	}
	if _, err := parseVersion(artifact.Version); err != nil {
		return "", 0, err
	}
	name := fmt.Sprintf("%s-%s-%s-%s.pkg.tar.zst", PackageName, artifact.Version, archRelease, artifact.Architecture.Arch)
	if filepath.Base(artifact.Path) != name {
		return "", 0, fmt.Errorf("%w: noncanonical positive Arch path", ErrArtifact)
	}
	positive := filepath.Join(work, name)
	if err := archCopyInput(artifact.Path, positive, maxBinaryBytes+(8<<20), DefaultSourceDateEpoch); err != nil {
		return "", 0, err
	}
	if err := archCopyInput(artifact.SignaturePath, positive+".sig", 64<<10, DefaultSourceDateEpoch); err != nil {
		return "", 0, err
	}
	sum, size, err := hashFile(positive)
	if err != nil || sum != artifact.SHA256 || size != artifact.Size {
		return "", 0, fmt.Errorf("%w: positive Arch digest differs: %v", ErrArtifact, err)
	}
	public, _, err := exportPublicKeys(ctx, work, key, work)
	if err != nil {
		return "", 0, err
	}
	if err := verifyArchSignature(ctx, work, positive, public); err != nil {
		return "", 0, err
	}
	info, err := readArchInfo(positive)
	if err != nil {
		return "", 0, err
	}
	if info["pkgver"][0] != artifact.Version+"-"+archRelease || info[pkgInfoArch][0] != artifact.Architecture.Arch {
		return "", 0, fmt.Errorf("%w: positive Arch metadata differs", ErrArtifact)
	}
	return positive, size, nil
}
