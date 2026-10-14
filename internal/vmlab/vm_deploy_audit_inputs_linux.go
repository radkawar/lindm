// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
)

type deployAuditNativeInputs struct {
	PackagePath     string
	PackageSHA256   string
	PublicKeyPath   string
	PublicKeySHA256 string
}

// snapshotDeployAuditNativeInputs consumes only an already authenticated manifest.
// The historical public key is not in that manifest: its independent pin is a
// separate required RPM trust input, never attributed to release authentication.
func snapshotDeployAuditNativeInputs(ctx context.Context, release, private, format, keySHA256, keyFingerprint string, manifest *releasev1.ReleaseManifest) (*deployAuditNativeInputs, error) {
	var selected *releasev1.ReleaseArtifact
	for _, entry := range manifest.GetArtifacts() {
		if entry.GetProduct() != "lindmd" || entry.GetFormat() != format || entry.GetArchitecture() != "amd64" {
			continue
		}
		if selected != nil {
			return nil, errors.New("ambiguous signed historical server package")
		}
		selected = entry
	}
	if selected == nil {
		return nil, errors.New("signed historical baseline lacks native server package")
	}
	name := selected.GetPath()
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || filepath.IsAbs(name) {
		return nil, errors.New("historical native artifact path must be a single manifest-bound member")
	}
	if selected.GetSize() == 0 || selected.GetSize() > 256<<20 {
		return nil, errors.New("historical native artifact exceeds its bound")
	}
	directory, err := os.MkdirTemp(private, "authenticated-inputs-")
	if err != nil {
		return nil, err
	}
	result := &deployAuditNativeInputs{PackagePath: filepath.Join(directory, name), PackageSHA256: selected.GetSha256()}
	if err := snapshotDeployAuditInput(ctx, filepath.Join(release, name), result.PackagePath, selected.GetSha256(), int64(selected.GetSize()), 256<<20); err != nil {
		return nil, err
	}
	if format == "rpm" {
		result.PublicKeyPath = filepath.Join(directory, "package-signing.asc")
		result.PublicKeySHA256 = keySHA256
		if err := snapshotDeployAuditInput(ctx, filepath.Join(release, "package-signing.asc"), result.PublicKeyPath, keySHA256, 0, 1<<20); err != nil {
			return nil, err
		}
		key, err := os.ReadFile(result.PublicKeyPath)
		if err != nil {
			return nil, err
		}
		if err := packaging.ValidateNativePublicKey(key, keyFingerprint); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func snapshotDeployAuditInput(ctx context.Context, source, destination, expectedSHA string, expectedSize, maxSize int64) error {
	decoded, err := hex.DecodeString(expectedSHA)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("historical native input requires an independently authenticated SHA256")
	}
	before, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxSize || (expectedSize != 0 && before.Size() != expectedSize) {
		return errors.New("historical native input is not a bounded regular file matching its authenticated size")
	}
	hash := sha256.New()
	if err := copyServerInput(ctx, source, destination, before, hash, make([]byte, 64<<10)); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		return errors.New("historical native input differs from its authenticated digest")
	}
	return os.Chmod(destination, 0400)
}
