// SPDX-License-Identifier: Apache-2.0

//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"lindm/internal/packaging"
	"lindm/internal/releasebuild"
)

const installedAgentRepository = "/usr/share/lindmd/agent-repository"

// The installed lindmd package authenticates this local trust anchor. It is
// never obtained from the repository HTTP endpoint or from an enrollment device.
// Source-built fixture binaries carry the same payload beside their executable.
func loadBundledNativeRepositories(ctx context.Context) *nativeRepositories {
	directory := installedAgentRepository
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		executable, executableErr := os.Executable()
		if executableErr != nil {
			return unavailableNativeBundle(executableErr)
		}
		directory = filepath.Join(filepath.Dir(executable), "agent-repository")
	}
	return loadNativeBundle(ctx, directory)
}

func unavailableNativeBundle(err error) *nativeRepositories {
	err = fmt.Errorf("installed agent repository: %w", err)
	return &nativeRepositories{
		apt: &nativeRepository{err: err}, rpm: &nativeRepository{err: err}, arch: &nativeRepository{err: err},
	}
}

func loadNativeBundle(ctx context.Context, directory string) *nativeRepositories {
	if err := checkNativeBundleFiles(directory); err != nil {
		return unavailableNativeBundle(err)
	}
	public, err := os.ReadFile(filepath.Join(directory, "attestation.pub"))
	if err != nil {
		return unavailableNativeBundle(err)
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return unavailableNativeBundle(errors.New("release attestation public key is invalid"))
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return unavailableNativeBundle(err)
	}
	pin := sha256.Sum256(block.Bytes)
	manifest, err := releasebuild.Verify(ctx, directory, filepath.Join(directory, "attestation.pub"), hex.EncodeToString(pin[:]))
	if err != nil {
		return unavailableNativeBundle(fmt.Errorf("verify agent release: %w", err))
	}
	public, err = os.ReadFile(filepath.Join(directory, "package-signing.asc"))
	if err != nil {
		return unavailableNativeBundle(err)
	}
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(public))
	if err != nil || len(keys) != 1 {
		return unavailableNativeBundle(errors.New("release package signer must contain exactly one key"))
	}
	fingerprint := strings.ToUpper(hex.EncodeToString(keys[0].PrimaryKey.Fingerprint))
	if _, err := nativeSigningKeys(public, fingerprint); err != nil {
		return unavailableNativeBundle(err)
	}
	hashes := make(map[string]string, len(manifest.GetArtifacts()))
	for _, artifact := range manifest.GetArtifacts() {
		if artifact.GetProduct() != packaging.PackageName {
			return unavailableNativeBundle(errors.New("agent bundle contains a non-agent artifact"))
		}
		hashes[artifact.GetPath()] = artifact.GetSha256()
	}
	result := &nativeRepositories{
		apt:  loadNativeRepository(ctx, directory, "apt", fingerprint),
		rpm:  loadNativeRepository(ctx, directory, "rpm", fingerprint),
		arch: loadNativeRepository(ctx, directory, string(packaging.FormatArch), fingerprint),
	}
	for _, repository := range []*nativeRepository{result.apt, result.rpm, result.arch} {
		if repository.err != nil {
			continue
		}
		for name, file := range repository.files {
			if !strings.HasSuffix(name, ".deb") && !strings.HasSuffix(name, ".rpm") && !strings.HasSuffix(name, ".pkg.tar.zst") {
				continue
			}
			if hashes[filepath.Base(name)] != file.digest {
				repository.err = errors.New("native agent package does not match authenticated release attestation")
				break
			}
		}
	}
	return result
}

// Bound local artifact traversal before the release verifier reads documents.
// Neither symlinks nor group/world-writable files can supply installed trust.
func checkNativeBundleFiles(directory string) error {
	count := 0
	return filepath.Walk(directory, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 512 {
			return errors.New("agent bundle contains more than 512 filesystem entries")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("agent bundle path %q permits group or other writes", name)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("agent bundle path %q is not a regular file or directory", name)
		}
		if info.IsDir() {
			return nil
		}
		limit := int64(nativeMetadataLimit)
		if strings.HasSuffix(name, ".deb") || strings.HasSuffix(name, ".rpm") || strings.HasSuffix(name, ".pkg.tar.zst") {
			limit = nativePackageLimit
		}
		if info.Size() <= 0 || info.Size() > limit {
			return fmt.Errorf("agent bundle file %q is empty or exceeds %d bytes", name, limit)
		}
		return nil
	})
}
