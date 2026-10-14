// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
)

type bundleMember struct {
	name, sum string
	size      int64
}

func bundleDigests(directory string) ([]bundleMember, error) {
	var members []bundleMember
	var total int64
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("releasebuild: repository link or special file")
		}
		sum, size, err := digestFile(path)
		if err != nil {
			return err
		}
		total += size
		if len(members) >= 8192 || total > 4<<30 {
			return errors.New("releasebuild: agent repository exceeds bound")
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		members = append(members, bundleMember{name: name, sum: sum, size: size})
		return nil
	})
	return members, err
}

func verifyEmbeddedRepository(ctx context.Context, directory string, manifest *releasev1.ReleaseManifest, pin string) (string, error) {
	server := false
	for _, artifact := range manifest.GetArtifacts() {
		server = server || artifact.GetProduct() == "lindmd"
	}
	if !server {
		return "", nil
	}
	bundle := filepath.Join(directory, "agent-repository")
	// The subset must not contain a server, avoiding recursive/unbounded bundles.
	document, err := readBounded(filepath.Join(bundle, "release.json"), maxDocument)
	if err != nil {
		return "", err
	}
	subset := new(releasev1.ReleaseManifest)
	if err := protojson.Unmarshal(document, subset); err != nil {
		return "", err
	}
	for _, artifact := range subset.GetArtifacts() {
		if artifact.GetProduct() != "lindm-agent" {
			return "", errors.New("releasebuild: embedded repository contains a non-agent")
		}
	}
	subset, err = Verify(ctx, bundle, filepath.Join(bundle, "attestation.pub"), pin)
	if err != nil {
		return "", err
	}
	if err := verifyRepositoryPayloads(bundle, subset); err != nil {
		return "", err
	}
	if subset.GetSourceSha256() != manifest.GetSourceSha256() || subset.GetVersion() != manifest.GetVersion() || subset.GetRevision() != manifest.GetRevision() || subset.GetCustody() != manifest.GetCustody() || subset.GetSourceDateEpoch() != manifest.GetSourceDateEpoch() {
		return "", errors.New("releasebuild: embedded agent release identity mismatch")
	}
	agents := map[string]string{}
	for _, artifact := range manifest.GetArtifacts() {
		if artifact.GetProduct() == "lindm-agent" {
			agents[artifact.GetPath()] = artifact.GetSha256()
		}
	}
	if len(agents) != len(subset.GetArtifacts()) {
		return "", errors.New("releasebuild: embedded agent release matrix mismatch")
	}
	for _, artifact := range subset.GetArtifacts() {
		if agents[artifact.GetPath()] != artifact.GetSha256() {
			return "", errors.New("releasebuild: embedded agent release digest mismatch")
		}
	}
	return bundle, nil
}

func verifyRepositoryPayloads(directory string, manifest *releasev1.ReleaseManifest) error {
	key, err := readBounded(filepath.Join(directory, "package-signing.asc"), 1<<20)
	if err != nil {
		return err
	}
	for _, format := range []string{"apt", "rpm", string(packaging.FormatArch)} {
		repositoryKey, err := readBounded(filepath.Join(directory, "repo", format, "lindm-package-signing.asc"), 1<<20)
		if err != nil {
			return err
		}
		if !bytes.Equal(key, repositoryKey) {
			return errors.New("releasebuild: repository package key differs from bundled key")
		}
	}
	allowed := map[string]string{}
	for _, artifact := range manifest.GetArtifacts() {
		if artifact.GetProduct() != "lindm-agent" {
			return errors.New("releasebuild: repository manifest contains a non-agent")
		}
		allowed[artifact.GetPath()] = artifact.GetSha256()
	}
	seen := map[string]bool{}
	members, err := bundleDigests(filepath.Join(directory, "repo"))
	if err != nil {
		return err
	}
	for _, member := range members {
		name := filepath.Base(member.name)
		if !strings.HasSuffix(name, ".deb") && !strings.HasSuffix(name, ".rpm") && !strings.HasSuffix(name, ".pkg.tar.zst") {
			continue
		}
		if allowed[name] != member.sum || seen[name] {
			return errors.New("releasebuild: repository package absent from signed agent manifest")
		}
		seen[name] = true
	}
	if len(seen) != len(allowed) {
		return errors.New("releasebuild: repository omits a signed agent package")
	}
	return nil
}

func verifyBundleProvenance(provenance json.RawMessage, digest string) error {
	var document struct {
		Definition struct {
			Dependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
	}
	if err := json.Unmarshal(provenance, &document); err != nil {
		return err
	}
	found := false
	for _, dependency := range document.Definition.Dependencies {
		if dependency.URI != "urn:lindm:canonical-agent-repository-after-unsigned-agreement" {
			continue
		}
		if found || dependency.Digest["sha256"] != digest {
			return errors.New("releasebuild: canonical agent repository provenance mismatch")
		}
		found = true
	}
	if !found {
		return errors.New("releasebuild: canonical agent repository provenance missing")
	}
	return nil
}
