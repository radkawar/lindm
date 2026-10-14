// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	releasev1 "lindm/gen/lindm/release/v1"
	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/devlab"
	"lindm/internal/labmatrix"
	"lindm/internal/offlinebundle"
	"lindm/internal/packaging"
	"lindm/internal/releasebuild"
	"lindm/internal/releaseupdate"
	"lindm/internal/vmlab"
)

// prepareAirgap uses the release and bundle builders, not a second packaging
// recipe. The two complete attested releases are shared by all selected guests;
// each release/architecture gets its registry-derived vendor advisory snapshots.
func (r *matrixRun) prepareAirgap(ctx context.Context, cells []*labmatrix.Cell, stderr io.Writer) error {
	var selected []*labmatrix.Cell
	for _, c := range cells {
		if c.Spec.GetLane() == "airgap" {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	dir := filepath.Join(r.evidence, "inputs", "airgap")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	signer, err := packaging.GenerateDevelopmentSigner(ctx, dir)
	if err != nil {
		return err
	}
	releaseKey := filepath.Join(dir, "release-key")
	releaseID, err := releasebuild.GenerateDevelopmentKey(releaseKey)
	if err != nil {
		return err
	}
	bundleKey := filepath.Join(dir, "bundle-key")
	bundleID, err := offlinebundle.GenerateDevelopmentKey(bundleKey)
	if err != nil {
		return err
	}
	// These development-only OCI artifacts use the explicit lab trust input,
	// never an ambient host CA bundle. Their digest remains in release evidence.
	ca := filepath.Join(devlab.FixturePath(r.repo), "transport-ca.crt")
	caSHA, err := labmatrix.FileSHA256(ca)
	if err != nil {
		return err
	}
	var releases [2]*releasev1.ReleaseManifest
	var paths [2]string
	epoch := time.Now().UTC().Unix()
	for i, version := range matrixVersions {
		paths[i] = filepath.Join(dir, "release-"+version)
		_, _ = fmt.Fprintln(stderr, "lab release build", version)
		buildCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
		releases[i], err = releasebuild.Build(buildCtx, releasebuild.Request{
			Repository: r.root, Output: paths[i], Version: version, Revision: r.revision, SourceDateEpoch: epoch,
			PackageSigner: *signer, OCICABundle: ca, OCICASHA256: caSHA,
			AttestationSigner: releasebuild.AttestationKey{Path: filepath.Join(releaseKey, "attestation.pem"), KeyID: releaseID, Custody: "development"},
		})
		cancel()
		if err != nil {
			return err
		}
	}
	r.airgap = make(map[string][]string)
	for _, c := range selected {
		key := c.Release.Key + "/" + c.Architecture
		if _, exists := r.airgap[key]; exists {
			continue
		}
		work := filepath.Join(dir, c.Release.Key+"-"+c.Architecture)
		if err := os.Mkdir(work, 0700); err != nil {
			return err
		}
		// Registry-declared partial coverage is recorded by the lane, as in the
		// advisories lane; only feeds with a maintained export are acquired.
		cfg, err := vmlab.AirgapAdvisories(c.Release, c.Manifest.Image.GetVersion(), c.Architecture)
		if err != nil {
			return err
		}
		cfg.RefreshEnabled = false // acquisition occurs at the connected station only.
		data, err := protojson.Marshal(cfg)
		if err != nil {
			return err
		}
		advisories := filepath.Join(work, "advisories.json")
		if err := os.WriteFile(advisories, data, 0600); err != nil {
			return err
		}
		keys, online := filepath.Join(work, "tuf-keys"), filepath.Join(work, "tuf-online")
		if err := releaseupdate.GenerateDevelopmentKeys(keys); err != nil {
			return err
		}
		if err := os.Mkdir(online, 0700); err != nil {
			return err
		}
		for _, role := range []string{"rollout", "snapshot", "timestamp"} {
			data, err := os.ReadFile(filepath.Join(keys, role+".pem"))
			if err != nil {
				return err
			}
			err = os.WriteFile(filepath.Join(online, role+".pem"), data, 0600)
			clear(data)
			if err != nil {
				return err
			}
		}
		signers, err := releaseupdate.LoadRoleSigners(keys, true)
		if err != nil {
			return err
		}
		repository := filepath.Join(work, "repository")
		publisher, err := releaseupdate.CreateRepository(ctx, releaseupdate.PublisherConfig{Directory: repository, Signers: signers})
		if err != nil {
			return err
		}
		rootPath := filepath.Join(repository, "metadata", "1.root.json")
		root, err := os.ReadFile(rootPath)
		if err != nil {
			return err
		}
		request := offlinebundle.ExportRequest{
			Validity: 24 * time.Hour, ReleasePublicKey: filepath.Join(releaseKey, "attestation.pub"), ReleaseKeyID: releaseID,
			PackageSigner: *signer, UpdatesRepository: repository, UpdatesRoot: root, Rings: []string{"canary"},
			Feeds: cfg.Feeds, HTTPClient: &http.Client{},
			Signer: offlinebundle.SigningKey{Path: filepath.Join(bundleKey, "bundle.pem"), KeyID: bundleID, Custody: "development"},
		}
		for i, name := range []string{"b1", "b2", "b3", "expired"} {
			version := 0
			if i >= 2 {
				version = 1
			}
			if i == 0 || i == 2 {
				channel, files := matrixAirgapChannel(releases[version], paths[version], uint64(version+1))
				if err := publisher.Publish(ctx, channel, files); err != nil {
					return err
				}
			}
			request.Output, request.Release, request.Sequence = filepath.Join(work, name), paths[version], uint64(i+1)
			if name == "expired" {
				request.Validity = time.Nanosecond
				request.Feeds = nil // expiry is rejected before advisory import.
			}
			_, _ = fmt.Fprintln(stderr, "lab bundle export", key, name)
			exportCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
			_, err := offlinebundle.Export(exportCtx, request)
			cancel()
			if err != nil {
				return err
			}
		}
		// Every complete bundle carries both repository formats signed by the
		// same pinned key. Its ASCII armor is manager-independent.
		publicKey := filepath.Join(work, "b1", "repositories", packagingArchitecture(c.Architecture), "apt", "lindm-package-signing.asc")
		r.airgap[key] = []string{
			"-first-bundle", filepath.Join(work, "b1"), "-second-bundle", filepath.Join(work, "b3"),
			"-replay-bundle", filepath.Join(work, "b2"), "-expired-bundle", filepath.Join(work, "expired"),
			"-bundle-public-key", filepath.Join(bundleKey, "bundle.pub"), "-bundle-key-id", bundleID,
			"-release-public-key", request.ReleasePublicKey, "-release-key-id", releaseID,
			"-release-root", rootPath, "-release-online-keys", online,
			"-package-public-key", publicKey, "-package-fingerprint", signer.Fingerprint, "-advisories", advisories,
		}
	}
	return nil
}

func matrixAirgapChannel(release *releasev1.ReleaseManifest, directory string, generation uint64) (*updatev1.AgentUpdateChannel, map[string]string) {
	now := time.Now().UTC()
	channel := &updatev1.AgentUpdateChannel{Ring: "canary", Generation: generation, Paused: true, EligiblePercentage: 100, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(24 * time.Hour))}
	files := make(map[string]string)
	for _, artifact := range release.GetArtifacts() {
		if artifact.GetProduct() != "lindm-agent" || artifact.GetFormat() == "oci" {
			continue
		}
		target := "packages/lindm-agent/" + artifact.GetArchitecture() + "/" + artifact.GetPath()
		native := release.GetVersion()
		switch artifact.GetFormat() {
		case "rpm":
			native += "-" + packaging.RPMRelease
		case string(packaging.FormatArch):
			native += "-1" // pacman reports pkgver-pkgrel; lindm packages use pkgrel 1.
		}
		update := &updatev1.AgentUpdateArtifact{Version: release.GetVersion(), Architecture: artifact.GetArchitecture(), PackageFormat: artifact.GetFormat(), TargetPath: target, NativeVersion: native, MinimumAgentVersion: "0.0.0", MaximumAgentVersion: "1.0.0", MinimumProtocolVersion: 1, MaximumProtocolVersion: 1}
		files[target] = filepath.Join(directory, artifact.GetPath())
		if signature := artifact.GetNativeSignaturePath(); signature != "" {
			update.SignatureTargetPath = target + ".sig"
			files[update.SignatureTargetPath] = filepath.Join(directory, signature)
		}
		channel.Artifacts = append(channel.Artifacts, update)
	}
	return channel, files
}
