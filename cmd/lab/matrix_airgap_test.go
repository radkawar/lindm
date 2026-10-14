// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"path/filepath"
	"testing"

	"buf.build/go/protovalidate"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
)

// A bundle must authorize both native architectures and package managers, but
// must not propose server, CLI or OCI artifacts as agent self-updates.
func TestMatrixAirgapChannelSelectsNativeAgents(t *testing.T) {
	release := &releasev1.ReleaseManifest{Version: "0.1.1"}
	for _, product := range []string{"lindm-agent", "lindmd", "lindmctl"} {
		for _, arch := range []string{"amd64", "arm64"} {
			for _, format := range []string{"deb", "rpm", "oci"} {
				release.Artifacts = append(release.Artifacts, &releasev1.ReleaseArtifact{Product: product, Architecture: arch, Format: format, Path: product + "-" + arch + "." + format})
			}
		}
	}
	directory := t.TempDir()
	channel, files := matrixAirgapChannel(release, directory, 2)
	if err := protovalidate.Validate(channel); err != nil {
		t.Fatal(err)
	}
	if len(channel.Artifacts) != 4 || len(files) != 4 || channel.Generation != 2 || !channel.Paused {
		t.Fatalf("incorrect native channel: %v", channel)
	}
	for _, artifact := range channel.Artifacts {
		name := "lindm-agent-" + artifact.Architecture + "." + artifact.PackageFormat
		if files[artifact.TargetPath] != filepath.Join(directory, name) {
			t.Fatalf("target lost attested package binding: %v", artifact)
		}
		native := release.Version
		if artifact.PackageFormat == "rpm" {
			native += "-" + packaging.RPMRelease
		}
		if artifact.Version != release.Version || artifact.NativeVersion != native {
			t.Fatalf("native version lost package-manager spelling: %v", artifact)
		}
	}
}
