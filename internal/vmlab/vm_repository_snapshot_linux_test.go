// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/vmlab/reposnapshot"
)

func TestTumbleweedSnapshotRequiresCapturedClosure(t *testing.T) {
	manifest := &labv1.ImageManifest{Distribution: "opensuse-tumbleweed", Version: "20261007", Architecture: "arm64", RepositorySnapshotDate: proto.String("2026-10-07")}
	server, err := startImageRepositorySnapshot(context.Background(), manifest, t.TempDir(), "127.0.0.1")
	if err == nil || server != nil {
		t.Fatal("uncaptured Tumbleweed repository was accepted")
	}
}

func TestRollingSnapshotDesiredBindsVerifiedMetadata(t *testing.T) {
	digest := strings.Repeat("a", 64)
	manifest := &labv1.ImageManifest{Distribution: "opensuse-tumbleweed", Version: "20261007", Architecture: "arm64", RepositorySnapshotDate: proto.String("2026-10-07")}
	server := &reposnapshot.Server{URL: "https://127.0.0.1:12345/snapshots/closure/", Manifest: &labv1.RepositorySnapshotManifest{SnapshotDate: "2026-10-07", RepomdSha256: digest}}
	desired := rollingSnapshotDesired(manifest, &guestRollingSnapshot{Server: server})
	if desired.GetDate() != "2026-10-07" || desired.GetRepositoryUrl() != server.URL || hex.EncodeToString(desired.GetMetadataSha256()) != digest {
		t.Fatalf("desired snapshot lost exact verified identity: %v", desired)
	}
}

func TestGoldenIdentityBindsClosureNotEphemeralOrigin(t *testing.T) {
	manifest := &labv1.ImageManifest{Distribution: "opensuse-tumbleweed", Version: "20261007", Architecture: "arm64", Sha256: strings.Repeat("b", 64), RepositorySnapshotManifestSha256: proto.String(strings.Repeat("a", 64))}
	first := encryptedGoldenID(manifest, EncryptedVMOptions{}, "code", "vars", "", true)
	manifest.RepositorySnapshotManifestSha256 = proto.String(strings.Repeat("c", 64))
	second := encryptedGoldenID(manifest, EncryptedVMOptions{}, "code", "vars", "", true)
	if first == second {
		t.Fatal("different captured closures share a golden identity")
	}
}
