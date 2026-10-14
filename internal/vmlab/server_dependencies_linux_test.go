// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"strings"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
)

func TestDependencyReplayRequiresExactAuthenticatedImageTuple(t *testing.T) {
	digest := strings.Repeat("a", 64)
	image := &labv1.ImageManifest{Distribution: "ubuntu", Version: "24.04", Architecture: "amd64", Sha256: digest}
	manifest := &serverdepsv1.Manifest{Distribution: "ubuntu", Version: "24.04", Architecture: "amd64", Backend: serverdepsv1.Backend_BACKEND_DEB, BaseImageSha256: digest}
	if err := dependencyReplayTarget(image, manifest); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*serverdepsv1.Manifest){
		func(m *serverdepsv1.Manifest) { m.Distribution = "rhel" },
		func(m *serverdepsv1.Manifest) { m.Version = "26.04" },
		func(m *serverdepsv1.Manifest) { m.Architecture = "arm64" },
		func(m *serverdepsv1.Manifest) { m.Backend = serverdepsv1.Backend_BACKEND_RPM },
		func(m *serverdepsv1.Manifest) { m.BaseImageSha256 = strings.Repeat("b", 64) },
	} {
		candidate := &serverdepsv1.Manifest{Distribution: "ubuntu", Version: "24.04", Architecture: "amd64", Backend: serverdepsv1.Backend_BACKEND_DEB, BaseImageSha256: digest}
		mutate(candidate)
		if err := dependencyReplayTarget(image, candidate); err == nil {
			t.Fatal("mismatched immutable closure accepted for replay image")
		}
	}
}

func TestDependencyReplayRejectsUnpinnedHelperBeforeGuestCreation(t *testing.T) {
	image := &labv1.ImageManifest{Distribution: "ubuntu", Version: "24.04", Architecture: "amd64"}
	for _, options := range []ServerDependenciesOptions{
		{},
		{LabBinary: "/missing/helper"},
		{LabBinary: "/missing/helper", LabSHA256: strings.Repeat("G", 64)},
		{LabBinary: "/missing/helper", LabSHA256: strings.Repeat("a", 63)},
	} {
		if _, _, err := ReplayServerDependencies(context.Background(), image, strings.Repeat("a", 64), options); err == nil || !strings.Contains(err.Error(), "SHA256-pinned") {
			t.Fatalf("unpinned helper was not refused before snapshot or VM access: %v", err)
		}
	}
}
