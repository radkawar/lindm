// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"lindm/internal/platform"
)

func TestDemoRepositoryMediaPinsReadOnlyDescriptor(t *testing.T) {
	manifest, receipt, source := vendorFixture(t)
	manifest.ImageFilename, receipt.ImageFilename = "rhel-9.8-x86_64-dvd.iso", "rhel-9.8-x86_64-dvd.iso"
	encoded, err := protojson.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(t.TempDir(), "cache")
	verified, err := ImportVendorImage(t.Context(), manifest, cache, source, encoded)
	if err != nil {
		t.Fatal(err)
	}
	recipe := platform.ForManifest("rhel", "9.8").Lab.RPMMedia
	media, err := openDemoRepositoryMedia(t.Context(), manifest, recipe, cache)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = media.Close() })
	if _, err := media.WriteAt([]byte("mutation"), 0); err == nil {
		t.Fatal("repository media descriptor permits writing")
	}
	if err := os.Rename(verified.Path, verified.Path+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(verified.Path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	pinned, err := digestInstalledImage(t.Context(), media)
	if err != nil || pinned.SHA256 != manifest.Sha256 {
		t.Fatalf("borrowed descriptor changed with cache path: %v, %v", pinned, err)
	}
	if _, err := openDemoRepositoryMedia(t.Context(), manifest, recipe, cache); err == nil {
		t.Fatal("changed cache media accepted")
	}
}

func TestDemoRepositoryMediaNotNeeded(t *testing.T) {
	media, err := openDemoRepositoryMedia(t.Context(), nil, nil, "unused")
	if err != nil || media != nil {
		t.Fatalf("release without DVD repositories accessed media: %v, %v", media, err)
	}
}

func TestDemoRepositoryMediaBootAndTrust(t *testing.T) {
	for _, architecture := range []string{"x86_64", "aarch64"} {
		args := strings.Join(encryptedRepositoryMediaArguments(architecture), " ")
		for _, required := range []string{"readonly=on", "format=raw", "file=/proc/self/fd/3", "media=cdrom", "bootindex=9"} {
			if !strings.Contains(args, required) {
				t.Fatalf("%s media lacks %s: %s", architecture, required, args)
			}
		}
	}
	recipe := platform.ForManifest("rhel", "9.8").Lab.RPMMedia
	if recipe == nil {
		t.Fatal("RHEL Binary DVD repository recipe missing")
	}
	script := demoRepositoryMediaScript(recipe)
	for _, required := range []string{"Options=ro", "WantedBy=local-fs.target", "enable --now mnt-lindmvendor.mount", "baseurl=file:///mnt/lindmvendor/BaseOS", "baseurl=file:///mnt/lindmvendor/AppStream", "gpgcheck=1", "localpkg_gpgcheck=1", "gpgkey=file://" + recipe.Key} {
		if !strings.Contains(script, required) {
			t.Fatalf("offline repository lacks %q", required)
		}
	}
	for _, forbidden := range []string{"https://", "http://", "subscription-manager", "gpgcheck=0", "repo_gpgcheck="} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("offline repository introduces %q", forbidden)
		}
	}
}
