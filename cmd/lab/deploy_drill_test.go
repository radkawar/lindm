// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestDeployDrillRejectsMutableOrForeignImageAuthority(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	for _, image := range []string{
		"postgres:17", "docker.io/library/postgres:18",
		"docker.io/other/postgres@sha256:" + digest,
		"example.test/library/postgres@sha256:" + digest,
		"docker.io/library/postgres@sha256:" + strings.ToUpper(digest),
		"docker.io/library/postgres@sha256:" + strings.Repeat("g", 64),
		"docker.io/library/postgres@sha256:" + digest[:63],
	} {
		if err := validateDeployDrillImage(image); err == nil {
			t.Fatalf("accepted mutable or unapproved image authority %q", image)
		}
	}
	if err := validateDeployDrillImage("docker.io/library/postgres@sha256:" + digest); err != nil {
		t.Fatal(err)
	}
}

func TestDeployDrillMountPathsCannotInjectFields(t *testing.T) {
	for _, path := range []string{"", "/private/archive,readonly=false", "/private/archive\nother"} {
		if _, err := deployDrillContainerArgs("owned", "pinned", "/private/lindmd", path, "/private/identity"); err == nil {
			t.Fatalf("accepted ambiguous mount source %q", path)
		}
	}
}
