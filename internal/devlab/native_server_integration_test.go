// SPDX-License-Identifier: Apache-2.0

//go:build integration

package devlab

import (
	"os"
	"testing"
)

// nativeServer returns the release-stamped lindmd and initialized repository
// that `go run ./cmd/devenv test-integration` provides to native-server tests.
func nativeServer(t *testing.T) (binary, repository string) {
	t.Helper()
	binary, repository = os.Getenv("LINDM_NATIVE_SERVER_BINARY"), os.Getenv("LINDM_NATIVE_REPOSITORY")
	if binary == "" || repository == "" {
		t.Fatal("native-server integration tests require LINDM_NATIVE_SERVER_BINARY and LINDM_NATIVE_REPOSITORY; use go run ./cmd/devenv test-integration")
	}
	return binary, repository
}
