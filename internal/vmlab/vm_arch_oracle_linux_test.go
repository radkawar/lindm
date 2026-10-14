// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/packaging"
)

func TestPacmanOraclePreservesEpochAndArchitecture(t *testing.T) {
	input := "foo 2:1.0-3\nbar 1.2-1\n\n--LINDM-ARCH-DETAILS--\nName            : foo\nVersion         : 2:1.0-3\nArchitecture    : x86_64\nDescription     : example\n\nName            : bar\nVersion         : 1.2-1\nArchitecture    : any\n\n"
	pkgs, err := parsePacmanTruth([]byte(input))
	if err != nil || len(pkgs) != 2 {
		t.Fatalf("native oracle: %v %v", pkgs, err)
	}
	if pkgs[nativePackage{name: "foo", version: "2:1.0-3", architecture: "x86_64", manager: "pacman", module: nativeModule{status: truthUnavailable}}] != 1 {
		t.Fatal("lost native identity")
	}
	for _, bad := range []string{strings.Replace(input, "Version         : 2:1.0-3", "Version         : 1.0-3", 1), strings.Replace(input, "Architecture    : any", "Architecture    :", 1), strings.Replace(input, "bar 1.2-1\n", "", 1), strings.TrimSuffix(input, "\n")} {
		if _, err := parsePacmanTruth([]byte(bad)); err == nil {
			t.Fatal("accepted inconsistent or truncated oracle")
		}
	}
}

func TestArchOracleAllowsOnlyNativeAbsentRelease(t *testing.T) {
	truth, actual := vmTestObservation()
	truth.host[0], truth.host[1] = "arch", ""
	actual.Host.OsId.Value = "arch"
	actual.Host.OsVersion.Value = ""
	actual.Host.OsVersion.Status = truthUnavailable
	if err := compareVMObservation(truth, actual); err != nil {
		t.Fatal(err)
	}
	actual.Host.OsVersion.Status = truthSuccess
	if err := compareVMObservation(truth, actual); err == nil {
		t.Fatal("empty successful version accepted")
	}
	actual.Host.OsVersion.Status = truthUnavailable
	truth.host[0], actual.Host.OsId.Value = "ubuntu", "ubuntu"
	if err := compareVMObservation(truth, actual); err == nil {
		t.Fatal("mutable release absence accepted")
	}
}

func TestArchArtifactAcceptedByNativeLifecycle(t *testing.T) {
	data := []byte("native artifact digest fixture")
	path := filepath.Join(t.TempDir(), "lindm-agent-0.1.0-1-x86_64.pkg.tar.zst")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	artifact := packaging.Artifact{
		Format: packaging.FormatArch, Version: "0.1.0", Path: path,
		Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data)),
	}
	file, err := nativeArtifactFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	artifact.Format = "unsupported"
	if file, err := nativeArtifactFile(artifact); err == nil {
		_ = file.Close()
		t.Fatal("accepted unsupported native package format")
	}
}
