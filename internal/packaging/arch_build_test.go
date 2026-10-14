// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Real Go compilation protects the Build/BuildSource format dispatch, version
// validation, manifest and detached-signature publication contracts. It is not
// agent runtime or installation evidence.
func TestArchBuildSourceArchitectures(t *testing.T) {
	requireNativeTools(t, "gpg", "gpgv", "gpgconf", "gpg-connect-agent", "systemd-analyze")
	work, err := os.MkdirTemp("", "pkg-arch-build-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Error(err)
		}
	})
	key, err := GenerateDevelopmentSigner(t.Context(), work)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "source")
	for name, data := range map[string]string{
		"go.mod":                           "module lindm\n\ngo 1.24.0\n",
		"internal/agent/buildinfo/info.go": "package buildinfo\nvar Version = \"development\"\nvar Revision = \"development\"\n",
		"cmd/lindm-agent/main.go":          "package main\nimport (\"fmt\"; \"lindm/internal/agent/buildinfo\")\nfunc main() { fmt.Println(buildinfo.Version) }\n",
	} {
		file := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"amd64", "arm64"} {
		t.Run(target, func(t *testing.T) {
			out := filepath.Join(work, target)
			if err := os.Mkdir(out, 0o700); err != nil {
				t.Fatal(err)
			}
			result, err := BuildSource(t.Context(), SourceRequest{Repository: source, Revision: "arch-test", BuildRequest: BuildRequest{OutputDir: out, Version: "0.1.0", TargetArchitecture: target, Formats: []Format{FormatArch}, Signer: *key}})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Artifacts) != 1 || result.Architecture.GOARCH != target || result.Architecture.Arch == "" {
				t.Fatalf("wrong build result: %+v", result)
			}
			artifact := result.Artifacts[0]
			if filepath.Dir(artifact.Path) != out || artifact.SignaturePath != artifact.Path+".sig" || !artifact.Signed || artifact.PayloadSHA256 != result.BinarySHA256 {
				t.Fatalf("incomplete artifact cutover: %+v", artifact)
			}
			for _, filename := range []string{artifact.Path, artifact.SignaturePath, result.PublicKey, filepath.Join(out, fmt.Sprintf("%s_0.1.0_manifest.json", PackageName))} {
				info, err := os.Lstat(filename)
				if err != nil || !info.Mode().IsRegular() {
					t.Fatalf("missing regular published artifact %s: %v", filename, err)
				}
			}
			info, err := readArchInfo(artifact.Path)
			if err != nil || info["arch"][0] != result.Architecture.Arch {
				t.Fatalf("package architecture mismatch: %v, %v", info, err)
			}
		})
	}
}
