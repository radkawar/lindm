// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTargetArchitecture(t *testing.T) {
	for _, target := range []string{"amd64", "arm64", ""} {
		got, err := targetArchitecture(target)
		if err != nil || (target != "" && got != target) || (target == "" && got != runtime.GOARCH) {
			t.Fatalf("target %q: %q, %v", target, got, err)
		}
	}
	if _, err := targetArchitecture("aarch64"); !errors.Is(err, ErrArchitecture) {
		t.Fatalf("unsupported target accepted: %v", err)
	}
}

// The fixture is a real Go module with the production command/module/stamp
// identities. These tests prove compiler/ELF/archive/signature boundaries, not
// that a fixture command implements the agent or server protocol.
func TestCrossArchitectureSourcePackages(t *testing.T) {
	requireNativeTools(t, "dpkg-deb", "rpmbuild", "rpmsign", "rpm", "rpmkeys", "rpm2cpio", "cpio", "gpg", "gpgconf", "gpg-connect-agent", "systemd-analyze")
	work, err := os.MkdirTemp("", "pkg-cross-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	key, guard, err := generateDevelopmentSigner(ctx, work)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.close(ctx, work); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "source")
	files := map[string]string{
		"go.mod":                           "module lindm\n\ngo 1.24.0\n",
		"internal/agent/buildinfo/info.go": "package buildinfo\nvar Version = \"development\"\nvar Revision = \"development\"\n",
	}
	for _, p := range []product{agentProduct(), serverProduct(), cliProduct()} {
		files["cmd/"+p.name+"/main.go"] = "package main\nimport (\"fmt\"; \"lindm/internal/agent/buildinfo\")\nfunc main() { fmt.Println(buildinfo.Version) }\n"
	}
	for name, contents := range files {
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []product{agentProduct(), serverProduct(), cliProduct()} {
		for _, target := range []string{"amd64", "arm64"} {
			t.Run(p.name+"/"+target, func(t *testing.T) {
				var first *BuildResult
				for iteration := range 2 {
					out := filepath.Join(work, fmt.Sprintf("%s-%s-%d", p.name, target, iteration))
					if err := os.Mkdir(out, 0o700); err != nil {
						t.Fatal(err)
					}
					request := SourceRequest{Repository: source, Revision: "test-revision", BuildRequest: BuildRequest{Version: "0.1.0", TargetArchitecture: target, OutputDir: out, Signer: *key}}
					result, err := buildSource(ctx, request, p)
					if err != nil {
						t.Fatal(err)
					}
					wantValidation := "embedded-build-metadata"
					if target == runtime.GOARCH {
						wantValidation = "native-execution"
					}
					if result.Architecture.GOARCH != target || result.VersionValidation != wantValidation || len(result.Artifacts) != 2 {
						t.Fatalf("incorrect architecture/validation evidence: %+v", result)
					}
					for _, artifact := range result.Artifacts {
						if artifact.PayloadSHA256 != result.BinarySHA256 || (artifact.Format == FormatRPM && !artifact.Signed) {
							t.Fatalf("unverified payload/signature: %+v", artifact)
						}
					}
					if first != nil {
						if first.BinarySHA256 != result.BinarySHA256 {
							t.Fatal("two clean compiler outputs differ")
						}
						for i, artifact := range result.Artifacts {
							if artifact.SHA256 != first.Artifacts[i].SHA256 || artifact.PayloadSHA256 != first.Artifacts[i].PayloadSHA256 || artifact.UnsignedSHA256 == "" || artifact.UnsignedSHA256 != first.Artifacts[i].UnsignedSHA256 {
								t.Fatalf("two clean %s archives differ", artifact.Format)
							}
						}
					}
					first = result
					t.Logf("build=%d target=%s product=%s binary=%s deb=%s rpm=%s validation=%s", iteration, target, p.name, result.BinarySHA256, result.Artifacts[0].SHA256, result.Artifacts[1].SHA256, result.VersionValidation)
					if iteration == 0 && target != runtime.GOARCH {
						assertForeignMetadataBoundaries(t, ctx, out, p, result)
					}
				}
			})
		}
	}
}

func assertForeignMetadataBoundaries(t *testing.T, ctx context.Context, work string, p product, result *BuildResult) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(work, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	extracted := filepath.Join(work, "extracted")
	if _, _, err := runTool(ctx, work, toolCmd{Name: "dpkg-deb", Args: []string{"--extract", result.Artifacts[0].Path, extracted}}); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(extracted, p.binary[1:])
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := confirmModule(bytes.NewReader(data), p, result.Architecture, "0.2.0"); !errors.Is(err, ErrVersion) {
		t.Fatalf("accepted wrong embedded version: %v", err)
	}
	for _, change := range []struct{ old, replacement string }{
		{"GOOS=linux", "GOOS=other"},
		{"GOARCH=" + result.Architecture.GOARCH, "GOARCH=wrong"},
		{"CGO_ENABLED=0", "CGO_ENABLED=1"},
		{"lindm/internal/agent/buildinfo.Version", "lindm/internal/agent/buildinfo.Missing"},
		{"lindm/cmd/" + p.name, "other/cmd/" + p.name},
	} {
		if !bytes.Contains(data, []byte(change.old)) {
			t.Fatalf("real Go metadata omitted expected %s", change.old)
		}
		corrupt := bytes.ReplaceAll(data, []byte(change.old), []byte(change.replacement))
		if _, err := confirmModule(bytes.NewReader(corrupt), p, result.Architecture, "0.1.0"); err == nil {
			t.Fatalf("accepted inconsistent %s metadata", change.old)
		}
	}
	if _, err := build(ctx, BuildRequest{AgentBinary: binaryPath, Version: "0.1.0", TargetArchitecture: runtime.GOARCH, OutputDir: work, Formats: []Format{FormatDEB}}, p); !errors.Is(err, ErrArchitecture) {
		t.Fatalf("accepted wrong requested architecture: %v", err)
	}
	other := agentProduct()
	if p.name == PackageName {
		other = serverProduct()
	}
	if _, err := confirmModule(bytes.NewReader(data), other, result.Architecture, "0.1.0"); !errors.Is(err, ErrArchitecture) {
		t.Fatalf("accepted wrong product metadata: %v", err)
	}
	header := bytes.Clone(data)
	// Swap the machine independently of the Go build metadata.
	header[18], header[19] = 62, 0
	if result.Architecture.GOARCH == "amd64" {
		header[18] = 183
	}
	arch, err := inspectELF(bytes.NewReader(header))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := confirmModule(bytes.NewReader(header), p, arch, "0.1.0"); !errors.Is(err, ErrArchitecture) {
		t.Fatalf("accepted ELF/build-setting disagreement: %v", err)
	}
}
