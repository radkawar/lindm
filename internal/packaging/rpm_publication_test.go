//go:build linux

package packaging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRPMPublicationAuthenticatesInputs(t *testing.T) {
	requireNativeTools(t, "createrepo_c", "rpmbuild", "rpmsign", "rpm", "rpmkeys", "rpm2cpio", "cpio", "gpg", "gpgconf", "gpg-connect-agent", "gpgv")
	work, err := os.MkdirTemp("", "rpm-publication-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Error(err)
		}
	})
	if err := os.Mkdir(filepath.Join(work, "tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, guard, err := generateDevelopmentSigner(ctx, work)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := guard.close(ctx, work); err != nil {
			t.Error(err)
		}
	}()
	build := func(p product, dir string) Artifact {
		t.Helper()
		root := filepath.Join(work, dir)
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		payload, staged, digest := stageProductFixture(t, root, p)
		artifact, err := buildRPM(ctx, root, payload, "0.1.0", Architecture{RPM: "x86_64", Debian: "amd64"}, DefaultSourceDateEpoch, *key, digest, staged, p)
		if err != nil {
			t.Fatal(err)
		}
		return artifact
	}
	signed := build(serverProduct(), "signed")
	other := agentProduct()
	other.name = "unrelated"
	unrelated := build(other, "unrelated")
	copyInput := func(source, name string) string {
		t.Helper()
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(work, name)
		if err := os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
		return target
	}
	renamed := copyInput(unrelated.Path, "lindmd-renamed.rpm")
	unsigned := copyInput(signed.Path, "lindmd-unsigned.rpm")
	if _, _, err := runTool(ctx, work, toolCmd{Name: "rpmsign", Args: []string{"--delsign", unsigned}}); err != nil {
		t.Fatal(err)
	}
	spoofed := copyInput(unsigned, "lindmd-signatures OK.rpm")
	if err := guard.close(ctx, work); err != nil {
		t.Fatal(err)
	}
	wrongDir := filepath.Join(work, "wrong")
	if err := os.Mkdir(wrongDir, 0700); err != nil {
		t.Fatal(err)
	}
	wrong, err := GenerateDevelopmentSigner(ctx, wrongDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		signer     SigningKey
		accepted   bool
	}{
		{"signed-supported", signed.Path, *key, true},
		{"unsigned", unsigned, *key, false},
		{"unsigned-filename-signatures OK", spoofed, *key, false},
		{"wrong-key", signed.Path, *wrong, false},
		{"renamed-unrelated", renamed, *key, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(work, "repository-"+tc.name)
			if err := os.Mkdir(out, 0700); err != nil {
				t.Fatal(err)
			}
			result, err := PublishRPM(ctx, RPMRequest{OutputDir: out, RPMs: []string{tc.path}, Signer: tc.signer})
			if tc.accepted {
				if err != nil {
					t.Fatal(err)
				}
				if !result.RepoMetadataSigned {
					t.Fatal("repository metadata was not authenticated")
				}
				return
			}
			if !errors.Is(err, ErrArtifact) {
				t.Fatalf("untrusted RPM publication: %v", err)
			}
			if _, err := os.Stat(filepath.Join(out, "rpm")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("untrusted package became a published repository")
			}
		})
	}
}
