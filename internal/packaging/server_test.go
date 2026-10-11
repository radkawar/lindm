//go:build linux

package packaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// These fixtures exercise actual native archives and signatures, not installation
// or a fake systemctl. Guest lifecycle and service confinement belong to the VM lane.
func stageProductFixture(t *testing.T, work string, p product) (string, []stagedFile, string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(work, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(work, "input")
	if err := os.WriteFile(binaryPath, []byte("native package payload\x00with embedded console bytes\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Open(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := binary.Close(); err != nil {
			t.Error(err)
		}
	}()
	root, staged, digest, err := stagePayload(work, binary, DefaultSourceDateEpoch, p)
	if err != nil {
		t.Fatal(err)
	}
	return root, staged, digest
}

func TestNativeProductLayoutAndPermissions(t *testing.T) {
	requireNativeTools(t, "dpkg-deb")
	ctx := context.Background()
	arch := Architecture{Debian: "amd64"}
	for _, p := range []product{agentProduct(), serverProduct()} {
		t.Run(p.name, func(t *testing.T) {
			work := t.TempDir()
			payload, staged, digest := stageProductFixture(t, work, p)
			artifact, err := buildDEB(ctx, work, payload, "0.1.0", arch, DefaultSourceDateEpoch, staged, digest, p)
			if err != nil {
				t.Fatal(err)
			}
			if artifact.Product != p.name || artifact.PayloadSHA256 != digest {
				t.Fatalf("artifact attributed to wrong product: %+v", artifact)
			}
			other := serverProduct()
			if p.name == ServerPackageName {
				other = agentProduct()
			}
			if err := verifyDEB(ctx, work, artifact.Path, "0.1.0", arch, digest, staged, other); !errors.Is(err, ErrArtifact) {
				t.Fatalf("cross-product archive accepted: %v", err)
			}
			extract := filepath.Join(work, "extracted")
			if _, _, err := runTool(ctx, work, toolCmd{Name: "dpkg-deb", Args: []string{"--raw-extract", artifact.Path, extract}}); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{other.binary, "/usr/lib/systemd/system/" + other.units[0]} {
				if _, err := os.Stat(filepath.Join(extract, path[1:])); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("package includes other product's %s: %v", path, err)
				}
			}
			if p.name == ServerPackageName {
				for _, path := range []string{"DEBIAN/conffiles", ServerConfigPath[1:], ServerMigrationConfigPath[1:], "etc/lindm/agent.json", "etc/lindm/executor.json"} {
					if _, err := os.Stat(filepath.Join(extract, path)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("server package claims operator credential/config %s: %v", path, err)
					}
				}
			}
			// A writable executable is a security failure even if all payload bytes,
			// package identity and checksums still match the selected product.
			if err := os.Chmod(filepath.Join(extract, p.binary[1:]), 0o777); err != nil {
				t.Fatal(err)
			}
			tampered := filepath.Join(work, "writable.deb")
			if _, _, err := runTool(ctx, work, toolCmd{Name: "dpkg-deb", Args: []string{"--root-owner-group", "--build", extract, tampered}}); err != nil {
				t.Fatal(err)
			}
			if err := verifyDEB(ctx, work, tampered, "0.1.0", arch, digest, staged, p); !errors.Is(err, ErrArtifact) {
				t.Fatalf("writable package executable accepted: %v", err)
			}
		})
	}
}

func TestServerSignedNativeReproducibilityAndAPT(t *testing.T) {
	requireNativeTools(t, "dpkg-deb", "rpmbuild", "rpmsign", "rpm", "rpmkeys", "rpm2cpio", "cpio", "gpg", "gpgconf", "gpg-connect-agent", "gpgv", "apt-ftparchive", "gzip", "systemd-analyze")
	// GnuPG agent sockets require a short private parent path.
	work, err := os.MkdirTemp("", "pkg-server-")
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
	defer func() {
		if err := guard.close(ctx, work); err != nil {
			t.Error(err)
		}
	}()
	p := serverProduct()
	arch := Architecture{Debian: "amd64", RPM: "x86_64"}
	var debs, rpms []Artifact
	for i := range 2 {
		buildWork := filepath.Join(work, fmt.Sprint(i))
		if err := os.Mkdir(buildWork, 0o700); err != nil {
			t.Fatal(err)
		}
		if ok, _, err := verifyUnits(ctx, buildWork, p); err != nil || !ok {
			t.Fatalf("invalid server units: %v", err)
		}
		payload, staged, digest := stageProductFixture(t, buildWork, p)
		deb, err := buildDEB(ctx, buildWork, payload, "0.1.0", arch, DefaultSourceDateEpoch, staged, digest, p)
		if err != nil {
			t.Fatal(err)
		}
		rpm, err := buildRPM(ctx, buildWork, payload, "0.1.0", arch, DefaultSourceDateEpoch, *key, digest, staged, p)
		if err != nil {
			t.Fatal(err)
		}
		debs = append(debs, deb)
		rpms = append(rpms, rpm)
	}
	if debs[0].SHA256 != debs[1].SHA256 || rpms[0].SHA256 != rpms[1].SHA256 {
		t.Fatal("two clean package builds with identical inputs differ")
	}
	if !rpms[0].Signed || rpms[0].SignerFingerprint != key.Fingerprint {
		t.Fatal("server RPM signature was not verified")
	}
	if err := guard.close(ctx, work); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(work, "published")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	repo, err := PublishAPT(ctx, APTRequest{OutputDir: out, DEBs: []string{debs[0].Path}, Signer: *key})
	if err != nil {
		t.Fatal(err)
	}
	if !repo.InReleaseVerified || !repo.PackagesHashVerified {
		t.Fatal("server repository was not authenticated")
	}
	published := filepath.Join(repo.Root, "pool/main/l/lindmd", filepath.Base(debs[0].Path))
	digest, _, err := hashFile(published)
	if err != nil || digest != debs[0].SHA256 {
		t.Fatalf("published server package differs: %s, %v", digest, err)
	}
	index, err := os.ReadFile(repo.Packages["amd64"])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(index, []byte("Package: lindmd\n")) || bytes.Contains(index, []byte("Package: lindm-agent\n")) {
		t.Fatal("signed repository identifies the wrong product")
	}
}

func TestAPTPublicationSeparatesNativeArchitectures(t *testing.T) {
	requireNativeTools(t, "dpkg-deb", "gpg", "gpgconf", "gpg-connect-agent", "gpgv", "apt-ftparchive", "gzip")
	work := t.TempDir()
	if err := os.Chmod(work, 0o700); err != nil {
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
	var archives []string
	var artifacts []Artifact
	for _, arch := range []Architecture{{Debian: "amd64", RPM: "x86_64"}, {Debian: "arm64", RPM: "aarch64"}} {
		buildWork := filepath.Join(work, arch.Debian)
		if err := os.Mkdir(buildWork, 0o700); err != nil {
			t.Fatal(err)
		}
		product := agentProduct()
		payload, staged, digest := stageProductFixture(t, buildWork, product)
		artifact, err := buildDEB(ctx, buildWork, payload, "0.1.0", arch, DefaultSourceDateEpoch, staged, digest, product)
		if err != nil {
			t.Fatal(err)
		}
		archives = append(archives, artifact.Path)
		artifacts = append(artifacts, artifact)
	}
	if err := guard.close(ctx, work); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(work, "published")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	repo, err := PublishAPT(ctx, APTRequest{OutputDir: out, DEBs: archives, Signer: *key})
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.Packages) != 2 || !repo.InReleaseVerified || !repo.PackagesHashVerified {
		t.Fatal("multiarchitecture publication omitted authenticated indexes")
	}
	for arch, path := range repo.Packages {
		index, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(index, []byte("Architecture: ")) != 1 || !bytes.Contains(index, []byte("Architecture: "+arch+"\n")) {
			t.Fatalf("%s index contains another architecture: %s", arch, index)
		}
	}
	release, err := os.ReadFile(repo.Release)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(release, []byte("Architectures: amd64 arm64\n")) {
		t.Fatal("signed Release omitted a native architecture")
	}
	snapshot, err := rejectionSnapshotAPT(ctx, work, repo, artifacts[1], repo.PublicKey, repo.PublicKeyArmor)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Packages) != 2 {
		t.Fatal("rejection snapshot omitted another architecture's signed index")
	}
}
