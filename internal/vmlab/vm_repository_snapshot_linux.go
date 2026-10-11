//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
	"lindm/internal/vmlab/reposnapshot"
)

// startImageRepositorySnapshot binds cache selection to the image's signed
// repository identity, not to the ephemeral origin port or TLS certificate.
func startImageRepositorySnapshot(ctx context.Context, manifest *labv1.ImageManifest, cache string) (*reposnapshot.Server, error) {
	if manifestRelease(manifest).Lab.Installer != platform.AutoYaST {
		return nil, nil
	}
	if manifest.GetRepositorySnapshotManifestSha256() == "" || manifest.GetRepositorySnapshotRepomdSha256() == "" {
		return nil, errors.New("tumbleweed requires a captured repository closure and repomd digest")
	}
	if cache == "" {
		cache = ".cache/lab/images"
	}
	server, err := reposnapshot.Start(ctx, cache, manifest.GetRepositorySnapshotManifestSha256(), reposnapshot.ServeOptions{ListenAddress: "127.0.0.1:0", AdvertiseHost: "10.0.2.2"})
	if err != nil {
		return nil, err
	}
	captured := server.Manifest
	if captured.GetDistribution() != manifest.GetDistribution() || captured.GetArchitecture() != manifest.GetArchitecture() || captured.GetSnapshotDate() != manifest.GetRepositorySnapshotDate() || captured.GetRepomdSha256() != manifest.GetRepositorySnapshotRepomdSha256() {
		return nil, errors.Join(errors.New("captured repository does not match selected image distribution, architecture, date or repomd digest"), server.Close())
	}
	return server, nil
}

// prepareGuestRollingSnapshot changes only the disposable VM. The host CA store,
// host package repositories and host firewall are untouched. A fresh authority
// replaces the installer's expired lane authority before native package work.
func prepareGuestRollingSnapshot(ctx context.Context, vm *guestVM, manifest *labv1.ImageManifest, cache string) (*reposnapshot.Server, error) {
	server, err := startImageRepositorySnapshot(ctx, manifest, cache)
	if err != nil || server == nil {
		return server, err
	}
	const ca = "/etc/pki/trust/anchors/lindm-repository-snapshot.pem"
	command := "set -eu; install -d -m 0755 /etc/pki/trust/anchors; cat > " + nativeQuote(ca) + "; chmod 0644 " + nativeQuote(ca) + "; update-ca-certificates"
	if _, err := vm.run(ctx, "sudo -n sh -c "+nativeQuote(command), bytes.NewReader(server.CAPEM), 64<<10, time.Minute); err != nil {
		return nil, errors.Join(err, server.Close())
	}
	// Load verified the registry-pinned metadata key and each RPM key delegated
	// by signed repomd. Import exactly those files, never arbitrary keys via
	// zypper's auto-import mode; all signature checks remain mandatory.
	var setup strings.Builder
	setup.WriteString("set -eu; install -d -m 0700 /run/lindm-repository-snapshot; ")
	for _, key := range server.KeyPaths {
		fmt.Fprintf(&setup, "curl --fail --silent --show-error --proto '=https' --cacert %s %s -o /run/lindm-repository-snapshot/vendor.key; rpm --import /run/lindm-repository-snapshot/vendor.key; ", nativeQuote(ca), nativeQuote(server.URL+key))
	}
	setup.WriteString("zypper --non-interactive modifyrepo --all --disable; cat > /etc/zypp/repos.d/lindm-repository-snapshot.repo")
	command = setup.String()
	repo := fmt.Sprintf("[lindm-repository-snapshot]\nname=Verified disposable lane snapshot\nbaseurl=%s\nenabled=1\nautorefresh=0\ngpgcheck=1\nrepo_gpgcheck=1\npkg_gpgcheck=1\n", server.URL)
	if _, err := vm.run(ctx, "sudo -n sh -c "+nativeQuote(command), bytes.NewBufferString(repo), 64<<10, 2*time.Minute); err != nil {
		return nil, errors.Join(err, server.Close())
	}
	return server, nil
}

func rollingSnapshotDesired(manifest *labv1.ImageManifest, server *reposnapshot.Server) *resourcev1.RollingUpdateSnapshot {
	release := manifestRelease(manifest)
	if server != nil {
		digest, _ := hex.DecodeString(server.Manifest.GetRepomdSha256()) // Load validated the digest.
		return &resourcev1.RollingUpdateSnapshot{Date: server.Manifest.GetSnapshotDate(), RepositoryUrl: server.URL, MetadataSha256: digest}
	}
	if release.Packages.Backend == platform.BackendPacman {
		return &resourcev1.RollingUpdateSnapshot{Date: manifest.GetRepositorySnapshotDate()}
	}
	return nil
}
