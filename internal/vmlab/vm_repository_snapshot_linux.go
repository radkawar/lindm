//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
	"lindm/internal/vmlab/reposnapshot"
)

// startImageRepositorySnapshot binds cache selection to the image's signed
// repository identity, not to the ephemeral origin port or TLS certificate.
// advertise is the address the client dials: the installer's unrestricted
// user network reaches the host at 10.0.2.2; lane guests use a loopback forward.
func startImageRepositorySnapshot(ctx context.Context, manifest *labv1.ImageManifest, cache, advertise string) (*reposnapshot.Server, error) {
	if manifestRelease(manifest).Lab.Installer != platform.AutoYaST {
		return nil, nil
	}
	if manifest.GetRepositorySnapshotManifestSha256() == "" || manifest.GetRepositorySnapshotRepomdSha256() == "" {
		return nil, errors.New("tumbleweed requires a captured repository closure and repomd digest")
	}
	if cache == "" {
		cache = ".cache/lab/images"
	}
	server, err := reposnapshot.Start(ctx, cache, manifest.GetRepositorySnapshotManifestSha256(), reposnapshot.ServeOptions{ListenAddress: "127.0.0.1:0", AdvertiseHost: advertise})
	if err != nil {
		return nil, err
	}
	captured := server.Manifest
	if captured.GetDistribution() != manifest.GetDistribution() || captured.GetArchitecture() != manifest.GetArchitecture() || captured.GetSnapshotDate() != manifest.GetRepositorySnapshotDate() || captured.GetRepomdSha256() != manifest.GetRepositorySnapshotRepomdSha256() {
		return nil, errors.Join(errors.New("captured repository does not match selected image distribution, architecture, date or repomd digest"), server.Close())
	}
	return server, nil
}

// guestRollingSnapshot serves the retained closure to one lane guest. Lane
// guests run with restricted user networking, which cannot reach host ports
// (curl exit 7 at 10.0.2.2, observed), so the guest dials the same loopback
// port through a pinned SSH reverse forward. A guest reboot ends the forward.
type guestRollingSnapshot struct {
	*reposnapshot.Server
	vm      *guestVM
	address string
	forward *guestForward
}

// reconnect restores the guest's forward after a guest reboot.
func (s *guestRollingSnapshot) reconnect(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.forward != nil {
		if err := s.forward.Close(); err != nil {
			return err
		}
		s.forward = nil
	}
	forward, err := newGuestForward(ctx, s.vm, s.address, s.address)
	if err != nil {
		return fmt.Errorf("forward repository snapshot into guest: %w", err)
	}
	s.forward = forward
	return nil
}

func (s *guestRollingSnapshot) Close() error {
	var err error
	if s.forward != nil {
		err = s.forward.Close()
	}
	return errors.Join(err, s.Server.Close())
}

// prepareGuestRollingSnapshot changes only the disposable VM. The host CA store,
// host package repositories and host firewall are untouched. A fresh authority
// replaces the installer's expired lane authority before native package work.
func prepareGuestRollingSnapshot(ctx context.Context, vm *guestVM, manifest *labv1.ImageManifest, cache string) (_ *guestRollingSnapshot, err error) {
	server, err := startImageRepositorySnapshot(ctx, manifest, cache, "127.0.0.1")
	if err != nil || server == nil {
		return nil, err
	}
	u, err := url.Parse(server.URL)
	if err != nil {
		return nil, errors.Join(err, server.Close())
	}
	snapshot := &guestRollingSnapshot{Server: server, vm: vm, address: u.Host}
	defer func() {
		if err != nil {
			err = errors.Join(err, snapshot.Close())
		}
	}()
	if err := snapshot.reconnect(ctx); err != nil {
		return nil, err
	}
	const ca = "/etc/pki/trust/anchors/lindm-repository-snapshot.pem"
	command := "set -eu; install -d -m 0755 /etc/pki/trust/anchors; cat > " + nativeQuote(ca) + "; chmod 0644 " + nativeQuote(ca) + "; update-ca-certificates"
	if _, err := vm.run(ctx, "sudo -n sh -c "+nativeQuote(command), bytes.NewReader(server.CAPEM), 64<<10, time.Minute); err != nil {
		return nil, err
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
		return nil, err
	}
	return snapshot, nil
}

func rollingSnapshotDesired(manifest *labv1.ImageManifest, snapshot *guestRollingSnapshot) *resourcev1.RollingUpdateSnapshot {
	release := manifestRelease(manifest)
	if snapshot != nil {
		digest, _ := hex.DecodeString(snapshot.Manifest.GetRepomdSha256()) // Load validated the digest.
		return &resourcev1.RollingUpdateSnapshot{Date: snapshot.Manifest.GetSnapshotDate(), RepositoryUrl: snapshot.URL, MetadataSha256: digest}
	}
	if release.Packages.Backend == platform.BackendPacman {
		return &resourcev1.RollingUpdateSnapshot{Date: manifest.GetRepositorySnapshotDate()}
	}
	return nil
}
