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
	return startRepositorySnapshot(ctx, manifest, platform.RollingTarget{Date: manifest.GetRepositorySnapshotDate(), ClosureSHA256: manifest.GetRepositorySnapshotManifestSha256(), RepomdSHA256: manifest.GetRepositorySnapshotRepomdSha256()}, cache, advertise)
}

func startRepositorySnapshot(ctx context.Context, manifest *labv1.ImageManifest, pin platform.RollingTarget, cache, advertise string) (*reposnapshot.Server, error) {
	if cache == "" {
		cache = ".cache/lab/images"
	}
	server, err := reposnapshot.Start(ctx, cache, pin.ClosureSHA256, reposnapshot.ServeOptions{ListenAddress: "127.0.0.1:0", AdvertiseHost: advertise})
	if err != nil {
		return nil, err
	}
	captured := server.Manifest
	if captured.GetDistribution() != manifest.GetDistribution() || captured.GetArchitecture() != manifest.GetArchitecture() || captured.GetSnapshotDate() != pin.Date || captured.GetRepomdSha256() != pin.RepomdSHA256 {
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
	return trustGuestRollingSnapshot(ctx, vm, server, "lindm-repository-snapshot", true)
}

// prepareGuestOSUpdateTarget resolves the registry's later os-update target for
// the guest architecture. Arch needs only the Archive date; a Tumbleweed target
// closure is served and trusted like the image's own, but only the agent's
// policy-owned repository uses it. Without a registry pin it returns nils.
func prepareGuestOSUpdateTarget(ctx context.Context, vm *guestVM, manifest *labv1.ImageManifest, cache string) (*guestRollingSnapshot, *resourcev1.RollingUpdateSnapshot, error) {
	release := manifestRelease(manifest)
	pin, ok := release.Lab.OSUpdateTargets[manifest.GetArchitecture()]
	if !ok {
		return nil, nil, nil
	}
	if pin.Date <= manifest.GetRepositorySnapshotDate() {
		return nil, nil, fmt.Errorf("os-update target %s is not later than the image snapshot %s", pin.Date, manifest.GetRepositorySnapshotDate())
	}
	if release.Packages.Backend == platform.BackendPacman {
		return nil, &resourcev1.RollingUpdateSnapshot{Date: pin.Date}, nil
	}
	server, err := startRepositorySnapshot(ctx, manifest, pin, cache, "127.0.0.1")
	if err != nil {
		return nil, nil, err
	}
	snapshot, err := trustGuestRollingSnapshot(ctx, vm, server, "lindm-os-update-target", false)
	if err != nil {
		return nil, nil, err
	}
	digest, _ := hex.DecodeString(server.Manifest.GetRepomdSha256()) // Load validated the digest.
	return snapshot, &resourcev1.RollingUpdateSnapshot{Date: server.Manifest.GetSnapshotDate(), RepositoryUrl: server.URL, MetadataSha256: digest}, nil
}

// trustGuestRollingSnapshot forwards server into the guest, trusts its lane CA
// as name.pem and imports its verified keys. configure replaces the guest's
// zypper repositories with it; an os-update target leaves them untouched.
func trustGuestRollingSnapshot(ctx context.Context, vm *guestVM, server *reposnapshot.Server, name string, configure bool) (_ *guestRollingSnapshot, err error) {
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
	ca := "/etc/pki/trust/anchors/" + name + ".pem"
	command := "set -eu; install -d -m 0755 /etc/pki/trust/anchors; cat > " + nativeQuote(ca) + "; chmod 0644 " + nativeQuote(ca) + "; update-ca-certificates"
	if _, err := vm.run(ctx, "sudo -n sh -c "+nativeQuote(command), bytes.NewReader(server.CAPEM), 64<<10, time.Minute); err != nil {
		return nil, err
	}
	// Load verified the registry-pinned metadata key and each RPM key delegated
	// by signed repomd. Import exactly those files, never arbitrary keys via
	// zypper's auto-import mode; all signature checks remain mandatory.
	var setup strings.Builder
	setup.WriteString("set -eu; install -d -m 0700 /run/" + name + "; ")
	for _, key := range server.KeyPaths {
		fmt.Fprintf(&setup, "curl --fail --silent --show-error --proto '=https' --cacert %s %s -o /run/%s/vendor.key; rpm --import /run/%s/vendor.key; ", nativeQuote(ca), nativeQuote(server.URL+key), name, name)
	}
	if !configure {
		if _, err := vm.run(ctx, "sudo -n sh -c "+nativeQuote(setup.String()+"true"), nil, 64<<10, 2*time.Minute); err != nil {
			return nil, err
		}
		return snapshot, nil
	}
	setup.WriteString("zypper --non-interactive modifyrepo --all --disable; cat > /etc/zypp/repos.d/lindm-repository-snapshot.repo")
	repo := fmt.Sprintf("[lindm-repository-snapshot]\nname=Verified disposable lane snapshot\nbaseurl=%s\nenabled=1\nautorefresh=0\ngpgcheck=1\nrepo_gpgcheck=1\npkg_gpgcheck=1\n", server.URL)
	if _, err := vm.run(ctx, "sudo -n sh -c "+nativeQuote(setup.String()), bytes.NewBufferString(repo), 64<<10, 2*time.Minute); err != nil {
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
