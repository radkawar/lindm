//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/platform"
	"lindm/internal/resource"
)

func nativeProvider(ctx context.Context, c nativeConfig) (*Provider, error) {
	if err := checkNative(ctx, c); err != nil {
		return nil, err
	}
	if c.NativeDigest == nil {
		return nil, ErrUnsupported
	}
	p := &Provider{config: Config{Native: c.Native, Platform: c.Platform, ExecutorIncarnation: c.ExecutorIncarnation, NativeDigest: c.NativeDigest}, run: runNative, readDB: func() (*localDB, error) { return readDatabase(c.NativeDigest) }}
	var version []byte
	var err error
	release := platform.Of(c.Platform)
	if err = release.Gate(platform.Accounts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	switch release.Native().Packages.Backend.PackageDB() {
	case platform.PackageDBDpkg:
		version, err = p.run(ctx, nil, "/usr/bin/dpkg-query", "-W", "-f=${Version}", "passwd")
	case platform.PackageDBRPM:
		version, err = p.run(ctx, nil, "/usr/bin/rpm", "-qf", "--qf", "%{VERSION}-%{RELEASE}", "/usr/sbin/useradd")
	case platform.PackageDBPacman:
		version, err = p.run(ctx, nil, "/usr/bin/pacman", "-Qo", "--", "/usr/bin/useradd")
		if err == nil {
			fields := strings.Fields(string(version))
			if len(fields) == 0 {
				return nil, ErrUnsupported
			}
			version = []byte(fields[len(fields)-1])
		}
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	if len(version) == 0 || len(version) > 128 {
		return nil, ErrUnsupported
	}
	p.backend = &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SHADOW, NativeVersion: string(version), ProviderVersion: "1", Product: proto.CloneOf(c.Platform)}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	p.boot = strings.TrimSpace(string(boot))
	return p, nil
}

// ObserveNative runs only in the fixed read-only helper. Homes are read-only,
// not hidden; the executor's own ProtectHome policy is never relaxed. It opens
// no ownership journal and grants no authority to modify an account.
func ObserveNative(ctx context.Context, env resourceprovider.NativeEnv, d *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
	return observeNative(ctx, configFromEnv(env), d)
}

func observeNative(ctx context.Context, c nativeConfig, d *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := resource.ValidateDesired(d); err != nil {
		return nil, err
	}
	if d.GetLocalUser() == nil && d.GetLocalGroup() == nil {
		return nil, ErrUnsupported
	}
	p, err := nativeProvider(ctx, c)
	if err != nil {
		return nil, err
	}
	if p.protected(d.GetRef().GetCanonicalKey()) {
		return nil, ErrUnsafe
	}
	if u := d.GetLocalUser(); u != nil && u.HomeDirectory != nil {
		if err := p.approvedHome(u); err != nil {
			return nil, err
		}
	}
	snapshot, receipt, db, err := p.observeLocal(ctx, d)
	if err != nil {
		return nil, err
	}
	if u := d.GetLocalUser(); u != nil && u.HomeDirectory != nil {
		home, err := homeMetadata(u.GetHomeDirectory())
		if err != nil {
			return nil, err
		}
		snapshot.AccountPrivate.DesiredHome = home
	}
	fresh, err := p.readDB()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(db.revision, fresh.revision) {
		return nil, ErrConflict
	}
	snapshot.AccountNssReceipt = receipt
	if err := validateMessage(snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}
func (p *Provider) approvedHome(u *resourcev1.LocalUserDesired) error {
	root := ""
	for _, approved := range p.config.Native.GetApprovedHomeRoots() {
		if approved.GetRootId() == u.GetHome().GetApprovedRootId() {
			root = approved.GetPath()
		}
	}
	path := u.GetHomeDirectory()
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(path, root+"/") || filepath.Clean(path) != path {
		return ErrUnsafe
	}
	return rootDirectory(filepath.Dir(path))
}
func (p *Provider) observe(ctx context.Context, d *resourcev1.ResourceDesiredState, l *agentv1.ResourceOwnershipLedger) (*agentv1.ResourceOwnershipSnapshot, *resourcev1.ProbeReceipt, *localDB, error) {
	if p.config.NativeObserve == nil {
		return nil, nil, nil, ErrUnsupported
	}
	started := time.Now()
	snapshot, err := p.config.NativeObserve(ctx, proto.CloneOf(d))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validateMessage(snapshot); err != nil {
		return nil, nil, nil, err
	}
	o := snapshot.GetObservation()
	if !proto.Equal(o.GetRef(), d.GetRef()) || !proto.Equal(o.GetMetadata().GetBackend(), p.backend) || o.GetMetadata().GetBootId() != p.boot || o.GetMetadata().GetExecutorIncarnation() != p.config.ExecutorIncarnation || o.GetMetadata().GetObservationStatus() != resourcev1.ObservationStatus_OBSERVATION_STATUS_OK || !snapshot.GetAccountNssReceipt().GetPassed() {
		return nil, nil, nil, ErrConflict
	}
	db, err := p.readDB()
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(db.revision, o.GetMetadata().GetNativeRevision()) {
		return nil, nil, nil, ErrConflict
	}
	if snapshot.AccountPrivate == nil || o.GetMetadata().GetObservedAt().AsTime().Before(started.Add(-time.Second)) || snapshot.GetAccountNssReceipt().GetObservedAt().AsTime().Before(started.Add(-time.Second)) {
		return nil, nil, nil, ErrConflict
	}
	prior := l.GetLastApplied()
	if prior == nil {
		prior = l.GetBaseline()
	}
	if l.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED && (exists(prior.GetObservation()) != exists(o) || exists(o) && !sameNumericIdentity(prior.GetObservation(), o)) {
		prior = nil
	}
	if prior != nil {
		if exists(o) && exists(prior.GetObservation()) && !sameNumericIdentity(prior.GetObservation(), o) {
			return nil, nil, nil, fmt.Errorf("%w: native identity reused", ErrConflict)
		}
		snapshot.AccountPrivate.NativeGeneration = prior.GetAccountPrivate().GetNativeGeneration()
		snapshot.AccountPrivate.IdentityAnchorSha256 = bytes.Clone(prior.GetAccountPrivate().GetIdentityAnchorSha256())
		if u := o.GetLocalUser(); u != nil && u.GetExists() {
			u.UidGeneration = proto.String(snapshot.AccountPrivate.GetNativeGeneration())
		}
	}
	return snapshot, snapshot.GetAccountNssReceipt(), db, nil
}
