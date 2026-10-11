//go:build linux

// Package accountprovider manages only protected local shadow-utils accounts.
// NSS is independently queried; directory objects and protected administrators
// are never changed. Native effects require a fixed isolated helper and final
// signed authority callback. Homes and other user data are never removed,
// recursively copied or chowned. Unknown effects are not replayed.
package accountprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/resource"
)

var (
	ErrUnsupported    = errors.New("accountprovider: unsupported")
	ErrUnsafe         = errors.New("accountprovider: unsafe local account state")
	ErrConflict       = errors.New("accountprovider: precondition conflict")
	ErrOutcomeUnknown = errors.New("accountprovider: outcome unknown")
	ErrNotConverged   = errors.Join(resource.ErrNotConverged, errors.New("accountprovider: not converged"))
)

// Config is trusted constructor context supplied by the root executor, not policy.
// Native contains root-approved home identities, account ranges and protected names.
// NativeTransaction must launch the fixed account helper, never run in executor.
type Config struct {
	Journal                                                                     *journal.Store
	ExecutorIncarnation, ActionID, DeploymentID, DeviceID, EnrollmentGeneration string
	Ownership                                                                   *agentv1.ResourceOwnershipBinding
	Platform                                                                    *resourcev1.PlatformProduct
	Native                                                                      *agentv1.NativeAccountProviderConfig
	NativeTransaction                                                           func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) error
	NativeObserve                                                               func(context.Context, *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error)
	NativeDigest                                                                func(string, []byte) ([]byte, error)
	// Secrets opens one delivered SecretRef for a single use; the provider
	// clears the returned material. Plaintext never enters plans, errors or logs.
	Secrets func(context.Context, *resourcev1.SecretRef) (*agentv1.SecretMaterial, error)
}
type Provider struct {
	config  Config
	boot    string
	backend *resourcev1.BackendSelection
	run     nativeRun
	readDB  func() (*localDB, error)
	mu      sync.Mutex
	closed  bool
}

func Open(ctx context.Context, c Config) (*Provider, error) {
	if ctx == nil || c.Journal == nil || c.Ownership == nil || c.Platform == nil || c.Native == nil || c.NativeTransaction == nil || c.NativeObserve == nil || c.NativeDigest == nil || c.Secrets == nil || os.Geteuid() != 0 {
		return nil, ErrUnsupported
	}
	for _, id := range []string{c.ExecutorIncarnation, c.ActionID, c.DeploymentID, c.DeviceID, c.EnrollmentGeneration} {
		if parsed, e := uuid.Parse(id); e != nil || parsed.String() != id {
			return nil, ErrUnsafe
		}
	}
	p, err := nativeProvider(ctx, NativeConfig{Native: c.Native, Platform: c.Platform, ExecutorIncarnation: c.ExecutorIncarnation, NativeDigest: c.NativeDigest})
	if err != nil {
		return nil, err
	}
	p.config = c
	if _, err = p.readDB(); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *Provider) Close() error { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true; return nil }
func (p *Provider) ledger(ctx context.Context, ref *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	l, e := p.config.Journal.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, ref)
	if errors.Is(e, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return l, e
}
func (p *Provider) protected(name string) bool {
	switch name {
	case "root", "admin", "administrator", "sudo", "wheel", "adm", "docker", "lxd", "disk", "lindm", "lindm-agent", "lindm-executor":
		return true
	}
	return strings.HasPrefix(name, "lindm-") || slices.Contains(p.config.Native.GetProtectedNames(), name)
}
func (p *Provider) validateDesired(d *resourcev1.ResourceDesiredState) error {
	if err := resource.ValidateDesired(d); err != nil {
		return err
	}
	if d.GetLocalGroup() == nil && d.GetLocalUser() == nil {
		return ErrUnsupported
	}
	if p.protected(d.GetRef().GetCanonicalKey()) {
		return ErrUnsafe
	}
	if g := d.GetLocalGroup(); g != nil {
		if g.Gid != nil && (g.GetGid() < p.config.Native.GetMinGid() || g.GetGid() > p.config.Native.GetMaxGid()) {
			return ErrUnsafe
		}
		if g.GetMembers().GetMode() == resourcev1.SetMode_SET_MODE_EXACT && !p.config.Ownership.GetPolicy().GetCompleteMembershipDimension() {
			return ErrUnsafe
		}
		return nil
	}
	u := d.GetLocalUser()
	if u.Uid != nil && (u.GetUid() < p.config.Native.GetMinUid() || u.GetUid() > p.config.Native.GetMaxUid()) {
		return ErrUnsafe
	}
	if u.GetSupplementaryGroups().GetMode() == resourcev1.SetMode_SET_MODE_EXACT && !p.config.Ownership.GetPolicy().GetCompleteMembershipDimension() {
		return ErrUnsafe
	}
	if aging := u.GetAging(); aging != nil {
		if aging.AccountLocked != nil && (aging.AccountExpiresAt != nil || aging.AccountNeverExpires != nil) {
			return ErrUnsafe
		}
		if aging.AccountNeverExpires != nil && !aging.GetAccountNeverExpires() {
			return ErrUnsafe
		}
		if aging.AccountExpiresAt != nil && (aging.GetAccountExpiresAt().GetNanos() != 0 || aging.GetAccountExpiresAt().GetSeconds()%86400 != 0) {
			return fmt.Errorf("%w: shadow expiry has whole-day precision", ErrUnsupported)
		}
	}
	if u.HomeDirectory != nil {
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
	}
	if u.GetHome() != nil && u.HomeDirectory == nil {
		return ErrUnsafe
	}
	if u.GetShell() != nil {
		shells, e := protectedRead("/etc/shells")
		if e != nil {
			return e
		}
		found := false
		for line := range strings.SplitSeq(string(shells), "\n") {
			if strings.TrimSpace(line) == u.GetShell().GetInstalledShell() {
				found = true
			}
		}
		if !found {
			return ErrUnsafe
		}
		resolved, e := filepath.EvalSymlinks(u.GetShell().GetInstalledShell())
		if e != nil {
			return e
		}
		if e = protectedAncestry(filepath.Dir(resolved)); e != nil {
			return e
		}
		info, e := os.Stat(resolved)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
			return ErrUnsafe
		}
		if e = rootOwned(info); e != nil {
			return e
		}
	}
	return nil
}
func (p *Provider) Plan(ctx context.Context, d *resourcev1.ResourceDesiredState, op resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrUnsupported
	}
	if err := p.validateDesired(d); err != nil {
		return nil, err
	}
	l, err := p.ledger(ctx, d.GetRef())
	if err != nil {
		return nil, err
	}
	if l.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	before, _, db, err := p.observe(ctx, d, l)
	if err != nil {
		return nil, err
	}
	return p.plan(ctx, d, op, before, db, l)
}
func (p *Provider) plan(ctx context.Context, d *resourcev1.ResourceDesiredState, op resourcev1.ResourceOperation, before *agentv1.ResourceOwnershipSnapshot, db *localDB, l *agentv1.ResourceOwnershipLedger) (*resourcev1.ResourcePlan, error) {
	if op != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && op != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return nil, ErrUnsupported
	}
	if l == nil || l.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		if op == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
			return nil, ErrConflict
		}
		if exists(before.GetObservation()) && p.config.Ownership.GetPolicy().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
			return nil, ErrConflict
		}
	}
	if p.isAdministrator(db, d.GetRef().GetCanonicalKey()) {
		return nil, ErrUnsafe
	}
	target, edges, err := p.target(ctx, d, op, before, db, l)
	if err != nil {
		return nil, err
	}
	change := resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_UPDATE
	if !exists(before.GetObservation()) && exists(target.GetObservation()) {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE
	} else if exists(before.GetObservation()) && !exists(target.GetObservation()) {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_REMOVE_OWNED
	} else if sameState(before, target) {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	} else if op == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_RESTORE_OWNED
	}
	dd, err := resource.DesiredDigest(d)
	if err != nil {
		return nil, err
	}
	od, err := resource.ObservationDigest(before.GetObservation())
	if err != nil {
		return nil, err
	}
	ld, err := journal.ResourceOwnershipDigest(l)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(d)
	if err != nil {
		return nil, err
	}
	plan := &resourcev1.ResourcePlan{Ref: proto.CloneOf(d.GetRef()), Operation: op, DesiredSha256: dd[:], ObservationSha256: od[:], OwnershipRevisionSha256: ld[:], Before: proto.CloneOf(before.GetObservation()), Backend: proto.CloneOf(p.backend), Claims: claims, Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT, resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED}}
	var inverse *resourcev1.OwnershipInverseBinding
	if op == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		last, err := resource.ObservationDigest(l.GetLastApplied().GetObservation())
		if err != nil {
			return nil, err
		}
		digest, err := inverseDigest(target, l.GetBaseline(), p.config.NativeDigest)
		if err != nil {
			return nil, err
		}
		inverse = &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ld[:], LastAppliedSha256: last[:], NativeIdentitySha256: identity(before.GetObservation()), InverseSha256: digest}
	}
	if g := d.GetLocalGroup(); g != nil {
		plan.Plan = &resourcev1.ResourcePlan_LocalGroup{LocalGroup: &resourcev1.LocalGroupPlan{Desired: proto.CloneOf(g), Change: change, MemberEdges: edges, ExpectedLocalRevision: bytes.Clone(db.revision), ExpectedIdentitySha256: identity(before.GetObservation()), Inverse: inverse}}
	} else {
		plan.Plan = &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: proto.CloneOf(d.GetLocalUser()), Change: change, Fields: changedFields(before, target), MemberEdges: edges, ExpectedLocalRevision: bytes.Clone(db.revision), ExpectedIdentitySha256: identity(before.GetObservation()), ExpectedUid: before.GetObservation().GetLocalUser().Uid, ExpectedUidGeneration: before.GetObservation().GetLocalUser().UidGeneration, CreateHome: needsHome(target), Inverse: inverse}}
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	commands, err := nativeCommands(&agentv1.NativeResourceTransactionRequest{Plan: plan, Before: before, Target: target}, db)
	if err != nil {
		return nil, err
	}
	if _, err = nativeToolOptions(ctx, p.run, commands, ChrootAccountRoot(p.config.Platform)); err != nil {
		return nil, err
	}
	return plan, nil
}
func (p *Provider) isAdministrator(db *localDB, name string) bool {
	row := db.users[name]
	if row != nil {
		uid, e := number(row[2])
		if e != nil || uid < p.config.Native.GetMinUid() || uid > p.config.Native.GetMaxUid() {
			return true
		}
		for group, g := range db.groups {
			if p.protected(group) && (g[2] == row[3] || slices.Contains(members(g[3]), name)) {
				return true
			}
		}
	}
	if g := db.groups[name]; g != nil {
		gid, e := number(g[2])
		return e != nil || gid < p.config.Native.GetMinGid() || gid > p.config.Native.GetMaxGid()
	}
	return false
}
func identity(o *resourcev1.ResourceObservation) []byte {
	if g := o.GetLocalGroup(); g != nil {
		return bytes.Clone(g.GetIdentitySha256())
	}
	return bytes.Clone(o.GetLocalUser().GetIdentitySha256())
}
func sameState(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	if a.GetObservation().GetLocalGroup() != nil {
		return proto.Equal(a.GetObservation().GetLocalGroup(), b.GetObservation().GetLocalGroup())
	}
	left, right := proto.CloneOf(a.GetAccountPrivate()), proto.CloneOf(b.GetAccountPrivate())
	if left != nil {
		left.EncryptedPasswordToken = nil
	}
	if right != nil {
		right.EncryptedPasswordToken = nil
	}
	return proto.Equal(a.GetObservation().GetLocalUser(), b.GetObservation().GetLocalUser()) && proto.Equal(left, right)
}
