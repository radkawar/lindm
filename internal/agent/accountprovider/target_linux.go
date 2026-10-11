//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
	"lindm/internal/secretseal"
)

func (p *Provider) target(ctx context.Context, d *resourcev1.ResourceDesiredState, op resourcev1.ResourceOperation, before *agentv1.ResourceOwnershipSnapshot, db *localDB, l *agentv1.ResourceOwnershipLedger) (*agentv1.ResourceOwnershipSnapshot, []*resourcev1.MemberEdgeChange, error) {
	target := proto.CloneOf(before)
	if op == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return releaseTarget(before, l)
	}
	if g := d.GetLocalGroup(); g != nil {
		o := target.Observation.GetLocalGroup()
		if g.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
			if o.GetExists() && !ownsObject(l) {
				return nil, nil, ErrConflict
			}
			for _, u := range db.users {
				if o.GetExists() && u[3] == strconv.FormatUint(uint64(o.GetGid()), 10) {
					return nil, nil, ErrUnsafe
				}
			}
			o.Exists = false
			o.Gid = nil
			o.Members = nil
		} else {
			if !o.GetExists() {
				if g.Gid == nil {
					return nil, nil, errors.New("accountprovider: creation requires an explicit noncolliding GID")
				}
				o.Exists = true
			}
			if before.GetObservation().GetLocalGroup().GetExists() && g.Gid != nil && o.GetGid() != g.GetGid() {
				for _, user := range db.users {
					if user[3] == decimal(o.GetGid()) {
						return nil, nil, ErrUnsafe
					}
				}
			}
			if g.Gid != nil {
				for name, row := range db.groups {
					if name != g.GetName() && row[2] == strconv.FormatUint(uint64(g.GetGid()), 10) {
						return nil, nil, ErrConflict
					}
				}
				o.Gid = proto.Uint32(g.GetGid())
			}
			if g.GetMembers() != nil {
				for _, name := range g.GetMembers().GetLocalUserNames() {
					if db.users[name] == nil || p.isAdministrator(db, name) || p.protected(name) {
						return nil, nil, ErrUnsafe
					}
				}
				o.Members = mergeMembers(o.GetMembers(), g.GetMembers())
			}
		}
	} else {
		u := d.GetLocalUser()
		o := target.Observation.GetLocalUser()
		if o.GetHasProcesses() && (u.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT || u.Uid != nil && u.GetUid() != o.GetUid()) {
			return nil, nil, ErrConflict
		}
		if u.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
			if o.GetExists() && !ownsObject(l) {
				return nil, nil, ErrConflict
			}
			o.Exists = false
			o.Uid = nil
			o.Gid = nil
			o.Groups = nil
			o.PasswordLocked = nil
			o.Aging = nil
			o.Shell = ""
			o.Home = nil
			o.UidGeneration = nil
			target.AccountPrivate.PasswordToken = nil
			target.AccountPrivate.EncryptedPasswordToken = nil
		} else {
			if !o.GetExists() {
				if u.Uid == nil || u.PrimaryGroup == nil || u.HomeDirectory == nil || u.Shell == nil {
					return nil, nil, errors.New("accountprovider: creation requires explicit UID, primary group, home and installed shell")
				}
				o.Exists = true
				o.PasswordLocked = proto.Bool(true)
				target.AccountPrivate.PasswordToken = proto.String("!")
				o.UidGeneration = proto.String(target.AccountPrivate.GetNativeGeneration())
				o.Aging = &resourcev1.PasswordAging{MinDays: proto.Uint32(0), MaxDays: proto.Uint32(99999), WarnDays: proto.Uint32(7), AccountNeverExpires: proto.Bool(true), AccountLocked: proto.Bool(false)}
			}
			if u.Uid != nil {
				for name, row := range db.users {
					if name != u.GetName() && row[2] == strconv.FormatUint(uint64(u.GetUid()), 10) {
						return nil, nil, ErrConflict
					}
				}
				o.Uid = proto.Uint32(u.GetUid())
			}
			if u.PrimaryGroup != nil {
				group := db.groups[u.GetPrimaryGroup()]
				if group == nil || p.protected(u.GetPrimaryGroup()) {
					return nil, nil, ErrUnsafe
				}
				gid, e := number(group[2])
				if e != nil || gid < 1000 {
					return nil, nil, ErrUnsafe
				}
				o.Gid = &gid
			}
			if u.GetSupplementaryGroups() != nil {
				for _, name := range u.GetSupplementaryGroups().GetLocalUserNames() {
					if db.groups[name] == nil || p.protected(name) {
						return nil, nil, ErrUnsafe
					}
				}
				o.Groups = mergeMembers(o.GetGroups(), u.GetSupplementaryGroups())
			}
			if u.HomeDirectory != nil && u.GetHomeDirectory() != o.GetHome().GetPath() {
				home := before.GetAccountPrivate().GetDesiredHome()
				if home == nil || home.GetPath() != u.GetHomeDirectory() {
					return nil, nil, ErrConflict
				}
				o.Home = proto.CloneOf(home)
			}
			if u.GetHome().GetCreation() == resourcev1.HomeCreation_HOME_CREATION_CREATE_IF_ABSENT && !o.GetHome().GetExists() {
				o.Home.Exists = true
				o.Home.OwnerUid = o.GetUid()
				o.Home.OwnerGid = o.GetGid()
				o.Home.Mode = 0700
				if u.GetHome().Mode != nil {
					o.Home.Mode = u.GetHome().GetMode()
				}
			}
			if u.Shell != nil {
				o.Shell = u.GetShell().GetInstalledShell()
			}
			if u.GetPassword().GetLocked() != nil && !o.GetPasswordLocked() {
				o.PasswordLocked = proto.Bool(true)
				target.AccountPrivate.PasswordToken = proto.String("!" + target.AccountPrivate.GetPasswordToken())
			}
			if hashed := u.GetPassword().GetHashed(); hashed != nil {
				hash, err := p.passwordHash(ctx, hashed)
				if err != nil {
					return nil, nil, err
				}
				// The delivered hash is the whole shadow field: unlocked and
				// exactly equal. Account lock/expiry stays the aging dimension.
				if subtle.ConstantTimeCompare([]byte(target.AccountPrivate.GetPasswordToken()), hash) != 1 {
					target.AccountPrivate.PasswordToken = proto.String(string(hash))
				}
				clear(hash)
				algorithm := hashed.GetAlgorithm()
				o.PasswordLocked = proto.Bool(false)
				o.PasswordAlgorithm = &algorithm
			}
			if u.GetAging() != nil {
				if o.Aging == nil {
					o.Aging = &resourcev1.PasswordAging{}
				}
				mergeAging(o.Aging, u.GetAging())
			}
		}
	}
	edges := edgeDifference(before.GetObservation(), target.GetObservation())
	for _, edge := range edges {
		if p.protected(edge.GetUser()) || p.isAdministrator(db, edge.GetUser()) || p.protected(edge.GetGroup()) {
			return nil, nil, ErrUnsafe
		}
	}
	return target, edges, nil
}

// passwordHash opens the delivered hash for one target computation. It must
// be a crypt(3) hash of the declared algorithm; the caller clears it.
func (p *Provider) passwordHash(ctx context.Context, policy *resourcev1.HashedPasswordPolicy) ([]byte, error) {
	if p.config.Secrets == nil {
		return nil, fmt.Errorf("%w: purpose-bound credential delivery is required", ErrUnsupported)
	}
	material, err := p.config.Secrets(ctx, policy.GetHash())
	if err != nil {
		return nil, err
	}
	defer secretseal.Clear(material)
	hash := bytes.Clone(material.GetPasswordHash())
	shape := &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: hash}}
	if len(hash) == 0 || validateMessage(shape) != nil || !resource.PasswordHashMatches(policy.GetAlgorithm(), hash) {
		clear(hash)
		return nil, fmt.Errorf("%w: delivered password hash does not match its policy", ErrUnsafe)
	}
	return hash, nil
}

// sameToken compares shadow password fields in constant time.
func sameToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func ownsObject(l *agentv1.ResourceOwnershipLedger) bool {
	return slices.Contains(l.GetOwnedDimensions(), agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT) && !exists(l.GetBaseline().GetObservation())
}
func mergeMembers(before []string, set *resourcev1.MemberSet) []string {
	out := slices.Clone(set.GetLocalUserNames())
	if set.GetMode() == resourcev1.SetMode_SET_MODE_ADDITIVE {
		out = append(out, before...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
func mergeAging(to, from *resourcev1.PasswordAging) {
	if from.MinDays != nil {
		to.MinDays = proto.Uint32(from.GetMinDays())
	}
	if from.MaxDays != nil {
		to.MaxDays = proto.Uint32(from.GetMaxDays())
	}
	if from.WarnDays != nil {
		to.WarnDays = proto.Uint32(from.GetWarnDays())
	}
	if from.InactiveDays != nil {
		to.InactiveDays = proto.Uint32(from.GetInactiveDays())
	}
	if from.AccountExpiresAt != nil {
		to.AccountExpiresAt = proto.CloneOf(from.AccountExpiresAt)
		to.AccountNeverExpires = nil
		to.AccountLocked = proto.Bool(from.GetAccountExpiresAt().GetSeconds() == 86400)
	}
	if from.AccountNeverExpires != nil {
		to.AccountNeverExpires = proto.Bool(from.GetAccountNeverExpires())
		to.AccountExpiresAt = nil
		to.AccountLocked = proto.Bool(false)
	}
	if from.AccountLocked != nil {
		if from.GetAccountLocked() {
			to.AccountExpiresAt = timestamppb.New(time.Unix(86400, 0))
			to.AccountNeverExpires = nil
		} else if to.GetAccountLocked() {
			to.AccountExpiresAt = nil
			to.AccountNeverExpires = proto.Bool(true)
		}
		to.AccountLocked = proto.Bool(from.GetAccountLocked())
	}
}
func edgeDifference(a, b *resourcev1.ResourceObservation) []*resourcev1.MemberEdgeChange {
	var old, next []string
	name := a.GetRef().GetCanonicalKey()
	group := a.GetLocalGroup() != nil
	if group {
		old = a.GetLocalGroup().GetMembers()
		next = b.GetLocalGroup().GetMembers()
	} else {
		old = a.GetLocalUser().GetGroups()
		next = b.GetLocalUser().GetGroups()
	}
	var out []*resourcev1.MemberEdgeChange
	for _, item := range old {
		if !slices.Contains(next, item) {
			e := &resourcev1.MemberEdgeChange{User: name, Group: item}
			if group {
				e.User = item
				e.Group = name
			}
			out = append(out, e)
		}
	}
	for _, item := range next {
		if !slices.Contains(old, item) {
			e := &resourcev1.MemberEdgeChange{User: name, Group: item, Present: true}
			if group {
				e.User = item
				e.Group = name
			}
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b *resourcev1.MemberEdgeChange) int {
		if a.GetUser() < b.GetUser() {
			return -1
		}
		if a.GetUser() > b.GetUser() {
			return 1
		}
		if a.GetGroup() < b.GetGroup() {
			return -1
		}
		if a.GetGroup() > b.GetGroup() {
			return 1
		}
		return 0
	})
	return out
}
func releaseTarget(before *agentv1.ResourceOwnershipSnapshot, l *agentv1.ResourceOwnershipLedger) (*agentv1.ResourceOwnershipSnapshot, []*resourcev1.MemberEdgeChange, error) {
	if l == nil || l.GetLastApplied() == nil || l.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED {
		return nil, nil, ErrConflict
	}
	target := proto.CloneOf(before)
	baseline := l.GetBaseline()
	last := l.GetLastApplied()
	if before.GetAccountPrivate().GetNativeGeneration() != last.GetAccountPrivate().GetNativeGeneration() || !bytes.Equal(before.GetAccountPrivate().GetIdentityAnchorSha256(), last.GetAccountPrivate().GetIdentityAnchorSha256()) {
		return nil, nil, ErrConflict
	}
	if l.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
		return target, nil, nil
	}
	for _, dim := range l.GetOwnedDimensions() {
		if dim == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS || dim == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_GROUPS {
			continue
		}
		if dim == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT {
			if !stateDimensionsEqual(before, last) {
				return nil, nil, ErrConflict
			}
			target = proto.CloneOf(baseline)
			break
		}
		if !dimensionEqual(before, last, dim) {
			return nil, nil, ErrConflict
		}
		copyDimension(target, baseline, dim)
	}
	for _, edge := range l.GetOwnedMemberEdges() {
		o := target.GetObservation()
		var set *[]string
		member := edge.GetGroup()
		current := before.GetObservation().GetLocalUser().GetGroups()
		if g := o.GetLocalGroup(); g != nil {
			set = &g.Members
			member = edge.GetUser()
			current = before.GetObservation().GetLocalGroup().GetMembers()
		} else {
			set = &o.GetLocalUser().Groups
		}
		if slices.Contains(current, member) != edge.GetLastAppliedPresent() {
			return nil, nil, ErrConflict
		}
		if !exists(o) {
			if edge.GetBaselinePresent() {
				return nil, nil, ErrConflict
			}
			continue
		}
		if edge.GetBaselinePresent() {
			if !slices.Contains(*set, member) {
				*set = append(*set, member)
			}
		} else {
			*set = slices.DeleteFunc(*set, func(s string) bool { return s == member })
		}
		slices.Sort(*set)
	}
	return target, edgeDifference(before.GetObservation(), target.GetObservation()), nil
}
func stateDimensionsEqual(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	a = proto.CloneOf(a)
	b = proto.CloneOf(b)
	a.Observation.Metadata = nil
	b.Observation.Metadata = nil
	if g := a.Observation.GetLocalGroup(); g != nil {
		g.LocalFileRevision = nil
		b.Observation.GetLocalGroup().LocalFileRevision = nil
	} else {
		a.Observation.GetLocalUser().LocalFileRevision = nil
		b.Observation.GetLocalUser().LocalFileRevision = nil
	}
	a.AccountMemberEdges = nil
	b.AccountMemberEdges = nil
	a.AccountNssReceipt = nil
	b.AccountNssReceipt = nil
	a.AccountPrivate.DesiredHome = nil
	b.AccountPrivate.DesiredHome = nil
	a.AccountPrivate.EncryptedPasswordToken = nil
	b.AccountPrivate.EncryptedPasswordToken = nil
	return proto.Equal(a, b)
}
func dimensionEqual(a, b *agentv1.ResourceOwnershipSnapshot, dim agentv1.ResourceOwnedDimension) bool {
	copy := proto.CloneOf(a)
	copyDimension(copy, b, dim)
	return sameState(a, copy)
}
func copyDimension(to, from *agentv1.ResourceOwnershipSnapshot, dim agentv1.ResourceOwnedDimension) {
	a, b := to.GetObservation().GetLocalUser(), from.GetObservation().GetLocalUser()
	switch dim {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID:
		to.Observation.GetLocalGroup().Gid = from.Observation.GetLocalGroup().Gid
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_UID:
		a.Uid = b.Uid
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PRIMARY_GROUP:
		a.Gid = b.Gid
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_HOME:
		a.Home = proto.CloneOf(b.GetHome())
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL:
		a.Shell = b.GetShell()
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK:
		a.PasswordLocked = b.PasswordLocked
		to.AccountPrivate.PasswordToken = from.AccountPrivate.PasswordToken
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MIN:
		a.Aging.MinDays = b.GetAging().MinDays
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MAX:
		a.Aging.MaxDays = b.GetAging().MaxDays
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_WARN:
		a.Aging.WarnDays = b.GetAging().WarnDays
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_INACTIVE:
		a.Aging.InactiveDays = b.GetAging().InactiveDays
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_EXPIRY:
		a.Aging.AccountExpiresAt = proto.CloneOf(b.GetAging().GetAccountExpiresAt())
		a.Aging.AccountNeverExpires = b.GetAging().AccountNeverExpires
		a.Aging.AccountLocked = b.GetAging().AccountLocked
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_ACCOUNT_LOCK:
		a.Aging.AccountExpiresAt = proto.CloneOf(b.GetAging().GetAccountExpiresAt())
		a.Aging.AccountNeverExpires = b.GetAging().AccountNeverExpires
		a.Aging.AccountLocked = b.GetAging().AccountLocked
	}
}
func dimensions(before, target *agentv1.ResourceOwnershipSnapshot) []agentv1.ResourceOwnedDimension {
	if exists(before.GetObservation()) != exists(target.GetObservation()) {
		return []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT}
	}
	if !exists(before.GetObservation()) {
		return nil
	}
	candidates := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID}
	if before.GetObservation().GetLocalUser() != nil {
		candidates = []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_UID, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PRIMARY_GROUP, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_HOME, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MIN, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MAX, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_WARN, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_INACTIVE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_EXPIRY}
	}
	var out []agentv1.ResourceOwnedDimension
	for _, dim := range candidates {
		if dim == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_EXPIRY && before.GetObservation().GetLocalUser().GetAging().GetAccountLocked() != target.GetObservation().GetLocalUser().GetAging().GetAccountLocked() {
			dim = agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_ACCOUNT_LOCK
		}
		if !dimensionEqual(before, target, dim) {
			out = append(out, dim)
		}
	}
	if len(edgeDifference(before.GetObservation(), target.GetObservation())) != 0 {
		dim := agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS
		if before.GetObservation().GetLocalUser() != nil {
			dim = agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_GROUPS
		}
		out = append(out, dim)
	}
	return out
}
func changedFields(a, b *agentv1.ResourceOwnershipSnapshot) []resourcev1.UserField {
	var out []resourcev1.UserField
	for _, d := range dimensions(a, b) {
		var field resourcev1.UserField
		switch d {
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PRIMARY_GROUP:
			field = resourcev1.UserField_USER_FIELD_PRIMARY_GROUP
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_HOME:
			field = resourcev1.UserField_USER_FIELD_HOME
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL:
			field = resourcev1.UserField_USER_FIELD_SHELL
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK:
			field = resourcev1.UserField_USER_FIELD_PASSWORD
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_ACCOUNT_LOCK:
			field = resourcev1.UserField_USER_FIELD_ACCOUNT_LOCK
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MIN, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MAX, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_WARN, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_INACTIVE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_EXPIRY:
			field = resourcev1.UserField_USER_FIELD_AGING
		}
		if field != 0 && !slices.Contains(out, field) {
			out = append(out, field)
		}
	}
	return out
}
func needsHome(target *agentv1.ResourceOwnershipSnapshot) bool {
	home := target.GetObservation().GetLocalUser().GetHome()
	return home.GetExists() && home.GetInode() == 0
}
