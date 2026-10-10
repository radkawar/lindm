package journal

import (
	"bytes"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func privateOwnershipSnapshotValid(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	observation := snapshot.GetObservation()
	if file := observation.GetManagedFile(); file != nil {
		if len(file.GetNativeIdentitySha256()) != 32 || len(file.GetSecurityMetadataSha256()) != 32 {
			return false
		}
		var size int
		previous := ""
		for _, attr := range snapshot.GetManagedFileXattrs() {
			if attr.GetName() <= previous || (!strings.HasPrefix(attr.GetName(), "user.") && attr.GetName() != "security.selinux") {
				return false
			}
			previous = attr.GetName()
			size += len(attr.GetName()) + len(attr.GetValue())
		}
		if size > 32768 || (!file.GetExists() && len(snapshot.GetManagedFileXattrs()) != 0) {
			return false
		}
	}
	if observation.GetLocalGroup() != nil || observation.GetLocalUser() != nil {
		private := snapshot.GetAccountPrivate()
		if private == nil || !canonicalResourceID(private.GetNativeGeneration()) || len(private.GetIdentityAnchorSha256()) != 32 {
			return false
		}
		if group := observation.GetLocalGroup(); group != nil {
			if group.GetOrigin() != resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES || private.PasswordToken != nil {
				return false
			}
		}
		if user := observation.GetLocalUser(); user != nil {
			if user.GetOrigin() != resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES || (user.GetExists() && private.PasswordToken == nil) || (!user.GetExists() && private.PasswordToken != nil) {
				return false
			}
			if user.UidGeneration != nil && user.GetUidGeneration() != private.GetNativeGeneration() {
				return false
			}
		}
		for i, edge := range snapshot.GetAccountMemberEdges() {
			if !accountEdgeBinds(snapshot, edge.GetUser(), edge.GetGroup()) {
				return false
			}
			for _, prior := range snapshot.GetAccountMemberEdges()[:i] {
				if edge.GetUser() == prior.GetUser() && edge.GetGroup() == prior.GetGroup() {
					return false
				}
			}
		}
	}
	return true
}

func extendedDimensionKind(kind resourcev1.ResourceKind, dimension agentv1.ResourceOwnedDimension) bool {
	switch {
	case dimension >= agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_PRESENCE && dimension <= agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_GID:
		return kind == resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE
	case dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID || dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS:
		return kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP
	case dimension >= agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_UID && dimension <= agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_ACCOUNT_LOCK:
		return kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER
	default:
		return false
	}
}

func managedFileDimensionMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	a, b := left.GetObservation().GetManagedFile(), right.GetObservation().GetManagedFile()
	if a == nil || b == nil || a.GetPath() != b.GetPath() || a.GetExists() != b.GetExists() || !bytes.Equal(a.GetAncestrySha256(), b.GetAncestrySha256()) || len(a.GetNativeIdentitySha256()) != 32 || !bytes.Equal(a.GetNativeIdentitySha256(), b.GetNativeIdentitySha256()) || !bytes.Equal(a.GetSecurityMetadataSha256(), b.GetSecurityMetadataSha256()) || len(left.GetManagedFileXattrs()) != len(right.GetManagedFileXattrs()) {
		return false
	}
	for i, attr := range left.GetManagedFileXattrs() {
		if !proto.Equal(attr, right.GetManagedFileXattrs()[i]) {
			return false
		}
	}
	if a.GetExists() && (a.GetFile().GetDevice() != b.GetFile().GetDevice() || a.GetFile().GetInode() != b.GetFile().GetInode()) {
		return false
	}
	switch dimension {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_PRESENCE:
		return proto.Equal(a.GetFile(), b.GetFile()) && bytes.Equal(left.GetManagedFileContent(), right.GetManagedFileContent())
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_CONTENT:
		return bytes.Equal(a.GetFile().GetSha256(), b.GetFile().GetSha256()) && bytes.Equal(left.GetManagedFileContent(), right.GetManagedFileContent())
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_MODE:
		return a.GetFile().GetMode() == b.GetFile().GetMode()
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_UID:
		return a.GetFile().GetUid() == b.GetFile().GetUid()
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_GID:
		return a.GetFile().GetGid() == b.GetFile().GetGid()
	default:
		return false
	}
}

func accountIdentityMatches(left, right *agentv1.ResourceOwnershipSnapshot) bool {
	a, b := left.GetAccountPrivate(), right.GetAccountPrivate()
	if a == nil || b == nil || a.GetNativeGeneration() != b.GetNativeGeneration() || !bytes.Equal(a.GetIdentityAnchorSha256(), b.GetIdentityAnchorSha256()) {
		return false
	}
	if group := left.GetObservation().GetLocalGroup(); group != nil {
		other := right.GetObservation().GetLocalGroup()
		return other != nil && group.GetName() == other.GetName() && group.GetExists() == other.GetExists() && group.GetGid() == other.GetGid() && group.GetOrigin() == other.GetOrigin()
	}
	user, other := left.GetObservation().GetLocalUser(), right.GetObservation().GetLocalUser()
	return user != nil && other != nil && user.GetName() == other.GetName() && user.GetExists() == other.GetExists() && user.GetUid() == other.GetUid() && user.GetOrigin() == other.GetOrigin()
}

func accountDimensionMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	if !accountIdentityMatches(left, right) {
		return false
	}
	return accountDimensionValueMatches(left, right, dimension)
}

func accountDimensionValueMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	a, b := left.GetObservation().GetLocalUser(), right.GetObservation().GetLocalUser()
	var emptyAging resourcev1.PasswordAging
	leftAging, rightAging := a.GetAging(), b.GetAging()
	if leftAging == nil {
		leftAging = &emptyAging
	}
	if rightAging == nil {
		rightAging = &emptyAging
	}
	switch dimension {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_UID:
		return true // Numeric native identity was already compared.
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_GROUPS:
		return true // The ledger's owned edges, not the entire set, are compared.
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PRIMARY_GROUP:
		return equalOptional(a.Gid, b.Gid)
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_HOME:
		return proto.Equal(a.GetHome(), b.GetHome())
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL:
		return a.GetShell() == b.GetShell()
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK:
		return equalOptional(a.PasswordLocked, b.PasswordLocked) && equalOptional(left.GetAccountPrivate().PasswordToken, right.GetAccountPrivate().PasswordToken)
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MIN:
		return equalOptional(leftAging.MinDays, rightAging.MinDays)
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MAX:
		return equalOptional(leftAging.MaxDays, rightAging.MaxDays)
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_WARN:
		return equalOptional(leftAging.WarnDays, rightAging.WarnDays)
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_INACTIVE:
		return equalOptional(leftAging.InactiveDays, rightAging.InactiveDays)
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_EXPIRY:
		return proto.Equal(a.GetAging().GetAccountExpiresAt(), b.GetAging().GetAccountExpiresAt()) && a.GetAging().GetAccountNeverExpires() == b.GetAging().GetAccountNeverExpires()
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_ACCOUNT_LOCK:
		return equalOptional(leftAging.AccountLocked, rightAging.AccountLocked) &&
			proto.Equal(leftAging.GetAccountExpiresAt(), rightAging.GetAccountExpiresAt()) &&
			equalOptional(leftAging.AccountNeverExpires, rightAging.AccountNeverExpires)
	default:
		return false
	}
}

// newOwnershipDimensionMatches fences a dimension the ledger starts managing.
// An object the ledger created has no pre-management value for any attribute,
// so the new dimension must equal the last state it applied: a foreign edit
// since then remains drift. Otherwise the original baseline is the fence.
func newOwnershipDimensionMatches(ledger *agentv1.ResourceOwnershipLedger, current *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	if slices.Contains(ledger.GetOwnedDimensions(), agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT) && ledger.GetLastApplied() != nil {
		return ownershipDimensionsMatch(ledger.GetLastApplied(), current, []agentv1.ResourceOwnedDimension{dimension})
	}
	return baselineOwnershipDimensionMatches(ledger, current, dimension)
}

// A journal-owned UID/GID change updates the live numeric identity fence, not
// the original baseline for unrelated fields. New dimensions still require
// their original baseline value and the same protected native incarnation.
func baselineOwnershipDimensionMatches(ledger *agentv1.ResourceOwnershipLedger, current *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	baseline := ledger.GetBaseline()
	if baseline.GetObservation().GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY {
		return PasswordBaselineDimensionMatches(ledger, current, dimension)
	}
	numericDimension := agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_UNSPECIFIED
	switch baseline.GetObservation().GetRef().GetKind() {
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:
		numericDimension = agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_UID
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP:
		numericDimension = agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID
	}
	if numericDimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_UNSPECIFIED ||
		!slices.Contains(ledger.GetOwnedDimensions(), numericDimension) ||
		dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT ||
		dimension == numericDimension {
		return ownershipDimensionsMatch(baseline, current, []agentv1.ResourceOwnedDimension{dimension})
	}
	if !accountIdentityMatches(ledger.GetLastApplied(), current) {
		return false
	}
	left, right := baseline.GetAccountPrivate(), current.GetAccountPrivate()
	if left == nil || right == nil || left.GetNativeGeneration() != right.GetNativeGeneration() || !bytes.Equal(left.GetIdentityAnchorSha256(), right.GetIdentityAnchorSha256()) {
		return false
	}
	if group := baseline.GetObservation().GetLocalGroup(); group != nil {
		other := current.GetObservation().GetLocalGroup()
		if other == nil || group.GetName() != other.GetName() || group.GetExists() != other.GetExists() || group.GetOrigin() != other.GetOrigin() {
			return false
		}
	} else {
		user, other := baseline.GetObservation().GetLocalUser(), current.GetObservation().GetLocalUser()
		if user == nil || other == nil || user.GetName() != other.GetName() || user.GetExists() != other.GetExists() || user.GetOrigin() != other.GetOrigin() {
			return false
		}
	}
	return accountDimensionValueMatches(baseline, current, dimension)
}

func equalOptional[T comparable](left, right *T) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func accountEdgeBinds(snapshot *agentv1.ResourceOwnershipSnapshot, user, group string) bool {
	if observed := snapshot.GetObservation().GetLocalGroup(); observed != nil {
		return observed.GetName() == group
	}
	if observed := snapshot.GetObservation().GetLocalUser(); observed != nil {
		return observed.GetName() == user
	}
	return false
}

func accountEdgePresent(snapshot *agentv1.ResourceOwnershipSnapshot, user, group string) bool {
	if observed := snapshot.GetObservation().GetLocalGroup(); observed != nil {
		return observed.GetExists() && observed.GetName() == group && slices.Contains(observed.GetMembers(), user)
	}
	if observed := snapshot.GetObservation().GetLocalUser(); observed != nil {
		return observed.GetExists() && observed.GetName() == user && slices.Contains(observed.GetGroups(), group)
	}
	return false
}

func ownershipLedgerMatches(ledger *agentv1.ResourceOwnershipLedger, current *agentv1.ResourceOwnershipSnapshot) bool {
	if !ownershipDimensionsMatch(ledger.GetLastApplied(), current, ledger.GetOwnedDimensions()) {
		return false
	}
	for _, edge := range ledger.GetOwnedMemberEdges() {
		if !accountEdgeBinds(current, edge.GetUser(), edge.GetGroup()) || accountEdgePresent(current, edge.GetUser(), edge.GetGroup()) != edge.GetLastAppliedPresent() {
			return false
		}
	}
	return true
}

func accountPlannedEdges(action *agentv1.ResourceExecutionRecord) []*resourcev1.MemberEdgeChange {
	if plan := action.GetNativePlan().GetLocalGroup(); plan != nil {
		return plan.GetMemberEdges()
	}
	return action.GetNativePlan().GetLocalUser().GetMemberEdges()
}

func beginAccountEdges(ledger *agentv1.ResourceOwnershipLedger, action *agentv1.ResourceExecutionRecord, before *agentv1.ResourceOwnershipSnapshot, release bool) error {
	planned := accountPlannedEdges(action)
	if len(planned) != len(before.GetAccountMemberEdges()) {
		return ErrResourceOwnershipConflict
	}
	if len(planned) != 0 && !slices.Contains(ledger.GetOwnedDimensions(), agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS) && !slices.Contains(ledger.GetOwnedDimensions(), agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_GROUPS) && !slices.Contains(ledger.GetOwnedDimensions(), agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT) {
		return ErrResourceOwnershipConflict
	}
	for i, edge := range planned {
		if !proto.Equal(edge, before.GetAccountMemberEdges()[i]) {
			return ErrResourceOwnershipConflict
		}
		var owned *agentv1.ResourceOwnedMemberEdge
		for _, candidate := range ledger.GetOwnedMemberEdges() {
			if edge.GetUser() == candidate.GetUser() && edge.GetGroup() == candidate.GetGroup() {
				owned = candidate
				break
			}
		}
		if release {
			if owned == nil || edge.GetPresent() != owned.GetBaselinePresent() {
				return ErrResourceOwnershipConflict
			}
		} else if owned == nil {
			present := accountEdgePresent(before, edge.GetUser(), edge.GetGroup())
			// An already-satisfied membership is observed, not acquired.
			if present != edge.GetPresent() {
				ledger.OwnedMemberEdges = append(ledger.OwnedMemberEdges, &agentv1.ResourceOwnedMemberEdge{User: edge.GetUser(), Group: edge.GetGroup(), BaselinePresent: present, LastAppliedPresent: present})
			}
		}
	}
	return nil
}

func completeAccountEdges(ledger *agentv1.ResourceOwnershipLedger, action *agentv1.ResourceExecutionRecord, after *agentv1.ResourceOwnershipSnapshot) error {
	for _, edge := range ledger.GetBeforeEffect().GetAccountMemberEdges() {
		if accountEdgePresent(after, edge.GetUser(), edge.GetGroup()) != edge.GetPresent() {
			return ErrResourceOwnershipConflict
		}
	}
	for _, edge := range ledger.GetOwnedMemberEdges() {
		expected := edge.GetLastAppliedPresent()
		for _, planned := range ledger.GetBeforeEffect().GetAccountMemberEdges() {
			if edge.GetUser() == planned.GetUser() && edge.GetGroup() == planned.GetGroup() {
				expected = planned.GetPresent()
				break
			}
		}
		if action.GetIntent().GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && action.GetIntent().GetOwnership().GetPolicy().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
			expected = edge.GetBaselinePresent()
		}
		if accountEdgePresent(after, edge.GetUser(), edge.GetGroup()) != expected {
			return ErrResourceOwnershipConflict
		}
		edge.LastAppliedPresent = expected
	}
	return nil
}

func extendedDimensionAllowed(action *agentv1.ResourceExecutionRecord, dimension agentv1.ResourceOwnedDimension) bool {
	desired := action.GetIntent().GetDesired()
	if file := desired.GetManagedFile(); file != nil {
		change := action.GetNativePlan().GetManagedFile().GetChange()
		if change == resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE || change == resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_REMOVE_OWNED {
			return true
		}
		switch dimension {
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_CONTENT:
			return file.Content != nil
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_MODE:
			return file.Mode != nil
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_UID:
			return file.Uid != nil
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_GID:
			return file.Gid != nil
		default:
			return false
		}
	}
	group, user := desired.GetLocalGroup(), desired.GetLocalUser()
	if group == nil && user == nil {
		return false
	}
	if dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT {
		change := action.GetNativePlan().GetLocalUser().GetChange()
		if group != nil {
			change = action.GetNativePlan().GetLocalGroup().GetChange()
		}
		return change == resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE || change == resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_REMOVE_OWNED
	}
	var emptyAging resourcev1.PasswordAging
	aging := user.GetAging()
	if aging == nil {
		aging = &emptyAging
	}
	switch dimension {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID:
		return group.Gid != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS:
		return group.GetMembers() != nil && (group.GetMembers().GetMode() != resourcev1.SetMode_SET_MODE_EXACT || action.GetIntent().GetOwnership().GetPolicy().GetCompleteMembershipDimension())
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_UID:
		return user.Uid != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PRIMARY_GROUP:
		return user.PrimaryGroup != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_GROUPS:
		return user.GetSupplementaryGroups() != nil && (user.GetSupplementaryGroups().GetMode() != resourcev1.SetMode_SET_MODE_EXACT || action.GetIntent().GetOwnership().GetPolicy().GetCompleteMembershipDimension())
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_HOME:
		return user.HomeDirectory != nil || user.GetHome() != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL:
		return user.GetShell() != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK:
		return user.GetPassword() != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MIN:
		return aging.MinDays != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MAX:
		return aging.MaxDays != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_WARN:
		return aging.WarnDays != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_INACTIVE:
		return aging.InactiveDays != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_EXPIRY:
		return aging.AccountExpiresAt != nil || aging.AccountNeverExpires != nil
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_ACCOUNT_LOCK:
		return aging.AccountLocked != nil
	default:
		return false
	}
}
