package journal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"slices"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal/journaldb"
	"lindm/internal/resource"
)

const maximumResourceOwnershipBytes = 1 << 20

var (
	ErrResourceOwnershipNotFound = errors.New("resource_ownership_not_found")
	ErrResourceOwnershipConflict = errors.New("resource_ownership_conflict")
	ErrResourceOwnershipUnknown  = errors.New("resource_ownership_unknown")
	ErrResourceOwnershipDrift    = errors.New("resource_ownership_drift")
	ErrResourceOwnershipCapacity = errors.New("resource_ownership_capacity")
)

// LoadResourceOwnership returns independently decoded private evidence. Missing
// ledgers are not an empty baseline and never authorize historical restoration.
func (s *Store) LoadResourceOwnership(ctx context.Context, deploymentID, deviceID, generation string, ref *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if resource.ValidateRef(ref) != nil {
		return nil, ErrResourceOwnershipConflict
	}
	key := journaldb.ReadResourceOwnershipParams{DeploymentID: deploymentID, DeviceID: deviceID, EnrollmentGeneration: generation, Kind: int64(ref.GetKind()), CanonicalKey: ref.GetCanonicalKey()}
	return s.loadResourceOwnership(ctx, s.queries, key)
}

// ClaimResourceOwnership binds a baseline to the exact durable signed owner.
// expectedRevision is zero only for a never-seen key. Released rows are retained
// and must be reclaimed using their current revision, preventing ABA claims.
func (s *Store) ClaimResourceOwnership(ctx context.Context, actionID string, expectedRevision int64, baseline *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	return s.mutateResourceOwnership(ctx, actionID, expectedRevision, baseline, nil, ownershipClaim)
}

// BeginResourceOwnershipEffect MUST complete before calling beforeEffect. It
// records the exact native before-state and makes any interruption UNKNOWN.
// This method does not consume start authority or authorize a native effect.
func (s *Store) BeginResourceOwnershipEffect(ctx context.Context, actionID string, expectedRevision int64, before *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error) {
	return s.mutateResourceOwnership(ctx, actionID, expectedRevision, before, dimensions, ownershipBegin)
}

// CompleteResourceOwnershipEffect durably records observed native post-state.
// It requires the same RUNNING action; revoked trust cannot suppress evidence.
// Native failures without trustworthy post-state deliberately leave UNKNOWN.
func (s *Store) CompleteResourceOwnershipEffect(ctx context.Context, actionID string, expectedRevision int64, after *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	return s.mutateResourceOwnership(ctx, actionID, expectedRevision, after, nil, ownershipComplete)
}

type ownershipTransition uint8

const (
	ownershipClaim ownershipTransition = iota
	ownershipBegin
	ownershipComplete
)

func (s *Store) mutateResourceOwnership(ctx context.Context, actionID string, expectedRevision int64, snapshot *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension, transition ownershipTransition) (*agentv1.ResourceOwnershipLedger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if expectedRevision < 0 || expectedRevision == math.MaxInt64 {
		return nil, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, resourceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	action, err := s.ownershipAction(ctx, q, actionID, transition == ownershipComplete)
	if err != nil {
		return nil, err
	}
	intent := action.GetIntent()
	ref := intent.GetDesired().GetRef()
	if err := s.validateOwnershipSnapshot(snapshot, ref); err != nil {
		return nil, err
	}
	key := journaldb.ReadResourceOwnershipParams{DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), Kind: int64(ref.GetKind()), CanonicalKey: ref.GetCanonicalKey()}
	ledger, err := s.loadResourceOwnership(ctx, q, key)
	missing := errors.Is(err, ErrResourceOwnershipNotFound)
	if err != nil && !missing {
		return nil, err
	}
	if (missing && expectedRevision != 0) || (!missing && ledger.GetRevision() != uint64(expectedRevision)) {
		return nil, ErrConflict
	}
	if !missing && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED && !sameResourceOwner(ledger.GetOwner(), intent.GetOwnership()) {
		return nil, ErrResourceOwnershipConflict
	}
	release := intent.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	switch transition {
	case ownershipClaim:
		if release {
			return nil, ErrResourceOwnershipConflict
		}
		digest, err := ResourceOwnershipDigest(ledger)
		if err != nil || !bytes.Equal(digest[:], action.GetNativePlan().GetOwnershipRevisionSha256()) {
			return nil, ErrConflict
		}
		if !missing && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
			if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
				return nil, ErrResourceOwnershipUnknown
			}
			return ledger, nil
		}
		if !ownershipAcquisitionAllowed(intent, snapshot) {
			return nil, ErrResourceOwnershipConflict
		}
		if err := s.rejectOtherGenerationOwnership(ctx, q, key); err != nil {
			return nil, err
		}
		if missing {
			history, err := q.ResourceOwnershipHistoricalEffects(ctx, journaldb.ResourceOwnershipHistoricalEffectsParams(key))
			if err != nil {
				return nil, stateReadError(ctx)
			}
			if history != 0 {
				return nil, ErrResourceOwnershipUnknown
			}
		}
		ledger = &agentv1.ResourceOwnershipLedger{FormatVersion: 1, InstallationId: s.installationID, DeploymentId: key.DeploymentID, DeviceId: key.DeviceID, EnrollmentGeneration: key.EnrollmentGeneration, Ref: proto.CloneOf(ref), Baseline: proto.CloneOf(snapshot), State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED}
	case ownershipBegin:
		if missing {
			return nil, ErrResourceOwnershipNotFound
		}
		if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
			return nil, ErrResourceOwnershipUnknown
		}
		if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
			return nil, ErrResourceOwnershipConflict
		}
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED || ledger.GetClaimActionId() != actionID {
			digest, err := ResourceOwnershipDigest(ledger)
			if err != nil || !bytes.Equal(digest[:], action.GetNativePlan().GetOwnershipRevisionSha256()) {
				return nil, ErrConflict
			}
		}
		if !validOwnershipDimensions(ref.GetKind(), dimensions) {
			return nil, ErrResourceOwnershipConflict
		}
		if release {
			if ledger.GetLastApplied() == nil || len(ledger.GetOwnedDimensions()) == 0 {
				return nil, ErrResourceOwnershipUnknown
			}
			if !ownershipLedgerMatches(ledger, snapshot) {
				return nil, ErrResourceOwnershipDrift
			}
			if !sameDimensions(dimensions, ledger.GetOwnedDimensions()) {
				return nil, ErrResourceOwnershipConflict
			}
		} else {
			if !ownershipDimensionsAllowed(action, dimensions) {
				return nil, ErrResourceOwnershipConflict
			}
			prior := ledger.GetLastApplied()
			if prior == nil {
				prior = ledger.GetBaseline()
			}
			if (ref.GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER || ref.GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP) && !accountIdentityMatches(prior, snapshot) {
				return nil, ErrResourceOwnershipDrift
			}
			for _, dimension := range dimensions {
				if !slices.Contains(ledger.OwnedDimensions, dimension) {
					if !baselineOwnershipDimensionMatches(ledger, snapshot, dimension) {
						return nil, ErrResourceOwnershipDrift
					}
					ledger.OwnedDimensions = append(ledger.OwnedDimensions, dimension)
				}
			}
			slices.Sort(ledger.OwnedDimensions)
		}
		if err := beginAccountEdges(ledger, action, snapshot, release); err != nil {
			return nil, err
		}
		ledger.BeforeEffect = proto.CloneOf(snapshot)
		ledger.EffectActionId = proto.String(actionID)
		ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN
	case ownershipComplete:
		if missing {
			return nil, ErrResourceOwnershipNotFound
		}
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN || ledger.GetEffectActionId() != actionID {
			return nil, ErrResourceOwnershipConflict
		}
		if err := completeAccountEdges(ledger, action, snapshot); err != nil {
			return nil, err
		}
		ledger.LastApplied = proto.CloneOf(snapshot)
		ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED
		if release {
			ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED
		}
	}
	ledger.Revision = uint64(expectedRevision + 1)
	ledger.Owner = proto.CloneOf(intent.GetOwnership())
	ledger.OwnerIntentEnvelope = bytes.Clone(action.GetIntentEnvelope())
	ledger.ClaimActionId = actionID
	encoded, err := s.encodeResourceOwnership(ledger)
	if err != nil {
		return nil, err
	}
	if missing {
		count, err := q.ReadResourceOwnershipUsage(ctx)
		if err != nil {
			return nil, stateReadError(ctx)
		}
		if count >= 256 {
			return nil, ErrResourceOwnershipCapacity
		}
		if err := consumeResourceOwnershipReservation(ctx, q, action, count); err != nil {
			return nil, err
		}
		changed, err := q.IncrementResourceOwnershipUsage(ctx, count)
		if err != nil {
			return nil, resourceActionWriteError(ctx)
		}
		if changed != 1 {
			return nil, ErrRecoveryHold
		}
		if err := q.InsertResourceOwnership(ctx, journaldb.InsertResourceOwnershipParams{DeploymentID: key.DeploymentID, DeviceID: key.DeviceID, EnrollmentGeneration: key.EnrollmentGeneration, Kind: key.Kind, CanonicalKey: key.CanonicalKey, Record: encoded}); err != nil {
			return nil, resourceActionWriteError(ctx)
		}
	} else {
		changed, err := q.ReplaceResourceOwnership(ctx, journaldb.ReplaceResourceOwnershipParams{Record: encoded, DeploymentID: key.DeploymentID, DeviceID: key.DeviceID, EnrollmentGeneration: key.EnrollmentGeneration, Kind: key.Kind, CanonicalKey: key.CanonicalKey, Revision: expectedRevision})
		if err != nil {
			return nil, resourceActionWriteError(ctx)
		}
		if changed != 1 {
			return nil, ErrConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, resourceActionWriteError(ctx)
	}
	return ledger, nil
}

func (s *Store) ownershipAction(ctx context.Context, q *journaldb.Queries, actionID string, completing bool) (*agentv1.ResourceExecutionRecord, error) {
	row, err := q.ReadResourceAction(ctx, actionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrResourceActionNotFound
	}
	if err != nil {
		return nil, stateReadError(ctx)
	}
	action, _, err := s.checkedResourceAction(ctx, q, row)
	if err != nil {
		return nil, err
	}
	if completing {
		if action.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
			return nil, ErrResourceOwnershipConflict
		}
		return action, nil
	}
	if action.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED {
		return nil, ErrResourceOwnershipConflict
	}
	authority, err := q.ReadState(ctx)
	if err != nil {
		return nil, stateReadError(ctx)
	}
	_, trustRevision, err := s.loadExecutionTrust(ctx, q)
	if err != nil {
		return nil, err
	}
	if err := s.resourceActionFences(ctx, q, authority.Revision, trustRevision, action, true); err != nil {
		return nil, err
	}
	return action, nil
}

func (s *Store) loadResourceOwnership(ctx context.Context, q *journaldb.Queries, key journaldb.ReadResourceOwnershipParams) (*agentv1.ResourceOwnershipLedger, error) {
	row, err := q.ReadResourceOwnership(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrResourceOwnershipNotFound
	}
	if err != nil {
		return nil, stateReadError(ctx)
	}
	ledger, err := s.decodeResourceOwnership(row)
	if err != nil {
		return nil, err
	}
	actionRow, err := q.ReadResourceAction(ctx, ledger.GetClaimActionId())
	if err != nil {
		return nil, stateReadError(ctx)
	}
	action, _, err := s.checkedResourceAction(ctx, q, actionRow)
	if err != nil {
		return nil, err
	}
	intent := action.GetIntent()
	if intent.GetDeploymentId() != ledger.GetDeploymentId() || intent.GetDeviceId() != ledger.GetDeviceId() || intent.GetEnrollmentGeneration() != ledger.GetEnrollmentGeneration() || !resource.RefEqual(intent.GetDesired().GetRef(), ledger.GetRef()) || !proto.Equal(intent.GetOwnership(), ledger.GetOwner()) || !bytes.Equal(action.GetIntentEnvelope(), ledger.GetOwnerIntentEnvelope()) {
		return nil, ErrRecoveryHold
	}
	return ledger, nil
}

// Owner revision changes do not steal ownership. The complete contributing
// source identity set must be identical; assignment/profile revisions are not
// native identities and cannot erase another owner's baseline.
func sameResourceOwner(left, right *agentv1.ResourceOwnershipBinding) bool {
	if left == nil || right == nil || len(left.GetSources()) == 0 || len(left.GetSources()) != len(right.GetSources()) {
		return false
	}
	for _, source := range left.GetSources() {
		count := 0
		for _, other := range right.GetSources() {
			if source.GetProfileId() == other.GetProfileId() && source.GetResourceId() == other.GetResourceId() {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}

func sameDimensions(left, right []agentv1.ResourceOwnedDimension) bool {
	if len(left) != len(right) {
		return false
	}
	for _, dimension := range left {
		if !slices.Contains(right, dimension) {
			return false
		}
	}
	return true
}

func ownershipAcquisitionAllowed(intent *agentv1.ResourceExecutionIntent, snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	observation := snapshot.GetObservation()
	if observation.GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL {
		return sysctlOwnershipAcquisitionAllowed(intent, snapshot)
	}
	if observation.GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION {
		return definitionOwnershipAcquisitionAllowed(intent, snapshot)
	}
	if observation.GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY {
		return passwordOwnershipAcquisitionAllowed(intent, snapshot)
	}
	if observation.GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE {
		return firewallOwnershipAcquisitionAllowed(intent, snapshot)
	}
	if group := observation.GetLocalGroup(); group != nil && group.GetOrigin() != resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES {
		return false
	}
	if user := observation.GetLocalUser(); user != nil && user.GetOrigin() != resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES {
		return false
	}
	if installed := observation.GetNativePackage(); installed != nil && installed.GetInstalled() && !installed.GetRecord().GetProvenanceKnown() {
		return false
	}
	if intent.GetOwnership().GetPolicy().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
		return true
	}
	switch {
	case observation.GetNativePackage() != nil:
		return !observation.GetNativePackage().GetInstalled() && observation.GetNativePackage().GetPinFile() == nil
	case observation.GetManagedFile() != nil:
		return !observation.GetManagedFile().GetExists()
	case observation.GetLocalGroup() != nil:
		return !observation.GetLocalGroup().GetExists()
	case observation.GetLocalUser() != nil:
		return !observation.GetLocalUser().GetExists()
	default:
		// Existing service runtime/enablement and other native objects require
		// signed adoption; absence cannot be inferred from incomplete evidence.
		return false
	}
}

// A new enrollment cannot adopt away an unreleased native owner from an older
// generation. Its signed authority does not authenticate the older baseline.
func (s *Store) rejectOtherGenerationOwnership(ctx context.Context, q *journaldb.Queries, key journaldb.ReadResourceOwnershipParams) error {
	for cursor := int64(0); ; {
		row, err := q.NextResourceOwnership(ctx, cursor)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return stateReadError(ctx)
		}
		cursor = row.LedgerID
		if row.Kind != key.Kind || row.CanonicalKey != key.CanonicalKey {
			continue
		}
		ledger, err := s.decodeResourceOwnership(row)
		if err != nil {
			return err
		}
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
			return ErrResourceOwnershipConflict
		}
	}
}
