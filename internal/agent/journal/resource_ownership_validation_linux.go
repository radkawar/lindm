package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal/journaldb"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

// ResourceOwnershipDigest binds plans to the full private ledger, including its
// monotonic revision. A never-claimed resource uses the all-zero digest.
func ResourceOwnershipDigest(ledger *agentv1.ResourceOwnershipLedger) ([32]byte, error) {
	if ledger == nil {
		return [32]byte{}, nil
	}
	projection := proto.CloneOf(ledger)
	for _, snapshot := range ownershipSnapshots(projection) {
		if err := redactOwnershipDigest(snapshot); err != nil {
			return [32]byte{}, err
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(projection)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.resource-ownership.v1\x00"))
	_, _ = h.Write(encoded)
	var digest [32]byte
	h.Sum(digest[:0])
	return digest, nil
}

func (s *Store) validateOwnershipSnapshot(snapshot *agentv1.ResourceOwnershipSnapshot, ref *resourcev1.ResourceRef) error {
	if snapshot == nil || proto.Size(snapshot) > 256<<10 || protodata.ValidateClosed(snapshot.ProtoReflect()) != nil || s.validator.Validate(snapshot) != nil {
		return ErrResourceOwnershipConflict
	}
	observation := snapshot.GetObservation()
	if resource.ValidateObservation(observation) != nil || !resource.RefEqual(observation.GetRef(), ref) || observation.GetMetadata().GetObservationStatus() != resourcev1.ObservationStatus_OBSERVATION_STATUS_OK {
		return ErrResourceOwnershipConflict
	}
	if !privateOwnershipSnapshotValid(snapshot) {
		return ErrResourceOwnershipConflict
	}
	if rules := ownershipRules(ref.GetKind()); rules.valid != nil && !rules.valid(snapshot) {
		return ErrResourceOwnershipConflict
	}
	if file := observation.GetManagedFile(); file != nil {
		if file.GetExists() != (snapshot.ManagedFileContent != nil) {
			return ErrResourceOwnershipConflict
		}
		if file.GetExists() {
			digest := sha256.Sum256(snapshot.GetManagedFileContent())
			if !bytes.Equal(digest[:], file.GetFile().GetSha256()) {
				return ErrResourceOwnershipConflict
			}
		}
	}
	if pkg := observation.GetNativePackage(); pkg != nil && pkg.GetPinFile() != nil {
		digest := sha256.Sum256(pkg.GetPinContents())
		if !bytes.Equal(digest[:], pkg.GetPinFile().GetSha256()) {
			return ErrResourceOwnershipConflict
		}
	}
	return nil
}

func (s *Store) validateResourceOwnershipLedger(ledger *agentv1.ResourceOwnershipLedger) error {
	if ledger == nil || ledger.GetInstallationId() != s.installationID || proto.Size(ledger) > maximumResourceOwnershipBytes || protodata.ValidateClosed(ledger.ProtoReflect()) != nil || s.validator.Validate(ledger) != nil {
		return ErrResourceOwnershipConflict
	}
	for _, id := range []string{ledger.GetInstallationId(), ledger.GetDeploymentId(), ledger.GetDeviceId(), ledger.GetEnrollmentGeneration(), ledger.GetClaimActionId()} {
		if !canonicalResourceID(id) {
			return ErrResourceOwnershipConflict
		}
	}
	if !sameResourceOwner(ledger.GetOwner(), ledger.GetOwner()) || !canonicalResourceID(ledger.GetOwner().GetAssignmentId()) || !canonicalResourceID(ledger.GetOwner().GetResourceId()) {
		return ErrResourceOwnershipConflict
	}
	for _, source := range ledger.GetOwner().GetSources() {
		if !canonicalResourceID(source.GetProfileId()) || !canonicalResourceID(source.GetProfileRevision()) || !canonicalResourceID(source.GetResourceId()) {
			return ErrResourceOwnershipConflict
		}
	}
	for _, snapshot := range []*agentv1.ResourceOwnershipSnapshot{ledger.GetBaseline(), ledger.GetLastApplied(), ledger.GetBeforeEffect()} {
		if snapshot != nil {
			if err := s.validateOwnershipSnapshot(snapshot, ledger.GetRef()); err != nil {
				return err
			}
		}
	}
	if !validOwnershipDimensions(ledger.GetRef().GetKind(), ledger.GetOwnedDimensions()) {
		return ErrResourceOwnershipConflict
	}
	for i, edge := range ledger.GetOwnedMemberEdges() {
		if !accountEdgeBinds(ledger.GetBaseline(), edge.GetUser(), edge.GetGroup()) {
			return ErrResourceOwnershipConflict
		}
		for _, prior := range ledger.GetOwnedMemberEdges()[:i] {
			if edge.GetUser() == prior.GetUser() && edge.GetGroup() == prior.GetGroup() {
				return ErrResourceOwnershipConflict
			}
		}
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED {
		if ledger.GetLastApplied() != nil || ledger.GetBeforeEffect() != nil || len(ledger.GetOwnedDimensions()) != 0 {
			return ErrResourceOwnershipConflict
		}
	} else if len(ledger.GetOwnedDimensions()) == 0 || ledger.GetBeforeEffect() == nil {
		return ErrResourceOwnershipConflict
	}
	if ledger.GetBeforeEffect() != nil && ledger.GetEffectActionId() != ledger.GetClaimActionId() {
		return ErrResourceOwnershipConflict
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED && ledger.GetLastApplied() == nil {
		return ErrResourceOwnershipConflict
	}
	return nil
}

func (s *Store) encodeResourceOwnership(ledger *agentv1.ResourceOwnershipLedger) ([]byte, error) {
	if err := s.validateResourceOwnershipLedger(ledger); err != nil {
		return nil, err
	}
	disk, err := s.sealOwnershipSecrets(ledger)
	if err != nil {
		return nil, err
	}
	if proto.Size(disk) > maximumResourceOwnershipBytes {
		return nil, ErrResourceOwnershipConflict
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(disk)
	if err != nil {
		return nil, ErrResourceOwnershipConflict
	}
	return encoded, nil
}

func (s *Store) decodeResourceOwnership(row journaldb.ResourceOwnership) (*agentv1.ResourceOwnershipLedger, error) {
	if row.Revision < 1 || len(row.Record) == 0 || len(row.Record) > maximumResourceOwnershipBytes {
		return nil, ErrRecoveryHold
	}
	ledger := new(agentv1.ResourceOwnershipLedger)
	if proto.Unmarshal(row.Record, ledger) != nil {
		return nil, ErrRecoveryHold
	}
	if err := s.openOwnershipSecrets(ledger); err != nil {
		return nil, err
	}
	if err := s.validateResourceOwnershipLedger(ledger); err != nil {
		return nil, ErrRecoveryHold
	}
	if ledger.GetRevision() != uint64(row.Revision) || ledger.GetDeploymentId() != row.DeploymentID || ledger.GetDeviceId() != row.DeviceID || ledger.GetEnrollmentGeneration() != row.EnrollmentGeneration || int64(ledger.GetRef().GetKind()) != row.Kind || ledger.GetRef().GetCanonicalKey() != row.CanonicalKey {
		return nil, ErrRecoveryHold
	}
	return ledger, nil
}

func (s *Store) validateResourceOwnership(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	count, err := s.queries.ReadResourceOwnershipUsage(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	total, err := s.queries.ResourceOwnershipCount(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if count != total || count < 0 || count > 256 {
		return ErrRecoveryHold
	}
	reserved, err := s.queries.CountResourceOwnershipReservations(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	invalid, err := s.queries.InvalidResourceOwnershipReservations(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if count+reserved > 256 || invalid != 0 {
		return ErrRecoveryHold
	}
	if err := s.validatePendingOwnershipReservations(ctx); err != nil {
		return err
	}
	var seen int64
	for cursor := int64(0); ; {
		row, err := s.queries.NextResourceOwnership(ctx, cursor)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return stateReadError(ctx)
		}
		key := journaldb.ReadResourceOwnershipParams{DeploymentID: row.DeploymentID, DeviceID: row.DeviceID, EnrollmentGeneration: row.EnrollmentGeneration, Kind: row.Kind, CanonicalKey: row.CanonicalKey}
		if _, err := s.loadResourceOwnership(ctx, s.queries, key); err != nil {
			return err
		}
		cursor = row.LedgerID
		seen++
	}
	if seen != count {
		return ErrRecoveryHold
	}
	return nil
}

func validOwnershipDimensions(kind resourcev1.ResourceKind, dimensions []agentv1.ResourceOwnedDimension) bool {
	for i, dimension := range dimensions {
		for _, prior := range dimensions[:i] {
			if prior == dimension {
				return false
			}
		}
		switch dimension {
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_RUNTIME, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_ENABLEMENT:
			if kind != resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PRESENCE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_VERSION, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PIN:
			if kind != resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT:
			if kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE || kind == resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE || kind == resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE || kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL || kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION || kind == resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY || kind == resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE {
				return false
			}
		default:
			if !extendedDimensionKind(kind, dimension) && !sysctlOwnershipDimensionKind(kind, dimension) && !definitionOwnershipDimensionKind(kind, dimension) && !passwordOwnershipDimensionKind(kind, dimension) && !firewallOwnershipDimensionKind(kind, dimension) {
				return false
			}
		}
	}
	return true
}

func ownershipDimensionsAllowed(action *agentv1.ResourceExecutionRecord, dimensions []agentv1.ResourceOwnedDimension) bool {
	if len(dimensions) == 0 || !validOwnershipDimensions(action.GetIntent().GetDesired().GetRef().GetKind(), dimensions) {
		return false
	}
	kind := action.GetIntent().GetDesired().GetRef().GetKind()
	if kind == resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE && slices.Contains(dimensions, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_PRESENCE) && len(dimensions) != 5 {
		return false
	}
	for _, dimension := range dimensions {
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP || kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER || kind == resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE {
			if !extendedDimensionAllowed(action, dimension) {
				return false
			}
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL && !sysctlOwnershipDimensionAllowed(action, dimension) {
			return false
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION && !definitionOwnershipDimensionAllowed(action, dimension) {
			return false
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY && !passwordOwnershipDimensionAllowed(action, dimension) {
			return false
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE && !firewallOwnershipDimensionAllowed(action, dimension) {
			return false
		}
		switch dimension {
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_RUNTIME:
			if !action.GetNativePlan().GetSystemdService().GetChangeRuntime() {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_ENABLEMENT:
			if !action.GetNativePlan().GetSystemdService().GetChangeEnablement() {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PIN:
			if !action.GetNativePlan().GetNativePackage().GetChangePin() {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_VERSION:
			if action.GetIntent().GetDesired().GetNativePackage().GetExact() == nil {
				return false
			}
		}
	}
	return true
}

// Comparison deliberately excludes observation timestamps and unrelated package
// database revisions. It includes native object identity, not merely desired
// value equality: replacing an inode or invocation is drift, even with ABA data.
func ownershipDimensionsMatch(last, current *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) bool {
	if last == nil || current == nil || !resource.RefEqual(last.GetObservation().GetRef(), current.GetObservation().GetRef()) {
		return false
	}
	left, right := last.GetObservation(), current.GetObservation()
	for _, dimension := range dimensions {
		kind := left.GetRef().GetKind()
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE {
			if !managedFileDimensionMatches(last, current, dimension) {
				return false
			}
			continue
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER || kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP {
			if dimension != agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT {
				if !accountDimensionMatches(last, current, dimension) {
					return false
				}
				continue
			}
			if !accountIdentityMatches(last, current) {
				return false
			}
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL {
			if !sysctlOwnershipDimensionMatches(last, current, dimension) {
				return false
			}
			continue
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION {
			if !definitionOwnershipDimensionMatches(last, current, dimension) {
				return false
			}
			continue
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY {
			if !passwordOwnershipDimensionMatches(last, current, dimension) {
				return false
			}
			continue
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE {
			if !firewallOwnershipDimensionMatches(last, current, dimension) {
				return false
			}
			continue
		}
		switch dimension {
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_RUNTIME:
			a, b := left.GetSystemdService(), right.GetSystemdService()
			if a == nil || b == nil || a.GetUnit() != b.GetUnit() || a.GetBootId() != b.GetBootId() || !bytes.Equal(a.GetDefinitionSha256(), b.GetDefinitionSha256()) || a.GetActiveState() != b.GetActiveState() || a.GetSubState() != b.GetSubState() || !bytes.Equal(a.GetInvocationId(), b.GetInvocationId()) || a.GetJobPending() || b.GetJobPending() {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_ENABLEMENT:
			a, b := left.GetSystemdService(), right.GetSystemdService()
			if a == nil || b == nil || !a.GetInstallProjectionComplete() || !b.GetInstallProjectionComplete() || a.GetUnit() != b.GetUnit() || !bytes.Equal(a.GetDefinitionSha256(), b.GetDefinitionSha256()) || a.GetUnitFileState() != b.GetUnitFileState() || len(a.GetInstallLinks()) != len(b.GetInstallLinks()) {
				return false
			}
			for i, link := range a.GetInstallLinks() {
				if !proto.Equal(link, b.GetInstallLinks()[i]) {
					return false
				}
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PRESENCE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_VERSION:
			a, b := left.GetNativePackage(), right.GetNativePackage()
			if a == nil || b == nil || !proto.Equal(a.GetPackage(), b.GetPackage()) || a.GetInstalled() != b.GetInstalled() || !proto.Equal(a.GetRecord(), b.GetRecord()) {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PIN:
			a, b := left.GetNativePackage(), right.GetNativePackage()
			if a == nil || b == nil || !proto.Equal(a.GetPackage(), b.GetPackage()) || !proto.Equal(a.GetPinFile(), b.GetPinFile()) || !bytes.Equal(a.GetPinContents(), b.GetPinContents()) {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT:
			a, b := left.ProtoReflect(), right.ProtoReflect()
			field := a.WhichOneof(a.Descriptor().Oneofs().ByName("observed"))
			if field == nil || field != b.WhichOneof(b.Descriptor().Oneofs().ByName("observed")) || !proto.Equal(a.Get(field).Message().Interface(), b.Get(field).Message().Interface()) || !bytes.Equal(last.GetManagedFileContent(), current.GetManagedFileContent()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
