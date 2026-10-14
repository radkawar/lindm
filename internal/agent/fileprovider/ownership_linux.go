// SPDX-License-Identifier: Apache-2.0

//go:build linux

package fileprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
)

func acquisitionAllowed(owner *agentv1.ResourceOwnershipBinding, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) error {
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return ErrOutcomeUnknown
	}
	if ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		if !sameOwner(owner, ledger.GetOwner()) {
			return ErrConflict
		}
		if ledger.GetLastApplied() != nil {
			last, current := ledger.GetLastApplied().GetObservation().GetManagedFile(), before.GetObservation().GetManagedFile()
			if last.GetExists() != current.GetExists() || !bytes.Equal(last.GetNativeIdentitySha256(), current.GetNativeIdentitySha256()) || !bytes.Equal(last.GetAncestrySha256(), current.GetAncestrySha256()) || !bytes.Equal(last.GetSecurityMetadataSha256(), current.GetSecurityMetadataSha256()) {
				return ErrConflict
			}
		}
		return nil
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return ErrConflict
	}
	if before.GetObservation().GetManagedFile().GetExists() && (owner.GetPolicy().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION || owner.GetPolicy().GetAdoptionApprovalId() == "") {
		return admissiondetail.Wrap(fmt.Errorf("%w: unowned %s exists", ErrAdoptionRequired, before.GetObservation().GetManagedFile().GetPath()), "existing_file")
	}
	return nil
}
func sameOwner(a, b *agentv1.ResourceOwnershipBinding) bool {
	if a == nil || b == nil || len(a.GetSources()) == 0 || len(a.GetSources()) != len(b.GetSources()) {
		return false
	}
	for _, source := range a.GetSources() {
		count := 0
		for _, other := range b.GetSources() {
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
func fileDimensions(desired *resourcev1.ManagedFileDesired, before *agentv1.ResourceOwnershipSnapshot) []agentv1.ResourceOwnedDimension {
	if !before.GetObservation().GetManagedFile().GetExists() || desired.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return []agentv1.ResourceOwnedDimension{
			agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_PRESENCE,
			agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_CONTENT,
			agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_MODE,
			agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_UID,
			agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_GID,
		}
	}
	var dimensions []agentv1.ResourceOwnedDimension
	if desired.Content != nil {
		dimensions = append(dimensions, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_CONTENT)
	}
	if desired.Mode != nil {
		dimensions = append(dimensions, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_MODE)
	}
	if desired.Uid != nil {
		dimensions = append(dimensions, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_UID)
	}
	if desired.Gid != nil {
		dimensions = append(dimensions, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_GID)
	}
	return dimensions
}
func managedMatch(last, current *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) bool {
	if last == nil || current == nil {
		return false
	}
	a, b := last.GetObservation().GetManagedFile(), current.GetObservation().GetManagedFile()
	if a == nil || b == nil || a.GetExists() != b.GetExists() || a.GetPath() != b.GetPath() || !bytes.Equal(a.GetAncestrySha256(), b.GetAncestrySha256()) || len(a.GetNativeIdentitySha256()) != 32 || !bytes.Equal(a.GetNativeIdentitySha256(), b.GetNativeIdentitySha256()) || len(a.GetSecurityMetadataSha256()) != 32 || !bytes.Equal(a.GetSecurityMetadataSha256(), b.GetSecurityMetadataSha256()) {
		return false
	}
	for _, dimension := range dimensions {
		switch dimension {
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_PRESENCE:
			if !imageEqual(last, current) {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_CONTENT:
			if !bytes.Equal(a.GetFile().GetSha256(), b.GetFile().GetSha256()) {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_MODE:
			if a.GetFile().GetMode() != b.GetFile().GetMode() {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_UID:
			if a.GetFile().GetUid() != b.GetFile().GetUid() {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_GID:
			if a.GetFile().GetGid() != b.GetFile().GetGid() {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// targetImage is a private image, not an observation of an effect. Native inode
// identity is replaced with fresh kernel evidence only after the atomic commit.
func targetImage(desired *resourcev1.ManagedFileDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	target := proto.CloneOf(before)
	o := target.Observation.GetManagedFile()
	switch operation {
	case resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE:
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED || ledger.GetLastApplied() == nil || len(ledger.GetOwnedDimensions()) == 0 {
			return nil, ErrOutcomeUnknown
		}
		if !managedMatch(ledger.GetLastApplied(), before, ledger.GetOwnedDimensions()) {
			return nil, ErrConflict
		}
		if ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
			return target, nil
		}
		if ledger.GetOwner().GetPolicy().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED {
			return nil, ErrUnsupported
		}
		baseline := ledger.GetBaseline()
		if slices.Contains(ledger.GetOwnedDimensions(), agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_PRESENCE) {
			target.ManagedFileContent = bytes.Clone(baseline.GetManagedFileContent())
			target.ManagedFileXattrs = cloneXattrs(baseline.GetManagedFileXattrs())
			o.Exists = baseline.GetObservation().GetManagedFile().GetExists()
			o.File = proto.CloneOf(baseline.GetObservation().GetManagedFile().GetFile())
		} else {
			if !o.GetExists() || !baseline.GetObservation().GetManagedFile().GetExists() {
				return nil, ErrConflict
			}
			for _, dimension := range ledger.GetOwnedDimensions() {
				b := baseline.GetObservation().GetManagedFile().GetFile()
				switch dimension {
				case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_CONTENT:
					target.ManagedFileContent = bytes.Clone(baseline.GetManagedFileContent())
					o.File.Sha256 = bytes.Clone(b.GetSha256())
				case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_MODE:
					o.File.Mode = b.GetMode()
				case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_UID:
					o.File.Uid = b.GetUid()
				case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_GID:
					o.File.Gid = b.GetGid()
				default:
					return nil, ErrUnsupported
				}
			}
		}
	case resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE:
		if desired.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
			o.Exists = false
			o.File = nil
			target.ManagedFileContent = nil
			target.ManagedFileXattrs = nil
		} else {
			if !o.GetExists() {
				// Content must be explicit on creation. Mode and ownership default
				// to root:root 0600 rather than inheriting umask or directory GID.
				if desired.Content == nil {
					return nil, errors.New("fileprovider: new file requires explicit public content")
				}
				o.Exists = true
				o.File = &resourcev1.FileIdentity{Path: desired.GetPath(), Mode: 0600}
				target.ManagedFileContent = []byte{}
			}
			if desired.Content != nil {
				target.ManagedFileContent = bytes.Clone(desired.GetContent())
				digest := sha256.Sum256(target.ManagedFileContent)
				o.File.Sha256 = digest[:]
			}
			if desired.Mode != nil {
				o.File.Mode = desired.GetMode()
			}
			if desired.Uid != nil {
				o.File.Uid = desired.GetUid()
			}
			if desired.Gid != nil {
				o.File.Gid = desired.GetGid()
			}
		}
	default:
		return nil, ErrUnsupported
	}
	if o.GetExists() && o.GetFile().GetMode() & ^uint32(0777) != 0 {
		return nil, ErrUnsupported
	}
	o.SecurityMetadataSha256 = nativefile.XattrDigest(target.GetManagedFileXattrs())
	return target, nil
}
func cloneXattrs(attrs []*agentv1.NativeFileXattr) []*agentv1.NativeFileXattr {
	result := make([]*agentv1.NativeFileXattr, len(attrs))
	for i, a := range attrs {
		result[i] = proto.CloneOf(a)
	}
	return result
}
func imageEqual(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	x, y := a.GetObservation().GetManagedFile(), b.GetObservation().GetManagedFile()
	return x != nil && y != nil && x.GetPath() == y.GetPath() && x.GetExists() == y.GetExists() && x.GetFile().GetMode() == y.GetFile().GetMode() && x.GetFile().GetUid() == y.GetFile().GetUid() && x.GetFile().GetGid() == y.GetFile().GetGid() && bytes.Equal(a.GetManagedFileContent(), b.GetManagedFileContent()) && bytes.Equal(x.GetSecurityMetadataSha256(), y.GetSecurityMetadataSha256())
}
func inverseBinding(before, target *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger) (*resourcev1.OwnershipInverseBinding, error) {
	ld, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	last, err := messageDigest(ledger.GetLastApplied())
	if err != nil {
		return nil, err
	}
	native, err := messageDigest(before.GetObservation().GetManagedFile())
	if err != nil {
		return nil, err
	}
	// The private inverse binds target bytes and metadata, not the timestamp of
	// the fresh read that recomputes it during Apply.
	image := proto.CloneOf(target)
	image.Observation.Metadata = nil
	inverse, err := messageDigest(image)
	if err != nil {
		return nil, err
	}
	return &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ld[:], LastAppliedSha256: last, NativeIdentitySha256: native, InverseSha256: inverse}, nil
}
func messageDigest(message proto.Message) ([]byte, error) {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}
