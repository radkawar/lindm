package inventory

import (
	"context"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/resource"
)

// ApprovedReferenceKind identifies one kind stored in host_approved_references.
type ApprovedReferenceKind int16

// Kinds stored in host_approved_references; numbers match
// adminv1.ApprovedReferenceKind.
const (
	ApprovedHomeRoot      ApprovedReferenceKind = 1
	ApprovedPackageSource ApprovedReferenceKind = 2
)

type approvedReference struct {
	kind                       ApprovedReferenceKind
	id, name, format, location string
}

// recordApprovedReferences keeps host_approved_references equal to the
// approvals in the generation's latest accepted host observation. An
// observation without the executor's report clears them: an older report is
// never presented as the device's current configuration.
func recordApprovedReferences(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, observed *agentv1.ApprovedConfigurationObservation) error {
	if err := q.DeleteHostApprovedReferences(ctx, generation); err != nil {
		return err
	}
	for _, reference := range approvedReferences(observed) {
		if err := q.InsertHostApprovedReference(ctx, devicedb.InsertHostApprovedReferenceParams{
			GenerationID: generation, Kind: int16(reference.kind), ReferenceID: reference.id,
			Name: reference.name, Format: reference.format, Location: reference.location,
		}); err != nil {
			return err
		}
	}
	return nil
}

// approvedReferences names each approval the way a profile references it:
// home roots by root ID, package sources by their repository resource key.
// A source whose key cannot be derived is not offered rather than guessed.
func approvedReferences(observed *agentv1.ApprovedConfigurationObservation) []approvedReference {
	var out []approvedReference
	for _, root := range observed.GetHomeRoots() {
		out = append(out, approvedReference{kind: ApprovedHomeRoot, id: root.GetRootId(), name: root.GetPath()})
	}
	for _, repository := range observed.GetPackageSources() {
		ref, err := resource.CanonicalRef(&resourcev1.ResourceDesiredState{State: &resourcev1.ResourceDesiredState_Repository{Repository: repository}})
		if err != nil {
			continue
		}
		reference := approvedReference{kind: ApprovedPackageSource, id: ref.GetCanonicalKey()}
		switch source := repository.GetSource().(type) {
		case *resourcev1.RepositoryDesired_Apt:
			reference.format, reference.name, reference.location = "apt", source.Apt.GetSuite(), source.Apt.GetUri()
		case *resourcev1.RepositoryDesired_Rpm:
			reference.format, reference.name = "rpm", source.Rpm.GetNativeId()
			if urls := source.Rpm.GetBaseUrls().GetUrls(); len(urls) > 0 {
				reference.location = urls[0]
			} else {
				reference.location = source.Rpm.GetMetalink()
			}
		case *resourcev1.RepositoryDesired_Alpm:
			reference.format, reference.name, reference.location = "alpm", source.Alpm.GetNativeName(), source.Alpm.GetSnapshotUri()
		default:
			// Executors approve only APT, RPM and pacman sources.
			continue
		}
		out = append(out, reference)
	}
	return out
}
