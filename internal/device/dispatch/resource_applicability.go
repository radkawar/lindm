// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/platform"
)

// Assignment row dispositions decided by applicability; the values are the
// admin ResourceDisposition numbers stored in resource_assignment_resources.
const (
	dispositionPending         int16 = 1
	dispositionSucceeded       int16 = 3
	dispositionNotApplicable   int16 = 8
	dispositionWaitingForFacts int16 = 9
)

const (
	// ResourceReasonPlatformNotApplicable: the device's recorded platform is
	// outside every product the resource is limited to.
	ResourceReasonPlatformNotApplicable = "resource_platform_not_applicable"
	// ResourceReasonDeviceFactsUnavailable: the device has not yet reported the
	// OS, version and architecture that decide a platform-limited resource.
	ResourceReasonDeviceFactsUnavailable = "device_platform_facts_unavailable"
	// ResourceReasonFeatureEvidenceUnavailable: the resource requires features
	// for which no device reports evidence, so it is never sent.
	ResourceReasonFeatureEvidenceUnavailable = "resource_feature_evidence_unavailable"
)

// platformFacts are the device's own platform facts from its latest host
// observation: os-release ID and VERSION_ID and the uname machine.
type platformFacts struct {
	known                       bool
	osID, version, architecture string
}

// loadPlatformFacts reads the generation's latest host observation. Missing
// or failed collection of the OS ID, version or architecture is unknown, not
// a mismatch. An absent VERSION_ID is a fact only where the registry release
// has none (Arch's rolling model; the agent reports it unavailable), as in
// core's observed release.
func loadPlatformFacts(ctx context.Context, q *devicedb.Queries, generation uuid.UUID) (platformFacts, error) {
	row, err := q.GetResourcePlatformFacts(ctx, generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return platformFacts{}, nil
	}
	if err != nil {
		return platformFacts{}, err
	}
	success := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)
	if row.OsIDStatus != success || row.ArchitectureStatus != success {
		return platformFacts{}, nil
	}
	switch row.OsVersionStatus {
	case success:
	case int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE), int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE):
		release := platform.Identify(platform.OSRelease{ID: row.OsIDValue})
		if !release.Known() || release.Version.Rule != platform.VersionAbsent {
			return platformFacts{}, nil
		}
	default:
		return platformFacts{}, nil
	}
	return platformFacts{known: true, osID: row.OsIDValue, version: row.OsVersionValue, architecture: row.ArchitectureValue}, nil
}

// resourceApplicability decides a resource's platform limits against the
// device's facts through the platform registry: the same os-release ID, the
// same registry release for VERSION_ID, and the same machine architecture in
// either spelling. It returns zero when the resource applies or has no
// platform limits. Features are decided by ResourceDispatchUnsupported.
func resourceApplicability(item *policyv1.ProfileResource, facts platformFacts) (int16, string) {
	products := item.GetApplicability().GetProducts()
	if len(products) == 0 {
		return 0, ""
	}
	if !facts.known {
		return dispositionWaitingForFacts, ResourceReasonDeviceFactsUnavailable
	}
	for _, product := range products {
		if product.GetOsId() == facts.osID && platform.SameRelease(facts.osID, product.GetVersion(), facts.version) && platform.SameArchitecture(product.GetArchitecture(), facts.architecture) {
			return 0, ""
		}
	}
	return dispositionNotApplicable, ResourceReasonPlatformNotApplicable
}

// refreshApplicability re-decides platform-limited rows of the locked head
// against the device's current facts and returns the rows as stored. Facts
// arriving release waiting rows; a platform change (such as a release upgrade)
// moves rows in or out of scope. Refused, failed and in-flight rows keep their
// recorded outcome.
func refreshApplicability(ctx context.Context, q *devicedb.Queries, head devicedb.ResourceAssignment, rows []devicedb.ResourceAssignmentResource) error {
	var facts *platformFacts
	for i := range rows {
		row := &rows[i]
		switch row.Disposition {
		case dispositionPending, dispositionSucceeded, dispositionNotApplicable, dispositionWaitingForFacts:
		default:
			continue
		}
		item := new(policyv1.ProfileResource)
		if err := proto.Unmarshal(row.Document, item); err != nil {
			return core.ErrInternalState
		}
		if len(item.GetApplicability().GetProducts()) == 0 {
			continue
		}
		if facts == nil {
			loaded, err := loadPlatformFacts(ctx, q, head.GenerationID)
			if err != nil {
				return err
			}
			facts = &loaded
		}
		disposition, reason := resourceApplicability(item, *facts)
		switch {
		case disposition == 0 && (row.Disposition == dispositionNotApplicable || row.Disposition == dispositionWaitingForFacts):
			disposition = dispositionPending
		case disposition == dispositionNotApplicable && row.Disposition != dispositionNotApplicable:
		case disposition == dispositionWaitingForFacts && (row.Disposition == dispositionPending || row.Disposition == dispositionNotApplicable):
		default:
			continue
		}
		if err := q.SetAssignmentResourceDisposition(ctx, devicedb.SetAssignmentResourceDispositionParams{AssignmentID: head.ID, ResourceID: row.ResourceID, Disposition: disposition, Reason: reason}); err != nil {
			return err
		}
		row.Disposition, row.Reason = disposition, reason
	}
	return nil
}
