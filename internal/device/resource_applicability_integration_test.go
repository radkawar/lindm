//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/dispatch"
)

// applicabilityResource is the fixture's independent service limited to products.
func applicabilityResource(f *dispatchFixture, products ...*resourcev1.PlatformProduct) *policyv1.ProfileResource {
	item := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	item.DependsOn = nil
	item.Applicability = &resourcev1.Applicability{Products: products}
	return item
}

func applicabilityProduct(osID, version, architecture string) *resourcev1.PlatformProduct {
	return &resourcev1.PlatformProduct{OsId: osID, Product: osID, Version: version, Architecture: architecture}
}

// reportApplicabilityHost records the fixture host (Debian 12, amd64 in the
// Debian spelling) with optional changes.
func reportApplicabilityHost(t *testing.T, f *dispatchFixture, sequence uint64, change func(*inventoryv1.HostObservation)) {
	t.Helper()
	host := hostObservation(f.principal.GenerationID.String(), sequence, "applicability")
	if change != nil {
		change(host.Observation)
	}
	// A later report stands for a later routine inventory, not a burst.
	if _, err := f.pool.Exec(t.Context(), "UPDATE enrollment_generations SET last_host_admission_at=clock_timestamp()-interval '5 minutes' WHERE id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.ReportHostObservation(f.deviceCtx, connect.NewRequest(host)); err != nil {
		t.Fatal(err)
	}
}

func onlyResourceState(t *testing.T, f *dispatchFixture) *adminv1.ResourceState {
	t.Helper()
	state := complianceState(t, f)
	if len(state.GetResources()) != 1 {
		t.Fatalf("want one resource row, got %v", state.GetResources())
	}
	return state.GetResources()[0]
}

func assertDispatched(t *testing.T, f *dispatchFixture, item *policyv1.ProfileResource) {
	t.Helper()
	work := f.work(t)
	if work == nil || f.intent(t, work).GetDesired().GetRef().GetCanonicalKey() != item.GetDesired().GetRef().GetCanonicalKey() {
		t.Fatalf("applicable resource was not dispatched: %v", work)
	}
}

func TestResourceApplicabilityMatchesRecordedPlatform(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	reportApplicabilityHost(t, f, 1, nil)
	// Kernel spelling in the profile matches the Debian spelling in inventory;
	// a non-matching product beside it does not matter.
	item := applicabilityResource(f, applicabilityProduct("ubuntu", "24.04", "x86_64"), applicabilityProduct("debian", "12", "x86_64"))
	publishDispatchResources(t, f, item)
	f.assign(t, nil)
	if state := onlyResourceState(t, f); state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_PENDING || state.GetReason() != "" || len(state.GetApplicability().GetProducts()) != 2 {
		t.Fatalf("matching resource not pending with its applicability: %v", state)
	}
	assertDispatched(t, f, item)
}

func TestResourceApplicabilityOutsidePlatformIsNeverDispatchedOrCounted(t *testing.T) {
	parallelDeviceIntegration(t)
	cases := []struct {
		name    string
		product *resourcev1.PlatformProduct
		change  func(*inventoryv1.HostObservation)
	}{
		{"os mismatch", applicabilityProduct("ubuntu", "12", "x86_64"), nil},
		{"version mismatch", applicabilityProduct("debian", "13", "x86_64"), nil},
		{"architecture mismatch", applicabilityProduct("debian", "12", "aarch64"), nil},
		{"architecture mismatch in kernel spelling", applicabilityProduct("debian", "12", "x86_64"), func(o *inventoryv1.HostObservation) {
			o.Architecture.Value = "aarch64"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDispatchFixture(t)
			reportApplicabilityHost(t, f, 1, tc.change)
			item := applicabilityResource(f, tc.product)
			publishDispatchResources(t, f, item)
			f.assign(t, nil)
			assertNoResourceWork(t, f)
			state := onlyResourceState(t, f)
			if state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_NOT_APPLICABLE || state.GetReason() != dispatch.ResourceReasonPlatformNotApplicable || state.GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_NOT_APPLICABLE || state.GetLatestAction() != nil || !proto.Equal(state.GetApplicability(), item.GetApplicability()) {
				t.Fatalf("resource outside the device's platform not reported as not applicable: %v", state)
			}
			summary, err := f.service.GetFleetSummary(f.adminCtx, connect.NewRequest(&adminv1.GetFleetSummaryRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			if counts := summary.Msg.GetResourceCompliance(); counts.GetTotalResources() != 0 || counts.GetAttentionResources() != 0 || counts.GetUnknownResources() != 0 {
				t.Fatalf("not-applicable resource counted for compliance: %v", counts)
			}
			var actions int
			if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM resource_actions WHERE generation_id=$1", f.principal.GenerationID).Scan(&actions); err != nil || actions != 0 {
				t.Fatalf("not-applicable resource minted an action: count=%d err=%v", actions, err)
			}
		})
	}
}

func TestResourceApplicabilityWaitsForDeviceFacts(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	item := applicabilityResource(f, applicabilityProduct("debian", "12", "x86_64"))
	publishDispatchResources(t, f, item)
	f.assign(t, nil)
	assertNoResourceWork(t, f)
	state := onlyResourceState(t, f)
	if state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_WAITING_FOR_DEVICE_FACTS || state.GetReason() != dispatch.ResourceReasonDeviceFactsUnavailable || state.GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_UNKNOWN {
		t.Fatalf("platform-limited resource without inventory not waiting for facts: %v", state)
	}
	// An architecture the device could not collect is still not a decision.
	reportApplicabilityHost(t, f, 1, func(o *inventoryv1.HostObservation) {
		o.Architecture = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE}
	})
	assertNoResourceWork(t, f)
	if state := onlyResourceState(t, f); state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_WAITING_FOR_DEVICE_FACTS {
		t.Fatalf("failed architecture collection decided applicability: %v", state)
	}
	// The next work poll after the facts arrive decides and dispatches it.
	reportApplicabilityHost(t, f, 2, nil)
	assertDispatched(t, f, item)
}

func TestResourceApplicabilityFollowsPlatformChange(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	reportApplicabilityHost(t, f, 1, func(o *inventoryv1.HostObservation) { o.OsVersion.Value = "11" })
	item := applicabilityResource(f, applicabilityProduct("debian", "12", "x86_64"))
	publishDispatchResources(t, f, item)
	f.assign(t, nil)
	assertNoResourceWork(t, f)
	if state := onlyResourceState(t, f); state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_NOT_APPLICABLE {
		t.Fatalf("resource for a later release applied: %v", state)
	}
	// A release upgrade brings it into scope at the next poll.
	reportApplicabilityHost(t, f, 2, nil)
	assertDispatched(t, f, item)
}

func TestResourceFeaturesWithoutEvidenceAreRefused(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	reportApplicabilityHost(t, f, 1, nil)
	item := applicabilityResource(f, applicabilityProduct("debian", "12", "x86_64"))
	item.Applicability.Features = []resourcev1.ResourceFeature{resourcev1.ResourceFeature_RESOURCE_FEATURE_SAFE_RELEASE}
	publishDispatchResources(t, f, item)
	f.assign(t, nil)
	assertNoResourceWork(t, f)
	if state := onlyResourceState(t, f); state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED || state.GetReason() != dispatch.ResourceReasonFeatureEvidenceUnavailable {
		t.Fatalf("feature without device evidence was not refused: %v", state)
	}
}

// Arch has no VERSION_ID; the agent reports it unavailable. That is a fact for
// the registry's rolling row, not missing evidence, but an unavailable version
// on a versioned release still waits.
func TestResourceApplicabilityRollingReleaseWithoutVersion(t *testing.T) {
	parallelDeviceIntegration(t)
	noVersion := func(id string) func(*inventoryv1.HostObservation) {
		return func(o *inventoryv1.HostObservation) {
			o.OsId.Value = id
			o.OsVersion = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
		}
	}
	f := newDispatchFixture(t)
	reportApplicabilityHost(t, f, 1, noVersion("arch"))
	item := applicabilityResource(f, applicabilityProduct("arch", "", "x86_64"))
	publishDispatchResources(t, f, item)
	f.assign(t, nil)
	if state := onlyResourceState(t, f); state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_PENDING {
		t.Fatalf("Arch device without VERSION_ID did not match its rolling product: %v", state)
	}
	assertDispatched(t, f, item)

	f = newDispatchFixture(t)
	reportApplicabilityHost(t, f, 1, noVersion("debian"))
	publishDispatchResources(t, f, applicabilityResource(f, applicabilityProduct("debian", "12", "x86_64")))
	f.assign(t, nil)
	assertNoResourceWork(t, f)
	if state := onlyResourceState(t, f); state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_WAITING_FOR_DEVICE_FACTS {
		t.Fatalf("unavailable version on a versioned release decided applicability: %v", state)
	}
}
