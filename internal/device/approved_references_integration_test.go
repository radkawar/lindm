// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"context"
	"crypto/sha256"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/inventory"
	"lindm/internal/identity"
)

func listApproved(t *testing.T, f *enrolledFixture, ctx context.Context, req *adminv1.ListApprovedReferencesRequest) *adminv1.ListApprovedReferencesResponse {
	t.Helper()
	res, err := f.svc.ListApprovedReferences(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("ListApprovedReferences(%v): %v", req, err)
	}
	return res.Msg
}

func approvedNames(res *adminv1.ListApprovedReferencesResponse) []string {
	names := make([]string, len(res.GetReferences()))
	for i, item := range res.GetReferences() {
		names[i] = item.GetName()
	}
	return names
}

func TestApprovedReferencesFollowLatestObservationWithinScope(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	home, srv, data := uuid.NewString(), uuid.NewString(), uuid.NewString()
	repository := uuid.NewString()
	key := sha256.Sum256([]byte("approved signing key"))
	report := hostObservation(f.generation, 1, "approved-references")
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.ApprovedConfiguration = &agentv1.ApprovedConfigurationObservation{
		ObservedAt: timestamppb.New(f.now),
		HomeRoots: []*agentv1.NativeApprovedHomeRoot{
			{RootId: srv, Path: "/srv/homes"}, {RootId: home, Path: "/home"}, {RootId: data, Path: "/Data/home"},
		},
		PackageSources: []*resourcev1.RepositoryDesired{{
			RepositoryId: repository, Presence: resourcev1.Presence_PRESENCE_PRESENT,
			Source: &resourcev1.RepositoryDesired_Apt{Apt: &resourcev1.AptRepository{
				Uri: "https://packages.example.test/ubuntu", Suite: "noble", Components: []string{"main"}, Architectures: []string{"amd64"},
				SigningKey: &resourcev1.ArtifactRef{Sha256: key[:], SizeBytes: 20, ArtifactId: uuid.NewString()},
			}},
		}},
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	roots := adminv1.ApprovedReferenceKind_APPROVED_REFERENCE_KIND_HOME_ROOT
	page := listApproved(t, f, f.ownerCtx, &adminv1.ListApprovedReferencesRequest{Kind: roots, PageSize: 2})
	if got := approvedNames(page); !slices.Equal(got, []string{"/Data/home", "/home"}) || page.GetNextAfterName() != "/home" || page.GetNextAfterReferenceId() != home {
		t.Fatalf("first page %q next %q/%q", got, page.GetNextAfterName(), page.GetNextAfterReferenceId())
	}
	if ref := page.GetReferences()[1]; ref.GetReferenceId() != home || ref.GetDeviceCount() != 1 || ref.GetFormat() != "" {
		t.Fatalf("home root reference = %v", ref)
	}
	next := listApproved(t, f, f.ownerCtx, &adminv1.ListApprovedReferencesRequest{Kind: roots, PageSize: 2, AfterName: page.GetNextAfterName(), AfterReferenceId: page.GetNextAfterReferenceId()})
	if got := approvedNames(next); !slices.Equal(got, []string{"/srv/homes"}) || next.GetNextAfterName() != "" {
		t.Fatalf("second page %q next %q", got, next.GetNextAfterName())
	}
	if got := approvedNames(listApproved(t, f, f.ownerCtx, &adminv1.ListApprovedReferencesRequest{Kind: roots, Prefix: "/DATA"})); !slices.Equal(got, []string{"/Data/home"}) {
		t.Fatalf("case-insensitive prefix = %q", got)
	}
	sources := listApproved(t, f, f.ownerCtx, &adminv1.ListApprovedReferencesRequest{Kind: adminv1.ApprovedReferenceKind_APPROVED_REFERENCE_KIND_PACKAGE_SOURCE})
	if len(sources.GetReferences()) != 1 {
		t.Fatalf("package sources = %v", sources)
	}
	if source := sources.GetReferences()[0]; source.GetReferenceId() != "apt/"+repository || source.GetName() != "noble" ||
		source.GetFormat() != "apt" || source.GetLocation() != "https://packages.example.test/ubuntu" {
		t.Fatalf("package source = %v, want the repository resource key and APT suite", source)
	}
	if got := listApproved(t, f, fleetReader(t, f, identity.PermissionReadFleet, uuid.NewString()), &adminv1.ListApprovedReferencesRequest{Kind: roots}); len(got.GetReferences()) != 0 {
		t.Fatalf("out-of-scope reader saw %v", got)
	}
	if _, err := f.svc.ListApprovedReferences(f.ownerCtx, connect.NewRequest(&adminv1.ListApprovedReferencesRequest{Kind: roots, AfterName: "/home"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("half a cursor accepted: %v", err)
	}

	// An observation without the executor's report clears every reference.
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	report.Sequence = 2
	report.Observation.Details.ApprovedConfiguration = nil
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	if got := listApproved(t, f, f.ownerCtx, &adminv1.ListApprovedReferencesRequest{Kind: roots}); len(got.GetReferences()) != 0 {
		t.Fatalf("stale approvals listed as current: %v", got)
	}
}
