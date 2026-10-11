//go:build integration

package device

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func TestProfileCatalogPaginationPreservesRowsWithinJSONBudget(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, key := testCA(t, time.Now().Add(24*time.Hour))
	service, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: localIdentity(t, pool)})
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	if _, err := service.ListProfiles(ctx, connect.NewRequest(&adminv1.ListProfilesRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unauthenticated catalog read: %v", err)
	}
	if _, err := service.ListProfiles(identity.WithPrincipal(ctx, identity.Principal{ID: owner.ID}), connect.NewRequest(&adminv1.ListProfilesRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("ungranted catalog read: %v", err)
	}
	description := strings.Repeat("\x01", 4096)
	expected := make([]string, 52)
	for i := range expected {
		profileID := uuid.NewString()
		expected[i] = profileID
		request := &adminv1.PublishProfileRevisionRequest{
			RequestId: uuid.NewString(), ProfileId: profileID, Reason: "verify bounded catalog pagination",
			Spec: &policyv1.ResourceProfile{
				Name: fmt.Sprintf("Pagination profile %02d", i), Description: description,
				Resources: []*policyv1.ProfileResource{{
					ResourceId: uuid.NewString(),
					Desired: &resourcev1.ResourceDesiredState{
						Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "pagination.service"},
						State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{
							Unit: "pagination.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED,
						}},
					},
					Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
					Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
				}},
			},
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, publishErr := service.Profiles.Publish(ctx, tx, request, owner.ID)
		if publishErr != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(publishErr)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(expected)
	var got []string
	token := ""
	pages := 0
	for {
		response, err := service.ListProfiles(ownerCtx, connect.NewRequest(&adminv1.ListProfilesRequest{PageSize: 100, PageToken: token}))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := protojson.Marshal(response.Msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) > core.MaxMessageBytes {
			t.Fatalf("JSON page exceeds Connect bound: %d", len(encoded))
		}
		for _, profile := range response.Msg.GetProfiles() {
			if profile.GetDescription() != description || profile.GetRevisionNumber() != 1 || profile.GetResourceCount() != 1 {
				t.Fatal("bounded pagination changed profile metadata")
			}
			got = append(got, profile.GetProfileId())
		}
		pages++
		next := response.Msg.GetNextPageToken()
		if next == "" {
			break
		}
		if next == token || pages > len(expected) {
			t.Fatal("profile cursor failed to advance")
		}
		token = next
	}
	if pages < 2 || !slices.Equal(got, expected) {
		t.Fatalf("catalog boundary lost/reordered/duplicated profiles: pages=%d got=%v expected=%v", pages, got, expected)
	}
	if _, err := service.ListProfiles(ownerCtx, connect.NewRequest(&adminv1.ListProfilesRequest{PageToken: "invalid"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid catalog cursor: %v", err)
	}
}
