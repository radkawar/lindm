// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"lindm/internal/device/assistance"
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
	parallelDeviceIntegration(t)
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, key := testCA(t, time.Now().Add(24*time.Hour))
	service, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
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

// Owner pass 2: the profile picker finds a profile by name beyond the first page.
func TestProfileCatalogNameSearch(t *testing.T) {
	parallelDeviceIntegration(t)
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, key := testCA(t, time.Now().Add(24*time.Hour))
	service, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	publish := func(name string) string {
		profileID := uuid.NewString()
		request := &adminv1.PublishProfileRevisionRequest{
			RequestId: uuid.NewString(), ProfileId: profileID, Reason: "verify catalog name search",
			Spec: &policyv1.ResourceProfile{
				Name: name,
				Resources: []*policyv1.ProfileResource{{
					ResourceId: uuid.NewString(),
					Desired: &resourcev1.ResourceDesiredState{
						Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "search.service"},
						State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{
							Unit: "search.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED,
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
		if _, err := service.Profiles.Publish(ctx, tx, request, owner.ID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return profileID
	}
	list := func(search, token string, size uint32) (*adminv1.ListProfilesResponse, error) {
		response, err := service.ListProfiles(ownerCtx, connect.NewRequest(&adminv1.ListProfilesRequest{NameSearch: search, PageToken: token, PageSize: size}))
		if err != nil {
			return nil, err
		}
		return response.Msg, nil
	}
	names := func(response *adminv1.ListProfilesResponse) []string {
		var got []string
		for _, profile := range response.GetProfiles() {
			got = append(got, profile.GetName())
		}
		slices.Sort(got)
		return got
	}
	for i := range 5 {
		publish(fmt.Sprintf("Filler profile %d", i))
	}
	publish("Workstation baseline")
	publish("Lab WORKSTATION hardening")
	publish("100% coverage")
	publish("100x coverage")
	publish("under_score")
	publish("underXscore")

	// Case-insensitive substring.
	response, err := list("workstation", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(response); !slices.Equal(got, []string{"Lab WORKSTATION hardening", "Workstation baseline"}) || response.GetNextPageToken() != "" {
		t.Fatalf("case-insensitive substring search = %v next=%q", got, response.GetNextPageToken())
	}
	if response, err = list("ATION BASE", "", 0); err != nil || !slices.Equal(names(response), []string{"Workstation baseline"}) {
		t.Fatalf("mid-name substring search = %v err=%v", names(response), err)
	}
	// LIKE wildcard characters are literal.
	for search, want := range map[string]string{"0%": "100% coverage", "r_s": "under_score", "%": "100% coverage", "_": "under_score"} {
		if response, err = list(search, "", 0); err != nil || !slices.Equal(names(response), []string{want}) {
			t.Fatalf("literal search %q = %v err=%v", search, names(response), err)
		}
	}
	if response, err = list("no such profile", "", 0); err != nil || len(response.GetProfiles()) != 0 {
		t.Fatalf("unmatched search = %v err=%v", names(response), err)
	}
	// Pagination walks only the matches, and the token stays bound to its search.
	var got []string
	token := ""
	pages := 0
	for {
		response, err := list("PROFILE", token, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range response.GetProfiles() {
			got = append(got, profile.GetName())
		}
		pages++
		if response.GetNextPageToken() == "" {
			break
		}
		if pages == 1 {
			if _, err := list("coverage", response.GetNextPageToken(), 2); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("token reused with a different search: %v", err)
			}
			if _, err := list("", response.GetNextPageToken(), 2); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("search token reused without a search: %v", err)
			}
		}
		if pages > 5 {
			t.Fatal("search cursor failed to advance")
		}
		token = response.GetNextPageToken()
	}
	slices.Sort(got)
	if pages != 3 || !slices.Equal(got, []string{"Filler profile 0", "Filler profile 1", "Filler profile 2", "Filler profile 3", "Filler profile 4"}) {
		t.Fatalf("paged search pages=%d got=%v", pages, got)
	}
	unsearched, err := list("", "", 2)
	if err != nil || unsearched.GetNextPageToken() == "" {
		t.Fatalf("unsearched first page: %v", err)
	}
	if _, err := list("profile", unsearched.GetNextPageToken(), 2); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unsearched token reused with a search: %v", err)
	}
	if _, err := list(strings.Repeat("x", 201), "", 0); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("oversized search: %v", err)
	}
}
