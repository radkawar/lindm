//go:build integration

package device

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func TestProfileCatalogPaginationPreservesRowsWithinJSONBudget(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, key := testCA(t, time.Now().Add(24*time.Hour))
	service, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key})
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	if _, err := service.ListServiceProfiles(ctx, connect.NewRequest(&adminv1.ListServiceProfilesRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unauthenticated catalog read: %v", err)
	}
	if _, err := service.ListServiceProfiles(identity.WithPrincipal(ctx, identity.Principal{ID: owner.ID, Role: "auditor"}), connect.NewRequest(&adminv1.ListServiceProfilesRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("ungranted catalog read: %v", err)
	}
	description := strings.Repeat("\x01", 4096)
	expected := make([]string, 52)
	for i := range expected {
		profileID := uuid.NewString()
		expected[i] = profileID
		request := &adminv1.PublishServiceProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: profileID, Reason: "verify bounded catalog pagination", Spec: &policyv1.ServiceProfileSpec{Name: fmt.Sprintf("Pagination profile %02d", i), Description: description, Resources: []*policyv1.ServiceProfileResource{{ResourceId: uuid.NewString(), Desired: &agentv1.ServiceDesiredState{Unit: "pagination.service", Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}}}}}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, publishErr := service.profiles.Publish(ctx, tx, request, owner.ID)
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
		response, err := service.ListServiceProfiles(ownerCtx, connect.NewRequest(&adminv1.ListServiceProfilesRequest{PageSize: 100, PageToken: token}))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := protojson.Marshal(response.Msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) > maxMessageBytes {
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
	if _, err := service.ListServiceProfiles(ownerCtx, connect.NewRequest(&adminv1.ListServiceProfilesRequest{PageToken: "invalid"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid catalog cursor: %v", err)
	}
}
