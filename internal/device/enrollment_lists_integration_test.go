//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"testing"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/identity"
)

func assertEnrollmentListHasNoCredential(t *testing.T, message proto.Message, secrets ...string) {
	t.Helper()
	wire, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	jsonWire, err := protojson.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		hash := core.HashGrant(secret)
		for _, forbidden := range [][]byte{[]byte(secret), hash, []byte(hex.EncodeToString(hash)), []byte(base64.StdEncoding.EncodeToString(hash))} {
			if bytes.Contains(wire, forbidden) || bytes.Contains(jsonWire, forbidden) {
				t.Fatal("enrollment metadata response leaked a credential or its hash")
			}
		}
	}
}

func TestEnrollmentGrantListLifecycleAndProjection(t *testing.T) {
	f := newProvisioningFixture(t)
	if _, err := f.conn.Exec(t.Context(), "UPDATE local_accounts SET username='enrollment-creator' WHERE id=$1", f.owner.ID); err != nil {
		t.Fatal(err)
	}
	created, err := f.service.CreateEnrollmentGrant(f.ownerCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{RequestId: uuid.NewString(), LifetimeSeconds: 600, Reason: "list lifecycle"}))
	if err != nil {
		t.Fatal(err)
	}
	assertGrant := func(status adminv1.EnrollmentGrantStatus, used uint32, creator, deviceID, hostname string, labels []string) {
		t.Helper()
		response, err := f.service.ListEnrollmentGrants(f.reviewerCtx, connect.NewRequest(&adminv1.ListEnrollmentGrantsRequest{PageSize: 1}))
		if err != nil {
			t.Fatal(err)
		}
		assertEnrollmentListHasNoCredential(t, response.Msg, created.Msg.GetSecret())
		if len(response.Msg.GetGrants()) != 1 || response.Msg.GetNextPageToken() != "" {
			t.Fatal("single grant list changed cardinality")
		}
		grant := response.Msg.GetGrants()[0]
		if grant.GetGrantId() != created.Msg.GetGrantId() || grant.GetStatus() != status || grant.GetMaxUses() != 1 || grant.GetUsedCount() != used || grant.GetCreatedBy() != f.owner.ID.String() || grant.GetCreatorDisplayName() != creator || grant.GetConsumedDeviceId() != deviceID || grant.GetConsumedDeviceHostname() != hostname || !slices.Equal(grant.GetLabels(), labels) {
			t.Fatalf("unexpected grant metadata: %v", grant)
		}
		if grant.GetCreatedAt() == nil || !grant.GetCreatedAt().AsTime().Before(grant.GetExpiresAt().AsTime()) || !grant.GetExpiresAt().AsTime().Equal(created.Msg.GetExpiresAt().AsTime()) {
			t.Fatal("grant lifetime projection changed")
		}
	}
	assertGrant(adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_ACTIVE, 0, "enrollment-creator", "", "", nil)
	enrolled, err := f.service.Enroll(t.Context(), connect.NewRequest(&enrollmentv1.EnrollRequest{GrantSecret: created.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: mustCSR(t, ed25519Key(t), &x509.CertificateRequest{})}))
	if err != nil {
		t.Fatal(err)
	}
	deviceID := enrolled.Msg.GetDeviceId()
	if _, err := f.conn.Exec(t.Context(), "UPDATE devices SET hostname='enrollment-host' WHERE id=$1", deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.Exec(t.Context(), "INSERT INTO device_labels(device_id,label) VALUES ($1,'workstation'),($1,'managed')", deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.Exec(t.Context(), "UPDATE principals SET display_name='Renamed Creator' WHERE id=$1", f.owner.ID); err != nil {
		t.Fatal(err)
	}
	assertGrant(adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_CONSUMED, 1, "Renamed Creator", deviceID, "enrollment-host", []string{"managed", "workstation"})
	if _, err := f.service.RevokeEnrollmentGrant(f.ownerCtx, connect.NewRequest(&adminv1.RevokeEnrollmentGrantRequest{RequestId: uuid.NewString(), GrantId: created.Msg.GetGrantId(), Reason: "retire consumed credential"})); err != nil {
		t.Fatal(err)
	}
	// Consumed is historical metadata, not a claim of current device authority.
	assertGrant(adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_CONSUMED, 1, "Renamed Creator", deviceID, "enrollment-host", []string{"managed", "workstation"})
}

func TestEnrollmentGrantListPaginationAndInactiveStates(t *testing.T) {
	f := newProvisioningFixture(t)
	want := make(map[string]adminv1.EnrollmentGrantStatus)
	var secrets []string
	for _, status := range []adminv1.EnrollmentGrantStatus{adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_ACTIVE, adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_EXPIRED, adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_REVOKED} {
		created, err := f.service.CreateEnrollmentGrant(f.ownerCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{RequestId: uuid.NewString(), LifetimeSeconds: 600, Reason: "paged grant history"}))
		if err != nil {
			t.Fatal(err)
		}
		id := created.Msg.GetGrantId()
		want[id] = status
		secrets = append(secrets, created.Msg.GetSecret())
		if status == adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_REVOKED {
			if _, err := f.service.RevokeEnrollmentGrant(f.ownerCtx, connect.NewRequest(&adminv1.RevokeEnrollmentGrantRequest{RequestId: uuid.NewString(), GrantId: id, Reason: "revoke before expiry"})); err != nil {
				t.Fatal(err)
			}
		}
		if status != adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_ACTIVE {
			// Move both ends of the persisted validity window, avoiding sleeps.
			if _, err := f.conn.Exec(t.Context(), "UPDATE enrollment_grants SET created_at=now()-interval '65 minutes', expires_at=now()-interval '1 hour' WHERE id=$1", id); err != nil {
				t.Fatal(err)
			}
		}
	}
	seen := make(map[string]bool)
	cursor := ""
	for page := range len(want) {
		response, err := f.service.ListEnrollmentGrants(f.ownerCtx, connect.NewRequest(&adminv1.ListEnrollmentGrantsRequest{PageSize: 1, PageToken: cursor}))
		if err != nil {
			t.Fatal(err)
		}
		assertEnrollmentListHasNoCredential(t, response.Msg, secrets...)
		if len(response.Msg.GetGrants()) != 1 {
			t.Fatal("page size did not bound grant projection")
		}
		grant := response.Msg.GetGrants()[0]
		if seen[grant.GetGrantId()] || want[grant.GetGrantId()] != grant.GetStatus() || grant.GetUsedCount() != 0 || grant.GetConsumedDeviceId() != "" || grant.GetConsumedDeviceHostname() != "" || len(grant.GetLabels()) != 0 {
			t.Fatalf("duplicate, unknown or incorrect grant metadata: %v", grant)
		}
		seen[grant.GetGrantId()] = true
		cursor = response.Msg.GetNextPageToken()
		if (cursor == "") != (page == len(want)-1) {
			t.Fatal("grant cursor ended early or continued past final page")
		}
	}
	if _, err := f.service.ListEnrollmentGrants(f.ownerCtx, connect.NewRequest(&adminv1.ListEnrollmentGrantsRequest{PageToken: "invalid-cursor"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid grant cursor: %v", err)
	}
}

func TestProvisioningTokenListCreatorProjection(t *testing.T) {
	f := newProvisioningFixture(t)
	if _, err := f.conn.Exec(t.Context(), "UPDATE local_accounts SET username='token-creator' WHERE id=$1", f.owner.ID); err != nil {
		t.Fatal(err)
	}
	first := f.mint(t, 2, false)
	second := f.mint(t, 1, true)
	assertTokens := func(name string, used uint32, revoked bool) {
		t.Helper()
		seen := make(map[string]bool)
		cursor := ""
		for page := range 2 {
			response, err := f.service.ListProvisioningTokens(f.reviewerCtx, connect.NewRequest(&adminv1.ListProvisioningTokensRequest{PageSize: 1, PageToken: cursor}))
			if err != nil {
				t.Fatal(err)
			}
			assertEnrollmentListHasNoCredential(t, response.Msg, first.GetSecret(), second.GetSecret())
			if len(response.Msg.GetTokens()) != 1 {
				t.Fatal("token creator join changed page cardinality")
			}
			token := response.Msg.GetTokens()[0]
			if seen[token.GetTokenId()] || (token.GetTokenId() != first.GetTokenId() && token.GetTokenId() != second.GetTokenId()) || token.GetCreatedBy() != f.owner.ID.String() || token.GetCreatorDisplayName() != name || token.GetCreatedAt() == nil || token.GetExpiresAt() == nil {
				t.Fatalf("incorrect token creator projection: %v", token)
			}
			if token.GetTokenId() == first.GetTokenId() && (token.GetMaxUses() != 2 || token.GetUsedCount() != used || (token.GetRevokedAt() != nil) != revoked) {
				t.Fatalf("token lifecycle metadata lost: %v", token)
			}
			seen[token.GetTokenId()] = true
			cursor = response.Msg.GetNextPageToken()
			if (cursor == "") != (page == 1) {
				t.Fatal("token pagination lost a row or continued past final page")
			}
		}
	}
	assertTokens("token-creator", 0, false)
	intent, _ := provisionIntent(t, first.GetSecret())
	if _, err := f.service.Provision(t.Context(), connect.NewRequest(intent)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.Exec(t.Context(), "UPDATE principals SET display_name='Current Token Creator' WHERE id=$1", f.owner.ID); err != nil {
		t.Fatal(err)
	}
	assertTokens("Current Token Creator", 1, false)
	if _, err := f.service.RevokeProvisioningToken(f.ownerCtx, connect.NewRequest(&adminv1.RevokeProvisioningTokenRequest{RequestId: uuid.NewString(), TokenId: first.GetTokenId(), Reason: "retire token"})); err != nil {
		t.Fatal(err)
	}
	assertTokens("Current Token Creator", 1, true)
}

func TestEnrollmentListsRequireFreshUnrestrictedAuthority(t *testing.T) {
	f := newProvisioningFixture(t)
	_, _, _, enrolled := enrollDevice(t, t.Context(), f.service, f.ownerCtx, ed25519Key(t))
	f.mint(t, 1, false)
	auditor := insertPrincipal(t, t.Context(), f.conn, identity.RoleAuditor)
	scoped := f.owner
	scoped.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionManageEnrollment)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{enrolled.Msg.GetDeviceId()}}}}}
	assertCode := func(ctx context.Context, code connect.Code) {
		t.Helper()
		if response, err := f.service.ListEnrollmentGrants(ctx, connect.NewRequest(&adminv1.ListEnrollmentGrantsRequest{})); connect.CodeOf(err) != code || response != nil {
			t.Fatalf("grant list authority boundary: response=%v error=%v", response, err)
		}
		if response, err := f.service.ListProvisioningTokens(ctx, connect.NewRequest(&adminv1.ListProvisioningTokensRequest{})); connect.CodeOf(err) != code || response != nil {
			t.Fatalf("token list authority boundary: response=%v error=%v", response, err)
		}
		if response, err := f.service.GetEnrollmentInstructions(ctx, connect.NewRequest(&adminv1.GetEnrollmentInstructionsRequest{})); connect.CodeOf(err) != code || response != nil {
			t.Fatalf("onboarding instructions authority boundary: response=%v error=%v", response, err)
		}
	}
	assertCode(t.Context(), connect.CodeUnauthenticated)
	assertCode(identity.WithPrincipal(t.Context(), auditor), connect.CodePermissionDenied)
	// Matching an enrolled device cannot widen global credential authority.
	assertCode(identity.WithPrincipal(t.Context(), scoped), connect.CodePermissionDenied)
	if _, err := f.conn.Exec(t.Context(), `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes',jsonb_build_array(jsonb_build_object('deviceIds',jsonb_build_array($2::text)))) WHERE id=$1`, f.owner.ID, enrolled.Msg.GetDeviceId()); err != nil {
		t.Fatal(err)
	}
	// The previously unrestricted context must not survive persisted narrowing.
	assertCode(f.ownerCtx, connect.CodePermissionDenied)
}

func TestEnrollmentInstructionsReturnsIsolatedPublicMetadata(t *testing.T) {
	f := newProvisioningFixture(t)
	f.service.EnrollmentInstructions = &adminv1.GetEnrollmentInstructionsResponse{
		EnrollmentOrigin:    "https://enroll.example.test",
		DeviceOrigin:        proto.String("https://devices.example.test"),
		ExecutionRootUrl:    proto.String("https://enroll.example.test/bootstrap/execution-root.json"),
		BootstrapBundleUrl:  proto.String("https://enroll.example.test/bootstrap/bootstrap.dsse.json"),
		ExecutionRootSha256: proto.String("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		Readiness:           &adminv1.EnrollmentReadiness{Reason: "native_repository_unavailable", Remedy: "Publish signed native packages on lindmd."},
	}
	response, err := f.service.GetEnrollmentInstructions(f.ownerCtx, connect.NewRequest(&adminv1.GetEnrollmentInstructionsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(response.Msg, f.service.EnrollmentInstructions) || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("instructions changed configured public metadata or allowed caching")
	}
	response.Msg.EnrollmentOrigin = "https://untrusted.example.test"
	response.Msg.Readiness.Remedy = "untrusted change"
	if f.service.EnrollmentInstructions.GetEnrollmentOrigin() != "https://enroll.example.test" {
		t.Fatal("response mutation changed deployment instructions")
	}
	if f.service.EnrollmentInstructions.GetReadiness().GetRemedy() != "Publish signed native packages on lindmd." {
		t.Fatal("response mutation changed deployment readiness")
	}
}
