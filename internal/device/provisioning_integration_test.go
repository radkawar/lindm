//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"lindm/internal/device/assistance"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

type provisioningFixture struct {
	service     *Service
	conn        *pgx.Conn
	owner       identity.Principal
	ownerCtx    context.Context
	reviewerCtx context.Context
}

func newProvisioningFixture(t *testing.T) *provisioningFixture {
	t.Helper()
	pool, conn := testdb.Open(t)
	ca, key := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, t.Context(), conn, identity.RoleOwner)
	reviewer := insertPrincipal(t, t.Context(), conn, identity.RoleOwner)
	return &provisioningFixture{service: svc, conn: conn, owner: owner, ownerCtx: identity.WithPrincipal(t.Context(), owner), reviewerCtx: identity.WithPrincipal(t.Context(), reviewer)}
}

func (f *provisioningFixture) mint(t *testing.T, maxUses uint32, approval bool) *adminv1.CreateProvisioningTokenResponse {
	t.Helper()
	response, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(&adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), LifetimeSeconds: 3600, MaxUses: maxUses, ApprovalRequired: approval, Reason: "isolated unattended enrollment"}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

func provisionIntent(t *testing.T, secret string) (*enrollmentv1.ProvisionRequest, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519Key(t)
	return &enrollmentv1.ProvisionRequest{ProvisioningToken: secret, TransactionId: uuid.NewString(), InstallationId: uuid.NewString(), CsrPem: mustCSR(t, key, &x509.CertificateRequest{})}, key
}

func provisioningProof(t *testing.T, svc *Service, request *enrollmentv1.ProvisionRequest, key ed25519.PrivateKey) *enrollmentv1.RetrieveProvisioningIssuanceRequest {
	t.Helper()
	digest := sha256.Sum256(request.GetCsrPem())
	proof, err := svc.Authority.Sign(t.Context(), &enrollmentv1.ProvisioningRetrieval{DeploymentId: svc.DeploymentID.String(), TransactionId: request.TransactionId, InstallationId: request.InstallationId, CsrSha256: digest[:]}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &enrollmentv1.RetrieveProvisioningIssuanceRequest{AuthorityProof: proof}
}

func TestProvisioningTokenHashOnlyAndMintIdempotency(t *testing.T) {
	f := newProvisioningFixture(t)
	request := &adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), LifetimeSeconds: 600, MaxUses: 2, Reason: "bounded token issuance"}
	first, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if first.Msg.Secret == "" || replay.Msg.Secret != "" || !replay.Msg.SecretDeliveryUnknown || first.Msg.TokenId != replay.Msg.TokenId {
		t.Fatal("mint replay recovered a credential or changed token")
	}
	var hash, assignment []byte
	if err := f.conn.QueryRow(t.Context(), "SELECT token_hash,assignment FROM provisioning_tokens WHERE id=$1", first.Msg.TokenId).Scan(&hash, &assignment); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash, core.HashGrant(first.Msg.Secret)) || bytes.Contains(assignment, []byte(first.Msg.Secret)) {
		t.Fatal("token persistence is not hash-only")
	}
	listed, err := f.service.ListProvisioningTokens(f.ownerCtx, connect.NewRequest(&adminv1.ListProvisioningTokensRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(listed.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(first.Msg.Secret)) {
		t.Fatal("list leaked token credential")
	}
	changed := proto.CloneOf(request)
	changed.MaxUses = 3
	if _, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed mint request: %v", err)
	}
}

func TestProvisioningConcurrentSameCSRAndMaximumUses(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same_transaction", false: "different_transactions"}[same], func(t *testing.T) {
			f := newProvisioningFixture(t)
			token := f.mint(t, 1, false)
			first, _ := provisionIntent(t, token.Secret)
			requests := make([]*enrollmentv1.ProvisionRequest, 8)
			for i := range requests {
				requests[i] = first
				if !same {
					requests[i], _ = provisionIntent(t, token.Secret)
				}
			}
			responses := make([]*connect.Response[enrollmentv1.ProvisionResponse], len(requests))
			failures := make([]error, len(requests))
			var workers sync.WaitGroup
			start := make(chan struct{})
			for i := range requests {
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-start
					responses[i], failures[i] = f.service.Provision(t.Context(), connect.NewRequest(requests[i]))
				}()
			}
			close(start)
			workers.Wait()
			successes := 0
			var deviceID string
			for i, err := range failures {
				if err != nil {
					if same || connect.CodeOf(err) != connect.CodeResourceExhausted || rpcReason(err) != "provisioning_token_exhausted" {
						t.Fatalf("race failure: %v", err)
					}
					continue
				}
				successes++
				if deviceID == "" {
					deviceID = responses[i].Msg.DeviceId
				} else if responses[i].Msg.DeviceId != deviceID {
					t.Fatal("same credential consumed twice")
				}
			}
			expected := 1
			if same {
				expected = len(requests)
			}
			if successes != expected {
				t.Fatalf("successes=%d want=%d", successes, expected)
			}
			var used, devices int
			if err := f.conn.QueryRow(t.Context(), "SELECT used_count,(SELECT count(*) FROM devices) FROM provisioning_tokens WHERE id=$1", token.TokenId).Scan(&used, &devices); err != nil {
				t.Fatal(err)
			}
			if used != 1 || devices != 1 {
				t.Fatalf("used=%d devices=%d", used, devices)
			}
		})
	}
}

func TestProvisioningInterruptedResumeAndWrongKey(t *testing.T) {
	f := newProvisioningFixture(t)
	token := f.mint(t, 1, false)
	request, key := provisionIntent(t, token.Secret)
	if _, err := f.service.RetrieveProvisioningIssuance(t.Context(), connect.NewRequest(provisioningProof(t, f.service, request, key))); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("pre-send crash recovery: %v", err)
	}
	issued, err := f.service.Provision(t.Context(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := f.service.RetrieveProvisioningIssuance(t.Context(), connect.NewRequest(provisioningProof(t, f.service, request, key)))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(issued.Msg, resumed.Msg.GetEnrollment()) {
		t.Fatal("lost-response resume changed identity")
	}
	if _, err := f.service.RetrieveProvisioningIssuance(t.Context(), connect.NewRequest(provisioningProof(t, f.service, request, ed25519Key(t)))); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong key: %v", err)
	}
	for _, change := range []func(*enrollmentv1.ProvisionRequest){func(r *enrollmentv1.ProvisionRequest) { r.InstallationId = uuid.NewString() }, func(r *enrollmentv1.ProvisionRequest) {
		r.CsrPem = mustCSR(t, ed25519Key(t), &x509.CertificateRequest{})
	}} {
		altered := proto.CloneOf(request)
		change(altered)
		if _, err := f.service.Provision(t.Context(), connect.NewRequest(altered)); connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Fatalf("changed transaction: %v", err)
		}
	}
	if _, err := f.conn.Exec(t.Context(), "UPDATE provisioning_tokens SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1", token.TokenId); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.RetrieveProvisioningIssuance(t.Context(), connect.NewRequest(provisioningProof(t, f.service, request, key))); err != nil {
		t.Fatalf("key-bound issued receipt must outlive boot token: %v", err)
	}
}

func TestProvisioningExpiryRevocationAndCreatorFences(t *testing.T) {
	for _, scenario := range []string{"expired", "revoked", "disabled", "version"} {
		t.Run(scenario, func(t *testing.T) {
			f := newProvisioningFixture(t)
			token := f.mint(t, 2, false)
			request, _ := provisionIntent(t, token.Secret)
			var err error
			switch scenario {
			case "expired":
				_, err = f.conn.Exec(t.Context(), "UPDATE provisioning_tokens SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1", token.TokenId)
			case "revoked":
				_, err = f.service.RevokeProvisioningToken(f.ownerCtx, connect.NewRequest(&adminv1.RevokeProvisioningTokenRequest{RequestId: uuid.NewString(), TokenId: token.TokenId, Reason: "stop unattended access"}))
			case "disabled":
				_, err = f.conn.Exec(t.Context(), "UPDATE local_accounts SET enabled=false WHERE id=$1", f.owner.ID)
			case "version":
				_, err = f.conn.Exec(t.Context(), "UPDATE principals SET authorization_version=authorization_version+1 WHERE id=$1", f.owner.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.Provision(t.Context(), connect.NewRequest(request)); err == nil {
				t.Fatal("invalid authority enrolled a device")
			}
			var used, devices int
			if err := f.conn.QueryRow(t.Context(), "SELECT used_count,(SELECT count(*) FROM devices) FROM provisioning_tokens WHERE id=$1", token.TokenId).Scan(&used, &devices); err != nil {
				t.Fatal(err)
			}
			if used != 0 || devices != 0 {
				t.Fatalf("denied authority consumed token: %d/%d", used, devices)
			}
		})
	}
}

func TestProvisioningPendingApprovalAndAssignments(t *testing.T) {
	f := newProvisioningFixture(t)
	group := uuid.New()
	if _, err := f.conn.Exec(t.Context(), "INSERT INTO device_groups(id,name) VALUES ($1,'provisioning')", group); err != nil {
		t.Fatal(err)
	}
	adopted := qualifiedServiceResource()
	adopted.ResourceId = uuid.NewString()
	adopted.Desired.Ref.CanonicalKey = "adopted.service"
	adopted.Desired.GetSystemdService().Unit = "adopted.service"
	adopted.Ownership.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	profile, err := f.service.PublishProfileRevision(f.ownerCtx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{
		RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "enrollment policy",
		Spec: &policyv1.ResourceProfile{Name: "enrollment", Resources: []*policyv1.ProfileResource{{
			ResourceId: uuid.NewString(),
			Desired: &resourcev1.ResourceDesiredState{
				Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "example.service"},
				State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{
					Unit: "example.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED,
				}},
			},
			Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
			Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
		}, adopted}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(&adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), LifetimeSeconds: 3600, MaxUses: 1, ApprovalRequired: true, Reason: "review provisioning", Metadata: &adminv1.DeviceMetadata{Labels: []string{"enrolled"}, Owner: &adminv1.DeviceMetadata_OwnerPrincipalId{OwnerPrincipalId: f.owner.ID.String()}}, GroupIds: []string{group.String()}, ProfileRevisionIds: []string{profile.Msg.Revision.RevisionId}}))
	if err != nil {
		t.Fatal(err)
	}
	request, key := provisionIntent(t, token.Msg.Secret)
	pending, err := f.service.Provision(t.Context(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if pending.Msg.State != "pending_approval" || len(pending.Msg.CertificatePem) != 0 {
		t.Fatal("pending enrollment received authority")
	}
	var certificates, heads int
	if err := f.conn.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM device_certificates),(SELECT count(*) FROM resource_assignment_heads)").Scan(&certificates, &heads); err != nil {
		t.Fatal(err)
	}
	if certificates != 0 || heads != 0 {
		t.Fatal("pending enrollment persisted usable authority")
	}
	inbox, err := f.service.ListApprovals(f.ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(inbox.Msg.Approvals) != 1 {
		t.Fatal("reservation absent from existing approvals inbox")
	}
	entry := inbox.Msg.Approvals[0]
	approve := proto.CloneOf(entry.GetApprovePendingEnrollment())
	approve.ApprovalId = entry.Id
	if _, err := f.service.ApprovePendingEnrollment(f.ownerCtx, connect.NewRequest(approve)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unapproved issuance: %v", err)
	}
	if _, err := f.service.ApproveApproval(f.ownerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: entry.Id, Reason: "self approval attempt"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := f.service.ApproveApproval(f.reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: entry.Id, Reason: "independent inventory approval"})); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := f.service.ApprovePendingEnrollment(f.ownerCtx, connect.NewRequest(approve)); err != nil {
			t.Fatal(err)
		}
	}
	ready, err := f.service.RetrieveProvisioningIssuance(t.Context(), connect.NewRequest(provisioningProof(t, f.service, request, key)))
	if err != nil {
		t.Fatal(err)
	}
	if ready.Msg.GetEnrollment().GetState() != "ready" || len(ready.Msg.GetEnrollment().GetCertificatePem()) == 0 || ready.Msg.GetEnrollment().GetDeviceId() != pending.Msg.DeviceId {
		t.Fatal("approval did not publish original key identity")
	}
	var used, labels, members, assignments int
	var owner uuid.UUID
	if err := f.conn.QueryRow(t.Context(), "SELECT t.used_count,d.owner_principal_id,(SELECT count(*) FROM device_labels),(SELECT count(*) FROM device_group_memberships),(SELECT count(*) FROM resource_assignments) FROM provisioning_tokens t,devices d WHERE t.id=$1 AND d.id=$2", token.Msg.TokenId, ready.Msg.GetEnrollment().GetDeviceId()).Scan(&used, &owner, &labels, &members, &assignments); err != nil {
		t.Fatal(err)
	}
	if used != 1 || owner != f.owner.ID || labels != 1 || members != 1 || assignments != 1 {
		t.Fatalf("assignment replay changed fixed reservation: %d %v %d %d %d", used, owner, labels, members, assignments)
	}
	var disposition int16
	var reason string
	if err := f.conn.QueryRow(t.Context(), "SELECT disposition, reason FROM resource_assignment_resources WHERE resource_id=$1", adopted.GetResourceId()).Scan(&disposition, &reason); err != nil {
		t.Fatal(err)
	}
	if disposition != int16(adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED) || reason != "adoption_approval_required" {
		t.Fatalf("enrollment approval incorrectly authorized resource adoption: %d %s", disposition, reason)
	}
}

func TestProvisioningPendingRejectionRevocationAndApprovalFences(t *testing.T) {
	for _, scenario := range []string{"rejected", "revoked", "expired", "requester_version", "approver_version"} {
		t.Run(scenario, func(t *testing.T) {
			f := newProvisioningFixture(t)
			token := f.mint(t, 1, true)
			request, key := provisionIntent(t, token.Secret)
			if _, err := f.service.Provision(t.Context(), connect.NewRequest(request)); err != nil {
				t.Fatal(err)
			}
			inbox, err := f.service.ListApprovals(f.ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			entry := inbox.Msg.Approvals[0]
			approve := proto.CloneOf(entry.GetApprovePendingEnrollment())
			approve.ApprovalId = entry.Id
			if scenario == "rejected" {
				_, err = f.service.RejectApproval(f.reviewerCtx, connect.NewRequest(&adminv1.RejectApprovalRequest{ApprovalId: entry.Id, Reason: "reject unknown installation"}))
			} else {
				_, err = f.service.ApproveApproval(f.reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: entry.Id, Reason: "review installation"}))
			}
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "revoked":
				_, err = f.service.RevokeProvisioningToken(f.ownerCtx, connect.NewRequest(&adminv1.RevokeProvisioningTokenRequest{RequestId: uuid.NewString(), TokenId: token.TokenId, Reason: "stop pending issuance"}))
			case "expired":
				_, err = f.conn.Exec(t.Context(), "UPDATE provisioning_enrollments SET expires_at=clock_timestamp()-interval '1 second' WHERE transaction_id=$1", request.TransactionId)
			case "requester_version":
				_, err = f.conn.Exec(t.Context(), "UPDATE principals SET authorization_version=authorization_version+1 WHERE id=$1", f.owner.ID)
			case "approver_version":
				reviewer, _ := identity.PrincipalFromContext(f.reviewerCtx)
				_, err = f.conn.Exec(t.Context(), "UPDATE principals SET authorization_version=authorization_version+1 WHERE id=$1", reviewer.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.ApprovePendingEnrollment(f.ownerCtx, connect.NewRequest(approve)); err == nil {
				t.Fatal("invalid approval issued a certificate")
			}
			response, err := f.service.RetrieveProvisioningIssuance(t.Context(), connect.NewRequest(provisioningProof(t, f.service, request, key)))
			if err == nil && len(response.Msg.GetEnrollment().GetCertificatePem()) != 0 {
				t.Fatal("retrieval bypassed approval")
			}
			var certificates int
			if err := f.conn.QueryRow(t.Context(), "SELECT count(*) FROM device_certificates").Scan(&certificates); err != nil {
				t.Fatal(err)
			}
			if certificates != 0 {
				t.Fatal("denied approval retained a certificate")
			}
		})
	}
}

// An approved reservation is not enrolled until the requester runs it; the
// pending list must say so instead of still asking for approval.
func TestPendingEnrollmentsReportApprovalProgress(t *testing.T) {
	f := newProvisioningFixture(t)
	token := f.mint(t, 1, true)
	request, _ := provisionIntent(t, token.Secret)
	if _, err := f.service.Provision(t.Context(), connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	states := func() []string {
		t.Helper()
		list, err := f.service.GetPendingEnrollments(f.ownerCtx, connect.NewRequest(&adminv1.GetPendingEnrollmentsRequest{PageSize: 10}))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, item := range list.Msg.GetEnrollments() {
			got = append(got, item.GetState())
		}
		return got
	}
	if got := states(); len(got) != 1 || got[0] != "pending_approval" {
		t.Fatalf("before approval: %v", got)
	}
	inbox, err := f.service.ListApprovals(f.ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	entry := inbox.Msg.Approvals[0]
	if _, err := f.service.ApproveApproval(f.reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: entry.Id, Reason: "independent installation review"})); err != nil {
		t.Fatal(err)
	}
	if got := states(); len(got) != 1 || got[0] != "approved" {
		t.Fatalf("after approval, before the requester runs it: %v", got)
	}
	approve := proto.CloneOf(entry.GetApprovePendingEnrollment())
	approve.ApprovalId = entry.Id
	if _, err := f.service.ApprovePendingEnrollment(f.ownerCtx, connect.NewRequest(approve)); err != nil {
		t.Fatal(err)
	}
	if got := states(); len(got) != 0 {
		t.Fatalf("after the requester ran the approval: %v", got)
	}
}

func TestProvisioningDoesNotBorrowScopeOrLabelPrivileges(t *testing.T) {
	f := newProvisioningFixture(t)
	helpdesk := insertPrincipal(t, t.Context(), f.conn, identity.RoleHelpdesk)
	request := &adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), LifetimeSeconds: 600, MaxUses: 1, Reason: "fixed scope test", Metadata: &adminv1.DeviceMetadata{Labels: []string{"privileged"}}}
	if _, err := f.service.CreateProvisioningToken(identity.WithPrincipal(t.Context(), helpdesk), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("enrollment-only label assignment: %v", err)
	}
	token := f.mint(t, 1, false)
	intent, _ := provisionIntent(t, token.Secret)
	if _, err := f.conn.Exec(t.Context(), `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes',jsonb_build_array(jsonb_build_object('deviceIds',jsonb_build_array($2::text)))) WHERE id=$1`, f.owner.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Provision(t.Context(), connect.NewRequest(intent)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("creator scope narrowed after mint: %v", err)
	}
}

func TestProvisioningApprovalRejectsScopedReviewer(t *testing.T) {
	f := newProvisioningFixture(t)
	token := f.mint(t, 1, true)
	request, _ := provisionIntent(t, token.Secret)
	response, err := f.service.Provision(t.Context(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := f.service.ListApprovals(f.ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	reviewer, _ := identity.PrincipalFromContext(f.reviewerCtx)
	// A reviewer scoped even to this device cannot widen global provisioning
	// authority. Fresh action and inbox scope checks remain independent.
	if _, err := f.conn.Exec(t.Context(), `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes',jsonb_build_array(jsonb_build_object('deviceIds',jsonb_build_array($2::text)))) WHERE id=$1`, reviewer.ID, response.Msg.DeviceId); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.ApproveApproval(f.reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: inbox.Msg.Approvals[0].Id, Reason: "scoped reviewer"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped reviewer widened enrollment authority: %v", err)
	}
}

func TestProvisioningRetryNeverReassignsOwnership(t *testing.T) {
	f := newProvisioningFixture(t)
	token, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(&adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), LifetimeSeconds: 600, MaxUses: 1, Reason: "initial owner", Metadata: &adminv1.DeviceMetadata{Owner: &adminv1.DeviceMetadata_OwnerPrincipalId{OwnerPrincipalId: f.owner.ID.String()}}}))
	if err != nil {
		t.Fatal(err)
	}
	request, _ := provisionIntent(t, token.Msg.Secret)
	issued, err := f.service.Provision(t.Context(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	reviewer, _ := identity.PrincipalFromContext(f.reviewerCtx)
	if _, err := f.service.SetDeviceMetadata(f.ownerCtx, connect.NewRequest(&adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: issued.Msg.DeviceId, Reason: "explicit reassignment", Metadata: &adminv1.DeviceMetadata{Owner: &adminv1.DeviceMetadata_OwnerPrincipalId{OwnerPrincipalId: reviewer.ID.String()}}})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Provision(t.Context(), connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	var owner uuid.UUID
	if err := f.conn.QueryRow(t.Context(), "SELECT owner_principal_id FROM devices WHERE id=$1", issued.Msg.DeviceId).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != reviewer.ID {
		t.Fatal("same-CSR retry reapplied initial owner")
	}
}

func TestProvisioningInstallationCannotConsumeAnotherToken(t *testing.T) {
	f := newProvisioningFixture(t)
	first := f.mint(t, 1, false)
	second := f.mint(t, 1, false)
	request, _ := provisionIntent(t, first.Secret)
	if _, err := f.service.Provision(t.Context(), connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	collision, _ := provisionIntent(t, second.Secret)
	collision.InstallationId = request.InstallationId
	if _, err := f.service.Provision(t.Context(), connect.NewRequest(collision)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("installation collision: %v", err)
	}
	var used, devices int
	if err := f.conn.QueryRow(t.Context(), "SELECT used_count,(SELECT count(*) FROM devices) FROM provisioning_tokens WHERE id=$1", second.TokenId).Scan(&used, &devices); err != nil {
		t.Fatal(err)
	}
	if used != 0 || devices != 1 {
		t.Fatal("conflicting installation consumed or reassigned an identity")
	}
}
