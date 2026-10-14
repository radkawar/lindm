// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"crypto/x509"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/orgapply"
)

func TestNamedEnrollmentCredentials(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newProvisioningFixture(t)
	tokenRequest := &adminv1.CreateProvisioningTokenRequest{RequestId: uuid.NewString(), Name: "org/engineering", LifetimeSeconds: 3600, MaxUses: 5, Reason: "named declarative provisioning token"}
	token, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(tokenRequest))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(tokenRequest))
	if err != nil {
		t.Fatal(err)
	}
	if replay.Msg.GetTokenId() != token.Msg.GetTokenId() || replay.Msg.GetSecret() != "" || !replay.Msg.GetSecretDeliveryUnknown() {
		t.Fatal("named token replay reissued or recovered a secret")
	}
	changed := proto.CloneOf(tokenRequest)
	changed.Name = "org/finance"
	if _, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("token replay accepted name substitution: %v", err)
	}
	changed = proto.CloneOf(tokenRequest)
	changed.RequestId = uuid.NewString()
	if _, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("duplicate live token name: %v", err)
	}
	tokens, err := f.service.ListProvisioningTokens(f.ownerCtx, connect.NewRequest(&adminv1.ListProvisioningTokensRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens.Msg.GetTokens()) != 1 || tokens.Msg.GetTokens()[0].GetName() != tokenRequest.GetName() {
		t.Fatal("token name was not persisted and projected")
	}
	grantRequest := &adminv1.CreateEnrollmentGrantRequest{RequestId: uuid.NewString(), Name: "org/single", LifetimeSeconds: 600, Reason: "named declarative enrollment grant"}
	grant, err := f.service.CreateEnrollmentGrant(f.ownerCtx, connect.NewRequest(grantRequest))
	if err != nil {
		t.Fatal(err)
	}
	changedGrant := proto.CloneOf(grantRequest)
	changedGrant.Name = "org/changed"
	if _, err := f.service.CreateEnrollmentGrant(f.ownerCtx, connect.NewRequest(changedGrant)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("grant replay accepted name substitution: %v", err)
	}
	grants, err := f.service.ListEnrollmentGrants(f.ownerCtx, connect.NewRequest(&adminv1.ListEnrollmentGrantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants.Msg.GetGrants()) != 1 || grants.Msg.GetGrants()[0].GetName() != grantRequest.GetName() || grants.Msg.GetGrants()[0].GetGrantId() != grant.Msg.GetGrantId() {
		t.Fatal("grant name was not persisted and projected")
	}
	if _, err := f.service.RevokeProvisioningToken(f.ownerCtx, connect.NewRequest(&adminv1.RevokeProvisioningTokenRequest{RequestId: uuid.NewString(), TokenId: token.Msg.GetTokenId(), Reason: "explicit credential replacement"})); err != nil {
		t.Fatal(err)
	}
	changed.RequestId = uuid.NewString()
	if _, err := f.service.CreateProvisioningToken(f.ownerCtx, connect.NewRequest(changed)); err != nil {
		t.Fatalf("explicitly revoked token did not release name: %v", err)
	}
}

func TestOrganizationConsumedRevokedGrantReissuesOnce(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newProvisioningFixture(t)
	spec := &orgv1.Organization{Name: "grant-cycle", Grants: []*orgv1.EnrollmentGrant{{Name: "single", Request: &adminv1.CreateEnrollmentGrantRequest{LifetimeSeconds: 600}}}}
	plan, err := orgapply.Plan(f.ownerCtx, f.service, spec)
	if err != nil {
		t.Fatal(err)
	}
	first, err := orgapply.Apply(f.ownerCtx, f.service, plan, orgapply.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Secrets) != 1 {
		t.Fatal("missing original grant secret")
	}
	secret := first.Secrets[0]
	key := ed25519Key(t)
	if _, err := f.service.Enroll(t.Context(), connect.NewRequest(&enrollmentv1.EnrollRequest{GrantSecret: secret.Value, TransactionId: uuid.NewString(), CsrPem: mustCSR(t, key, &x509.CertificateRequest{})})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.RevokeEnrollmentGrant(f.ownerCtx, connect.NewRequest(&adminv1.RevokeEnrollmentGrantRequest{RequestId: uuid.NewString(), GrantId: secret.ID, Reason: "explicit consumed credential replacement"})); err != nil {
		t.Fatal(err)
	}
	list, err := f.service.ListEnrollmentGrants(f.ownerCtx, connect.NewRequest(&adminv1.ListEnrollmentGrantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetGrants()) != 1 || list.Msg.GetGrants()[0].GetRevokedAt() == nil || list.Msg.GetGrants()[0].GetStatus() != adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_CONSUMED {
		t.Fatal("revocation must remain visible independently of consumed status")
	}
	plan, err = orgapply.Plan(f.ownerCtx, f.service, spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := orgapply.Apply(f.ownerCtx, f.service, plan, orgapply.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Secrets) != 1 || second.Secrets[0].ID == secret.ID || second.Outcomes[0].Status != "created" {
		t.Fatal("revoked predecessor replayed its old issuance receipt")
	}
	plan, err = orgapply.Plan(f.ownerCtx, f.service, spec)
	if err != nil {
		t.Fatal(err)
	}
	third, err := orgapply.Apply(f.ownerCtx, f.service, plan, orgapply.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(third.Secrets) != 0 || third.Outcomes[0].Status != "unchanged" {
		t.Fatal("replacement was reissued on subsequent apply")
	}
}

func TestOrganizationDeletedGroupReceiptCannotClaimCreation(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newProvisioningFixture(t)
	group := &orgv1.StaticGroup{Id: uuid.NewString(), Name: "temporary"}
	spec := &orgv1.Organization{Name: "group-cycle", Groups: []*orgv1.StaticGroup{group}}
	plan, err := orgapply.Plan(f.ownerCtx, f.service, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orgapply.Apply(f.ownerCtx, f.service, plan, orgapply.Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.DeleteDeviceGroup(f.ownerCtx, connect.NewRequest(&adminv1.DeleteDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: group.GetId(), Reason: "delete managed group explicitly"})); err != nil {
		t.Fatal(err)
	}
	plan, err = orgapply.Plan(f.ownerCtx, f.service, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := orgapply.Apply(f.ownerCtx, f.service, plan, orgapply.Options{})
	if connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("deleted group receipt must surface conflict: %v", err)
	}
	if len(result.Outcomes) != 0 {
		t.Fatal("stale receipt falsely reported group created")
	}
	groups, err := f.service.ListDeviceGroups(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups.Msg.GetGroups()) != 0 {
		t.Fatal("stale replay recreated the deleted group")
	}
}
