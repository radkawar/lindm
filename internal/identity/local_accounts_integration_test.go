// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
)

func authAccountRequest(t *testing.T, s *Service, method, path, cookie string, message proto.Message) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	var err error
	if message != nil {
		body, err = protojson.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, localTestOrigin+path, bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:3456"
	request.Header.Set("Origin", localTestOrigin)
	request.Header.Set(csrfHeader, csrfToken(cookie))
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	return response
}
func TestLocalAccountManagementHTTP(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	owner, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	ownerAuth := localAuthenticator(t)
	enrollLocal(t, s, ctx, owner, ownerAuth)
	ownerCookie := loginLocal(t, s, ctx, "owner", "", ownerAuth)
	response := authAccountRequest(t, s, http.MethodPost, "/auth/accounts/create", ownerCookie, &authv1.CreateAccountRequest{Username: "admin", Role: RoleAdmin})
	if response.Code != http.StatusOK {
		t.Fatalf("create status %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("enrollment response cacheable")
	}
	issued := &authv1.AccountEnrollment{}
	if err = protojson.Unmarshal(response.Body.Bytes(), issued); err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(issued.AccountId)
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err = pool.QueryRow(ctx, "SELECT secret_hash FROM local_enrollments WHERE account_id=$1", id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, domainHash("lindm.local.enrollment.v1", issued.Secret)) {
		t.Fatal("enrollment not hash-only")
	}
	adminAuth := localAuthenticator(t)
	enrollLocal(t, s, ctx, Enrollment{AccountID: id, Secret: issued.Secret}, adminAuth)
	adminCookie := loginLocal(t, s, ctx, "admin", "", adminAuth)
	response = authAccountRequest(t, s, http.MethodGet, "/auth/accounts", adminCookie, nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("admin gained accounts.manage: %d", response.Code)
	}
	response = authAccountRequest(t, s, http.MethodGet, "/auth/accounts", ownerCookie, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("list status %d", response.Code)
	}
	listed := &authv1.ListAccountsResponse{}
	if err = protojson.Unmarshal(response.Body.Bytes(), listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Accounts) != 2 {
		t.Fatal("account listing missing entries")
	}
	response = authAccountRequest(t, s, http.MethodPost, "/auth/accounts/update", ownerCookie, &authv1.UpdateAccountRequest{AccountId: id.String(), Enabled: true, Role: RoleAdmin, BreakGlass: true})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("non-owner breakglass designation accepted: %d", response.Code)
	}
	response = authAccountRequest(t, s, http.MethodPost, "/auth/accounts/update", ownerCookie, &authv1.UpdateAccountRequest{AccountId: id.String(), Enabled: false, Role: RoleAdmin})
	if response.Code != http.StatusNoContent {
		t.Fatalf("disable status %d", response.Code)
	}
	if _, decision, err := s.resolve(ctx, adminCookie); err != nil || decision.Kind != accessUnauthenticated {
		t.Fatalf("disabled session survived: %v %v", decision, err)
	}
	response = authAccountRequest(t, s, http.MethodPost, "/auth/accounts/update", ownerCookie, &authv1.UpdateAccountRequest{AccountId: id.String(), Enabled: true, Role: RoleOwner, BreakGlass: true})
	if response.Code != http.StatusNoContent {
		t.Fatalf("role/designation update status %d", response.Code)
	}
	response = authAccountRequest(t, s, http.MethodPost, "/auth/accounts/reset", ownerCookie, &authv1.ResetAccountRequest{AccountId: id.String()})
	if response.Code != http.StatusOK {
		t.Fatalf("reset status %d", response.Code)
	}
	reset := &authv1.AccountEnrollment{}
	if err = protojson.Unmarshal(response.Body.Bytes(), reset); err != nil {
		t.Fatal(err)
	}
	if reset.Secret == issued.Secret {
		t.Fatal("credential reset reused secret")
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM local_credentials WHERE account_id=$1", id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("reset retained authenticator")
	}
	replacement := localAuthenticator(t)
	enrollLocal(t, s, ctx, Enrollment{AccountID: id, Secret: reset.Secret}, replacement)
}
