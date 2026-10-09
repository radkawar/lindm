package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthorizeDefaultDeny(t *testing.T) {
	perms := []Permission{PermissionReadFleet, PermissionManageEnrollment, PermissionRevokeDevice, PermissionReadAudit, PermissionManageExecutionTrust, PermissionManageProfiles}
	allow := []string{RoleOwner, RoleAdmin}
	deny := []string{"", "auditor", "operator", "helpdesk", "owner ", "Admin"}
	for _, role := range allow {
		for _, perm := range perms {
			if !Authorize(Principal{Role: role}, perm) {
				t.Fatalf("role %q permission %q denied", role, perm)
			}
		}
		if Authorize(Principal{Role: role}, Permission("fleet.write")) {
			t.Fatalf("role %q granted an unknown permission", role)
		}
	}
	for _, role := range deny {
		for _, perm := range perms {
			if Authorize(Principal{Role: role}, perm) {
				t.Fatalf("role %q permission %q granted", role, perm)
			}
		}
	}
}

func TestDecideOwnerDeniedOnDisableAndOutage(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	owner := freshOwner(now)
	if d := decideAccess(now, owner.Issuer, []string{"/admins"}, owner); d.Kind != accessOK || d.Role != RoleOwner {
		t.Fatalf("fresh owner = %#v", d)
	}
	disabled := owner
	disabled.Enabled = false
	disabled.Deactivated = true
	if d := decideAccess(now, owner.Issuer, nil, disabled); d.Kind != accessUnauthenticated || !d.RevokeSessions || d.Role != "" {
		t.Fatalf("disabled owner = %#v", d)
	}
	outage := owner
	outage.RefreshFailed = true
	if d := decideAccess(now, owner.Issuer, nil, outage); d.Kind != accessForbidden || d.RevokeSessions || d.Role != "" {
		t.Fatalf("owner outage = %#v", d)
	}
	stale := owner
	stale.ObservedAt = now.Add(-directoryFreshnessLimit - time.Nanosecond)
	if d := decideAccess(now, owner.Issuer, nil, stale); d.Kind != accessForbidden {
		t.Fatalf("stale owner = %#v", d)
	}
	boundary := owner
	boundary.ObservedAt = now.Add(-directoryFreshnessLimit)
	if d := decideAccess(now, owner.Issuer, nil, boundary); d.Kind != accessOK {
		t.Fatalf("owner at freshness limit = %#v", d)
	}
}

func TestDecideAdminGroupExactAndDefaultDeny(t *testing.T) {
	now := time.Now().UTC()
	snap := freshUser(now)
	snap.Groups = []string{"/operators", "/admins/extra"}
	if d := decideAccess(now, snap.Issuer, []string{"/admins"}, snap); d.Kind != accessOK || d.Role != "" {
		t.Fatalf("prefix group granted %#v", d)
	}
	snap.Groups = []string{"/admins"}
	if d := decideAccess(now, snap.Issuer, []string{"/admins"}, snap); d.Kind != accessOK || d.Role != RoleAdmin {
		t.Fatalf("exact admin group = %#v", d)
	}
	snap.Groups = nil
	if d := decideAccess(now, snap.Issuer, []string{"/admins"}, snap); d.Kind != accessOK || d.Role != "" {
		t.Fatalf("unassigned user = %#v", d)
	}
	if Authorize(Principal{Role: dRole(now, snap)}, PermissionReadAudit) {
		t.Fatal("unassigned role granted audit")
	}
	unqualified := snap
	unqualified.Qualified = false
	if d := decideAccess(now, snap.Issuer, []string{"/admins"}, unqualified); d.Kind != accessUnauthenticated || !d.RevokeSessions {
		t.Fatalf("unqualified admin group = %#v", d)
	}
	tombstone := snap
	tombstone.Groups = []string{"/admins"}
	tombstone.Enabled = true
	tombstone.Deactivated = true
	tombstone.DeactivationSource = deactivationSCIM
	if d := decideAccess(now, snap.Issuer, []string{"/admins"}, tombstone); d.Kind != accessUnauthenticated || d.Role != "" {
		t.Fatalf("scim tombstone = %#v", d)
	}
}

func TestCredentialSeparation(t *testing.T) {
	cookie, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	session := sessionHash(cookie)
	csrf := csrfToken(cookie)
	if csrf == "" || len(session) != 32 {
		t.Fatal("missing credential material")
	}
	if csrf == string(session) {
		t.Fatal("csrf token equals session hash bytes")
	}
	if !hashesDiffer(domainHash(csrfDomain, cookie), session) {
		t.Fatal("csrf hash equals session lookup hash")
	}
	if !csrfMatch(cookie, csrf) || csrfMatch(cookie, csrf+"x") || csrfMatch(cookie, "") {
		t.Fatal("csrf compare failed")
	}
	other, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	if !hashesDiffer(sessionHash(other), session) {
		t.Fatal("distinct cookies hashed equal")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	rec := httptest.NewRecorder()
	setHostCookie(rec, sessionCookie, "token", sessionCookieMaxAge)
	resp := rec.Result()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "__Host-lindm_session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie = %#v", c)
	}
}

func TestIDTokenAudienceAndNonce(t *testing.T) {
	now := time.Now()
	nonce, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	want := nonceHash(nonce)
	if !idTokenAccepted("client", []string{"client"}, "client", nonce, want, now, now) {
		t.Fatal("valid token rejected")
	}
	if idTokenAccepted("client", []string{"client", "account"}, "client", nonce, want, now, now) {
		t.Fatal("extra audience accepted")
	}
	if idTokenAccepted("client", []string{"client"}, "other", nonce, want, now, now) {
		t.Fatal("azp mismatch accepted")
	}
	if idTokenAccepted("client", []string{"client"}, "", "other-nonce", want, now, now) {
		t.Fatal("nonce mismatch accepted")
	}
}

func TestSessionResponseUsesProtobufJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	writeSession(rec, Principal{ID: id, Issuer: "https://idp.example/realms/lindm", Subject: id.String(), CSRFToken: "csrf"})
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "issuer", "subject", "displayName", "role", "csrfToken"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing %s in %s", key, rec.Body.String())
		}
	}
	if _, ok := got["display_name"]; ok || got["csrfToken"] != "csrf" || got["role"] != "" {
		t.Fatalf("session JSON = %s", rec.Body.String())
	}
}

func TestOriginAndIssuerRouting(t *testing.T) {
	origin, redirect, err := parsePublicURL("https://console.example:443/lindm")
	if err == nil || origin != "" || redirect != "" {
		t.Fatal("path public URL accepted")
	}
	origin, redirect, err = parsePublicURL("https://console.example:443/")
	if err != nil || origin != "https://console.example" || redirect != "https://console.example/auth/callback" {
		t.Fatalf("origin = %s redirect = %s err = %v", origin, redirect, err)
	}
	if originMatches(origin, "https://console.example:443") || originMatches(origin, "") || !originMatches(origin, origin) {
		t.Fatal("origin compare failed")
	}
	base, err := adminRealmBase("https://idp.example/realms/lindm")
	if err != nil || base != "https://idp.example/admin/realms/lindm" {
		t.Fatalf("admin base = %s err = %v", base, err)
	}
	base, err = adminRealmBase("https://idp.example/auth/realms/lindm")
	if err != nil || base != "https://idp.example/auth/admin/realms/lindm" {
		t.Fatalf("legacy admin base = %s err = %v", base, err)
	}
	if _, err := adminRealmBase("http://idp.example/realms/lindm"); err == nil {
		t.Fatal("http issuer accepted")
	}
	if _, err := adminRealmBase("https://idp.example/realms/lindm/"); err == nil {
		t.Fatal("trailing slash issuer accepted")
	}
}

func freshOwner(now time.Time) directorySnapshot {
	snap := freshUser(now)
	snap.PinnedRole = RoleOwner
	return snap
}

func freshUser(now time.Time) directorySnapshot {
	return directorySnapshot{
		PrincipalID: uuid.New(),
		Issuer:      "https://idp.example/realms/lindm",
		Subject:     "11111111-1111-1111-1111-111111111111",
		Enabled:     true,
		Observed:    true,
		ObservedAt:  now.Add(-5 * time.Second),
		Qualified:   true,
	}
}

func dRole(now time.Time, snap directorySnapshot) string {
	return decideAccess(now, snap.Issuer, []string{"/admins"}, snap).Role
}
