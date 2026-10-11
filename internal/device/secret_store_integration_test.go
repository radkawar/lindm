//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/devlab/webauthnlab"
	"lindm/internal/escrow"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

const (
	secretTestOrigin   = "https://console.example.com:18444"
	secretTestPassword = "correct local password 123!"
)

type secretFixture struct {
	svc      *Service
	pool     *pgxpool.Pool
	stepUp   context.Context // real local password + WebAuthn browser session
	owner    identity.Principal
	ownerCtx context.Context // same principal without step-up proof
}

func newSecretFixture(t *testing.T) *secretFixture {
	t.Helper()
	pool, _ := testdb.Open(t)
	authority, err := identity.New(t.Context(), pool, identity.Config{Local: true, PublicURL: secretTestOrigin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	custody, err := escrow.New(rsaKey, kek)
	clear(kek)
	if err != nil {
		t.Fatal(err)
	}
	ca, caKey := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: authority, Escrow: custody})
	if err != nil {
		t.Fatal(err)
	}
	stepUp := localStepUp(t, authority)
	owner, _ := identity.PrincipalFromContext(stepUp)
	return &secretFixture{svc: svc, pool: pool, stepUp: stepUp, owner: owner, ownerCtx: identity.WithPrincipal(t.Context(), owner)}
}

// localStepUp performs the production local enrollment and login ceremonies and
// returns the context the session middleware hands to authenticated handlers.
func localStepUp(t *testing.T, authority *identity.Service) context.Context {
	t.Helper()
	enrollment, err := authority.BootstrapLocalOwner(t.Context(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := webauthnlab.New("console.example.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := authority.Handler()
	post := func(path string, request proto.Message, result proto.Message, status int) []*http.Cookie {
		t.Helper()
		body, err := protojson.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, secretTestOrigin+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", secretTestOrigin)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != status {
			t.Fatalf("%s: HTTP %d", path, recorder.Code)
		}
		if result != nil {
			if err := protojson.Unmarshal(recorder.Body.Bytes(), result); err != nil {
				t.Fatal(err)
			}
		}
		response := recorder.Result()
		defer func() { _ = response.Body.Close() }()
		return response.Cookies()
	}
	ceremony := func(kind string, request proto.Message, counter uint32, status int, result proto.Message) []*http.Cookie {
		t.Helper()
		challenge := new(authv1.WebAuthnChallenge)
		post("/auth/local/"+kind+"/begin", request, challenge, http.StatusOK)
		var options struct {
			Challenge string `json:"challenge"`
		}
		if err := json.Unmarshal([]byte(challenge.GetOptionsJson()), &options); err != nil || options.Challenge == "" {
			t.Fatalf("challenge: %v", err)
		}
		credential, _, err := authenticator.Response(options.Challenge, secretTestOrigin, kind == "enroll", true, counter)
		if err != nil {
			t.Fatal(err)
		}
		return post("/auth/local/"+kind+"/finish", &authv1.WebAuthnFinishRequest{Token: challenge.GetToken(), CredentialJson: string(credential)}, result, status)
	}
	ceremony("enroll", &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: secretTestPassword}, 0, http.StatusNoContent, nil)
	login := ceremony("login", &authv1.LocalLoginRequest{Username: "owner", Password: secretTestPassword}, 1, http.StatusOK, new(authv1.SessionPrincipal))
	var proof context.Context
	req := httptest.NewRequest(http.MethodGet, secretTestOrigin+"/auth/session", nil)
	for _, cookie := range login {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	authority.RequireSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { proof = r.Context() })).ServeHTTP(recorder, req)
	if proof == nil {
		t.Fatalf("session middleware rejected login: %d", recorder.Code)
	}
	return proof
}

func opaqueMaterial(value string) *agentv1.SecretMaterial {
	return &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_Opaque{Opaque: []byte(value)}}
}

func (f *secretFixture) create(t *testing.T, request *adminv1.CreateSecretRequest) *adminv1.SecretSummary {
	t.Helper()
	response, err := f.svc.CreateSecret(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetSecret()
}

func scopedSecretPrincipal(owner identity.Principal, permissions ...identity.Permission) identity.Principal {
	scoped := owner
	binding := &authv1.RoleBinding{Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}
	for _, permission := range permissions {
		binding.Permissions = append(binding.Permissions, string(permission))
	}
	scoped.Bindings = []*authv1.RoleBinding{binding}
	return scoped
}

func TestSecretStoreLifecycleAndIdempotency(t *testing.T) {
	f := newSecretFixture(t)
	first := "vpn-credential-version-one-7f3c"
	create := &adminv1.CreateSecretRequest{RequestId: uuid.NewString(), Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_VPN_AUTHENTICATION, DisplayName: "branch vpn", Material: opaqueMaterial(first), Reason: "provision vpn credential"}
	summary := f.create(t, create)
	if summary.GetCurrentVersion() != 1 || summary.GetPurpose() != create.GetPurpose() || summary.GetCreatedBy() != f.owner.ID.String() {
		t.Fatalf("created summary: %v", summary)
	}
	if _, err := uuid.Parse(summary.GetSubjectBindingId()); err != nil || summary.GetSubjectBindingId() == summary.GetSecretId() {
		t.Fatal("subject binding was not server generated")
	}
	// An exact retry returns the original secret; any changed payload is a reused ID.
	if replay := f.create(t, create); replay.GetSecretId() != summary.GetSecretId() || replay.GetSubjectBindingId() != summary.GetSubjectBindingId() {
		t.Fatalf("exact create retry minted another secret: %v", replay)
	}
	changed := proto.CloneOf(create)
	changed.Material = opaqueMaterial("vpn-credential-different-material")
	if _, err := f.svc.CreateSecret(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("request reuse with different material: %v", err)
	}
	mismatch := proto.CloneOf(create)
	mismatch.RequestId = uuid.NewString()
	mismatch.Purpose = resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH
	if _, err := f.svc.CreateSecret(f.ownerCtx, connect.NewRequest(mismatch)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("purpose/material mismatch: %v", err)
	}

	second := "vpn-credential-version-two-9a1d"
	rotate := &adminv1.RotateSecretRequest{RequestId: uuid.NewString(), SecretId: summary.GetSecretId(), ExpectedVersion: 1, Material: opaqueMaterial(second), Reason: "scheduled vpn rotation"}
	rotated, err := f.svc.RotateSecret(f.ownerCtx, connect.NewRequest(rotate))
	if err != nil || rotated.Msg.GetSecret().GetCurrentVersion() != 2 {
		t.Fatalf("rotate: %v", err)
	}
	if replay, err := f.svc.RotateSecret(f.ownerCtx, connect.NewRequest(rotate)); err != nil || replay.Msg.GetSecret().GetCurrentVersion() != 2 {
		t.Fatalf("exact rotate retry: %v", err)
	}
	reused := proto.CloneOf(rotate)
	reused.Material = opaqueMaterial("vpn-credential-other-material")
	if _, err := f.svc.RotateSecret(f.ownerCtx, connect.NewRequest(reused)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("rotate request reuse: %v", err)
	}
	stale := &adminv1.RotateSecretRequest{RequestId: uuid.NewString(), SecretId: summary.GetSecretId(), ExpectedVersion: 1, Material: opaqueMaterial("vpn-credential-stale"), Reason: "stale rotation"}
	if _, err := f.svc.RotateSecret(f.ownerCtx, connect.NewRequest(stale)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("version conflict: %v", err)
	}
	wrongArm := &adminv1.RotateSecretRequest{RequestId: uuid.NewString(), SecretId: summary.GetSecretId(), ExpectedVersion: 2, Material: &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_WifiPsk{WifiPsk: []byte("wifi-passphrase")}}, Reason: "wrong material"}
	if _, err := f.svc.RotateSecret(f.ownerCtx, connect.NewRequest(wrongArm)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("rotate purpose mismatch: %v", err)
	}
	missing := proto.CloneOf(stale)
	missing.RequestId, missing.SecretId = uuid.NewString(), uuid.NewString()
	if _, err := f.svc.RotateSecret(f.ownerCtx, connect.NewRequest(missing)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing secret rotate: %v", err)
	}

	other := f.create(t, &adminv1.CreateSecretRequest{RequestId: uuid.NewString(), Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK, DisplayName: "office wifi", Material: &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_WifiPsk{WifiPsk: []byte("office-wifi-passphrase")}}, Reason: "provision wifi"})
	page, err := f.svc.ListSecrets(f.ownerCtx, connect.NewRequest(&adminv1.ListSecretsRequest{PageSize: 1}))
	if err != nil || len(page.Msg.GetSecrets()) != 1 || page.Msg.GetSecrets()[0].GetSecretId() != summary.GetSecretId() || page.Msg.GetNextPageToken() == "" {
		t.Fatalf("first page: %v %v", page, err)
	}
	next, err := f.svc.ListSecrets(f.ownerCtx, connect.NewRequest(&adminv1.ListSecretsRequest{PageSize: 1, PageToken: page.Msg.GetNextPageToken()}))
	if err != nil || len(next.Msg.GetSecrets()) != 1 || next.Msg.GetSecrets()[0].GetSecretId() != other.GetSecretId() || next.Msg.GetNextPageToken() != "" {
		t.Fatalf("second page: %v %v", next, err)
	}
	if _, err := f.svc.ListSecrets(f.ownerCtx, connect.NewRequest(&adminv1.ListSecretsRequest{PageToken: "garbage"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad page token: %v", err)
	}
	detail, err := f.svc.GetSecret(f.ownerCtx, connect.NewRequest(&adminv1.GetSecretRequest{SecretId: summary.GetSecretId()}))
	if err != nil || len(detail.Msg.GetVersions()) != 2 || detail.Msg.GetVersions()[0].GetVersion() != 2 || detail.Msg.GetVersions()[1].GetReason() != create.GetReason() || detail.Msg.GetVersions()[0].GetCreatedByDisplayName() == "" {
		t.Fatalf("get secret: %v %v", detail, err)
	}
	if _, err := f.svc.GetSecret(f.ownerCtx, connect.NewRequest(&adminv1.GetSecretRequest{SecretId: uuid.NewString()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing secret get: %v", err)
	}

	// Scoped grants may read metadata, but never mutate deployment-global secrets.
	scoped := identity.WithPrincipal(t.Context(), scopedSecretPrincipal(f.owner, identity.PermissionManageSecrets, identity.PermissionRevealSecrets))
	if _, err := f.svc.ListSecrets(scoped, connect.NewRequest(&adminv1.ListSecretsRequest{})); err != nil {
		t.Fatalf("scoped list: %v", err)
	}
	scopedCreate := proto.CloneOf(create)
	scopedCreate.RequestId = uuid.NewString()
	if _, err := f.svc.CreateSecret(scoped, connect.NewRequest(scopedCreate)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped create: %v", err)
	}
	scopedRotate := proto.CloneOf(rotate)
	scopedRotate.RequestId, scopedRotate.ExpectedVersion = uuid.NewString(), 2
	if _, err := f.svc.RotateSecret(scoped, connect.NewRequest(scopedRotate)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped rotate: %v", err)
	}
	if _, err := f.svc.RevealSecret(scoped, connect.NewRequest(&adminv1.RevealSecretRequest{RequestId: uuid.NewString(), SecretId: summary.GetSecretId(), Version: 1, Reason: "scoped reveal attempt"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped reveal: %v", err)
	}

	// Reveal requires private step-up proof, then audits before release.
	if _, err := f.svc.RevealSecret(f.ownerCtx, connect.NewRequest(&adminv1.RevealSecretRequest{RequestId: uuid.NewString(), SecretId: summary.GetSecretId(), Version: 1, Reason: "attempt without step-up"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("reveal without step-up: %v", err)
	}
	for version, want := range map[uint64]string{1: first, 2: second} {
		revealed, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(&adminv1.RevealSecretRequest{RequestId: uuid.NewString(), SecretId: summary.GetSecretId(), Version: version, Reason: "incident verification"}))
		if err != nil {
			t.Fatal(err)
		}
		if string(revealed.Msg.GetMaterial().GetOpaque()) != want || revealed.Msg.GetPurpose() != create.GetPurpose() || revealed.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("revealed version %d mismatch", version)
		}
	}
	if _, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(&adminv1.RevealSecretRequest{RequestId: uuid.NewString(), SecretId: summary.GetSecretId(), Version: 3, Reason: "missing version"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing version reveal: %v", err)
	}
	var reveals int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action='secret.reveal' AND resource_id=$1 AND actor_id=$2 AND reason='incident verification'", summary.GetSecretId(), f.owner.ID).Scan(&reveals); err != nil || reveals != 2 {
		t.Fatalf("reveal audits=%d err=%v", reveals, err)
	}
	var created, rotations int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FILTER (WHERE action='secret.created'), count(*) FILTER (WHERE action='secret.rotated' AND reason=$2) FROM audit_events WHERE resource_id=$1", summary.GetSecretId(), rotate.GetReason()).Scan(&created, &rotations); err != nil || created != 1 || rotations != 1 {
		t.Fatalf("mutation audits created=%d rotated=%d err=%v", created, rotations, err)
	}

	// No plaintext anywhere in durable state or metadata responses.
	var stored [][]byte
	rows, err := f.pool.Query(t.Context(), "SELECT binding_document || wrapped_key || ciphertext || convert_to(key_id || reason, 'UTF8') FROM managed_secret_versions UNION ALL SELECT convert_to(action || resource_id || reason, 'UTF8') FROM audit_events UNION ALL SELECT convert_to(display_name, 'UTF8') FROM managed_secrets")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var value []byte
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, value)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	for _, message := range []proto.Message{page.Msg, next.Msg, detail.Msg, rotated.Msg} {
		encoded, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, encoded)
	}
	for _, value := range stored {
		for _, secret := range []string{first, second, "office-wifi-passphrase"} {
			if bytes.Contains(value, []byte(secret)) {
				t.Fatal("secret material escaped custody")
			}
		}
	}
}

func TestSecretRevealApprovalRequired(t *testing.T) {
	f := newSecretFixture(t)
	f.svc.revealApproval = true
	summary := f.create(t, &adminv1.CreateSecretRequest{RequestId: uuid.NewString(), Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_DIRECTORY_JOIN, DisplayName: "domain join", Material: opaqueMaterial("domain-join-credential"), Reason: "provision join account"})
	request := &adminv1.RevealSecretRequest{RequestId: uuid.NewString(), SecretId: summary.GetSecretId(), Version: 1, Reason: "two person reveal"}
	if _, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("reveal without approval: %v", err)
	}
	created, err := f.svc.CreateApproval(f.stepUp, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevealSecret{RevealSecret: request}}))
	if err != nil {
		t.Fatal(err)
	}
	approval := created.Msg.GetApproval()
	if approval.GetAction() != "secret.reveal" || approval.GetPermission() != string(identity.PermissionRevealSecrets) || approval.GetDeviceId() != "" {
		t.Fatalf("approval binding: %v", approval)
	}
	request.ApprovalId = approval.GetId()
	if _, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied && connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("reveal with pending approval: %v", err)
	}
	if _, err := f.svc.ApproveApproval(f.stepUp, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "self approval"})); err == nil {
		t.Fatal("requester approved own reveal")
	}
	reviewer := approvalReviewer(t, f.svc, t.Context())
	if _, err := f.svc.ApproveApproval(reviewer, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "independent reveal review"})); err != nil {
		t.Fatal(err)
	}
	revealed, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(request))
	if err != nil || string(revealed.Msg.GetMaterial().GetOpaque()) != "domain-join-credential" {
		t.Fatalf("approved reveal: %v", err)
	}
	var state string
	if err := f.pool.QueryRow(t.Context(), "SELECT state FROM approval_requests WHERE id=$1", approval.GetId()).Scan(&state); err != nil || state != "consumed" {
		t.Fatalf("approval state=%s err=%v", state, err)
	}
	changed := proto.CloneOf(request)
	changed.RequestId = uuid.NewString()
	if _, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(changed)); err == nil {
		t.Fatal("approval reused for a different reveal")
	}
}

func TestOpenManagedSecretBindingRefusals(t *testing.T) {
	f := newSecretFixture(t)
	hash := "$6$saltsalt$" + strings.Repeat("a", 86)
	summary := f.create(t, &adminv1.CreateSecretRequest{RequestId: uuid.NewString(), Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, DisplayName: "local user", Material: &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: []byte(hash)}}, Reason: "provision local user"})
	q := devicedb.New(f.pool)
	ref := &resourcev1.SecretRef{SecretId: summary.GetSecretId(), Version: 1, Purpose: summary.GetPurpose(), SubjectBindingId: summary.GetSubjectBindingId()}
	material, err := f.svc.openManagedSecret(t.Context(), q, ref)
	if err != nil || string(material.GetPasswordHash()) != hash {
		t.Fatalf("open exact reference: %v", err)
	}
	for name, test := range map[string]struct {
		mutate func(*resourcev1.SecretRef)
		want   error
	}{
		"purpose": {func(r *resourcev1.SecretRef) { r.Purpose = resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK }, errSecretBindingMismatch},
		"subject": {func(r *resourcev1.SecretRef) { r.SubjectBindingId = uuid.NewString() }, errSecretBindingMismatch},
		"version": {func(r *resourcev1.SecretRef) { r.Version = 2 }, errSecretUnavailable},
		"secret":  {func(r *resourcev1.SecretRef) { r.SecretId = uuid.NewString() }, errSecretUnavailable},
		"zero":    {func(r *resourcev1.SecretRef) { r.Version = 0 }, errSecretUnavailable},
		"malform": {func(r *resourcev1.SecretRef) { r.SecretId = "x" }, errSecretUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(ref)
			test.mutate(changed)
			if _, err := f.svc.openManagedSecret(t.Context(), q, changed); err != test.want {
				t.Fatalf("got %v want %v", err, test.want)
			}
		})
	}
	custody := f.svc.escrow
	f.svc.escrow = nil
	if _, err := f.svc.openManagedSecret(t.Context(), q, ref); err != errSecretUnavailable {
		t.Fatalf("unconfigured escrow: %v", err)
	}
	if _, err := f.svc.CreateSecret(f.ownerCtx, connect.NewRequest(&adminv1.CreateSecretRequest{RequestId: uuid.NewString(), Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_DIRECTORY_JOIN, DisplayName: "no custody", Material: opaqueMaterial("never stored"), Reason: "no custody"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("create without escrow: %v", err)
	}
	f.svc.escrow = custody
}

func TestSecretRevealApprovalConstraints(t *testing.T) {
	f := newSecretFixture(t)
	insert := func(action, permission string, device *uuid.UUID) error {
		_, err := f.pool.Exec(t.Context(), `INSERT INTO approval_requests (id, requester_id, requester_version, action, permission, device_id, mutation_id, payload, payload_sha256, created_at, expires_at)
			VALUES ($1, $2, 1, $3, $4, $5, $6, '\x01', decode(repeat('00', 32), 'hex'), clock_timestamp(), clock_timestamp() + interval '10 minutes')`, uuid.New(), f.owner.ID, action, permission, device, uuid.NewString())
		return err
	}
	device := uuid.New()
	for _, test := range []struct {
		action, permission string
		device             *uuid.UUID
		ok                 bool
	}{
		{"secret.reveal", "secrets.reveal", nil, true},
		{"secret.reveal", "secrets.reveal", &device, false},
		{"secret.reveal", "recovery_keys.read", nil, false},
		{"local_admin.reveal", "secrets.reveal", &device, true},
		{"local_admin.reveal", "secrets.reveal", nil, false},
		{"local_admin.reveal", "secrets.manage", &device, false},
	} {
		if err := insert(test.action, test.permission, test.device); (err == nil) != test.ok {
			t.Fatalf("%s/%s device=%v: %v", test.action, test.permission, test.device != nil, err)
		}
	}
}
