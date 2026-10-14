// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/gen/lindm/recovery/v1/recoveryv1connect"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/trust"
)

type recoveryTimeHandlerFixture struct {
	*deviceActionFixture
	snapshot *executionauthority.Snapshot
	verifier *trust.ExecutionVerifier
	request  *recoveryv1.GetRecoveryTimeRequest
	client   recoveryv1connect.RecoveryServiceClient
}

func newRecoveryTimeHandlerFixture(t *testing.T) *recoveryTimeHandlerFixture {
	t.Helper()
	f := &recoveryTimeHandlerFixture{deviceActionFixture: newDeviceActionFixtureCapabilities(t, []string{"device.sanitize.v1"})}
	tx, err := f.svc.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	f.snapshot, f.verifier, err = f.svc.Execution.CurrentInTransaction(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	rootDigest, err := trust.ExecutionRootDigest(f.snapshot.Root)
	if err != nil {
		t.Fatal(err)
	}
	delegationDigest := sha256.Sum256(f.snapshot.DelegationEnvelope)
	f.request = &recoveryv1.GetRecoveryTimeRequest{
		Nonce: bytes.Repeat([]byte{8}, 32), BootId: uuid.NewString(), RootVersion: f.snapshot.Root.GetVersion(), RootSha256: rootDigest[:],
		DelegationVersion: f.snapshot.Delegation.GetVersion(), DelegationSha256: delegationDigest[:], MinimumRecoveryEpoch: f.snapshot.Delegation.GetMinimumRecoveryEpoch(),
	}
	mux := http.NewServeMux()
	path, handler := f.svc.RecoveryHandler()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	f.client = recoveryv1connect.NewRecoveryServiceClient(server.Client(), server.URL)
	return f
}

// Compare actual persisted authority, not just counts: time delivery must not
// issue device credentials, acquire a session, consume an action or append audit.
func (f *recoveryTimeHandlerFixture) authorityState(t *testing.T) string {
	t.Helper()
	var state string
	if err := f.svc.Pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'principals', (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM principals p),
		'devices', (SELECT jsonb_agg(to_jsonb(d) ORDER BY id) FROM devices d),
		'generations', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM enrollment_generations g),
		'certificates', (SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM device_certificates c),
		'authority', (SELECT jsonb_agg(to_jsonb(a)) FROM execution_authority a),
		'roots', (SELECT jsonb_agg(to_jsonb(r) ORDER BY position) FROM execution_authority_roots r),
		'updates', (SELECT jsonb_agg(to_jsonb(u) ORDER BY request_digest) FROM execution_authority_updates u),
		'actions', (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM device_actions a),
		'recovery', (SELECT jsonb_agg(to_jsonb(r) ORDER BY action_id) FROM device_action_recovery r),
		'requests', (SELECT jsonb_agg(to_jsonb(r) ORDER BY credential_id, request_id) FROM device_action_recovery_requests r),
		'audit', (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM audit_events a)
	)::text`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestRecoveryTimePublicHandlerUsesDatabaseTimeWithoutAuthorityMutation(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newRecoveryTimeHandlerFixture(t)
	before := f.authorityState(t)
	// An unusable process wall clock cannot be the source of signed time.
	f.svc.Clock = func() time.Time { return time.Unix(0, 0) }
	lower, err := core.DispatchClock(t.Context(), devicedb.New(f.svc.Pool))
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.client.GetRecoveryTime(t.Context(), connect.NewRequest(f.request))
	if err != nil {
		t.Fatal(err)
	}
	upper, err := core.DispatchClock(t.Context(), devicedb.New(f.svc.Pool))
	if err != nil {
		t.Fatal(err)
	}
	statement, root, delegation, err := f.verifier.VerifyRecoveryTime(t.Context(), f.snapshot.Root, response.Msg, f.request, f.snapshot.AcceptedAt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if statement.GetServerTime().AsTime().Before(lower) || statement.GetServerTime().AsTime().After(upper) || statement.GetExpiresAt().AsTime().Sub(statement.GetServerTime().AsTime()) != 30*time.Second {
		t.Fatal("signed time did not use bounded database dispatch clock")
	}
	if !proto.Equal(root, f.snapshot.Root) || !proto.Equal(delegation, f.snapshot.Delegation) || !bytes.Equal(response.Msg.GetTrustUpdate().GetDelegationEnvelope(), f.snapshot.DelegationEnvelope) || len(response.Msg.GetTrustUpdate().GetRootTransitions()) != 0 {
		t.Fatal("unchanged public trust was omitted or substituted")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("public signed time is cacheable")
	}
	replay := proto.CloneOf(f.request)
	replay.Nonce[0] ^= 1
	if _, _, _, err := f.verifier.VerifyRecoveryTime(t.Context(), f.snapshot.Root, response.Msg, replay, f.snapshot.AcceptedAt, 0); err == nil {
		t.Fatal("time response replay authenticated a new request")
	}
	if _, err := f.svc.GetExecutionTrust(t.Context(), connect.NewRequest(&devicev1.GetExecutionTrustRequest{SessionEpoch: 1, RootVersion: f.request.RootVersion, RootSha256: f.request.RootSha256})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("public time conferred device principal: %v", err)
	}
	if _, err := f.client.AcquireRecoveryWork(t.Context(), connect.NewRequest(&recoveryv1.AcquireRecoveryWorkRequest{CredentialEnvelope: response.Msg.TimeEnvelope, RequestProof: response.Msg.TimeEnvelope})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("public time became an action credential: %v", err)
	}
	if after := f.authorityState(t); after != before {
		t.Fatal("public time delivery mutated device or action authority")
	}
}

func TestRecoveryTimeHandlerRejectsMalformedOrIncompatibleTrust(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newRecoveryTimeHandlerFixture(t)
	before := f.authorityState(t)
	for _, tc := range []struct {
		name   string
		change func(*recoveryv1.GetRecoveryTimeRequest)
		code   connect.Code
	}{
		{name: "short nonce", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.Nonce = r.Nonce[:31] }, code: connect.CodeInvalidArgument},
		{name: "long nonce", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.Nonce = append(r.Nonce, 0) }, code: connect.CodeInvalidArgument},
		{name: "nil boot", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.BootId = uuid.Nil.String() }, code: connect.CodeInvalidArgument},
		{name: "zero root", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.RootVersion = 0 }, code: connect.CodeInvalidArgument},
		{name: "zero delegation", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.DelegationVersion = 0 }, code: connect.CodeInvalidArgument},
		{name: "wrong root digest", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.RootSha256[0] ^= 1 }, code: connect.CodeFailedPrecondition},
		{name: "wrong delegation digest", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.DelegationSha256[0] ^= 1 }, code: connect.CodeFailedPrecondition},
		{name: "server behind root", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.RootVersion++ }, code: connect.CodeFailedPrecondition},
		{name: "server behind delegation", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.DelegationVersion++ }, code: connect.CodeFailedPrecondition},
		{name: "server behind epoch", change: func(r *recoveryv1.GetRecoveryTimeRequest) { r.MinimumRecoveryEpoch++ }, code: connect.CodeFailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := proto.CloneOf(f.request)
			tc.change(request)
			if _, err := f.client.GetRecoveryTime(t.Context(), connect.NewRequest(request)); connect.CodeOf(err) != tc.code {
				t.Fatalf("request error=%v, want %v", err, tc.code)
			}
		})
	}
	if f.authorityState(t) != before {
		t.Fatal("rejected public time requests mutated authority")
	}
}

func TestRecoveryTimeHandlerUsesCurrentSignerAndBoundedDelegationExpiry(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newRecoveryTimeHandlerFixture(t)
	delegation := proto.CloneOf(f.snapshot.Delegation)
	delegation.Version++
	now, err := core.DispatchClock(t.Context(), devicedb.New(f.svc.Pool))
	if err != nil {
		t.Fatal(err)
	}
	delegation.ExpiresAt = timestamppb.New(now.Add(20 * time.Second))
	envelope, err := f.svc.Authority.Sign(t.Context(), delegation, f.rootKeys...)
	if err != nil {
		t.Fatal(err)
	}
	actor, ok := identity.PrincipalFromContext(f.ownerCtx)
	if !ok {
		t.Fatal("missing fixture authority owner")
	}
	tx, err := f.svc.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := f.svc.Execution.Apply(t.Context(), tx, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: envelope}, actor.ID, "bound recovery time signer expiry"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := f.authorityState(t)
	response, err := f.client.GetRecoveryTime(t.Context(), connect.NewRequest(f.request))
	if err != nil {
		t.Fatal(err)
	}
	statement, _, accepted, err := f.verifier.VerifyRecoveryTime(t.Context(), f.snapshot.Root, response.Msg, f.request, f.snapshot.AcceptedAt, 0)
	if err != nil || !proto.Equal(accepted, delegation) || !statement.GetExpiresAt().AsTime().Equal(delegation.GetExpiresAt().AsTime()) {
		t.Fatalf("time did not bind current delegation expiry: %v", err)
	}
	// A configured key is not authority: self-verification must reject a signer
	// that is absent from the current START device.sanitize.v1 delegation.
	f.svc.Signing.StartKey = ed25519Key(t)
	if _, err := f.client.GetRecoveryTime(t.Context(), connect.NewRequest(f.request)); err == nil {
		t.Fatal("server returned a time statement from an undelegated signer")
	}
	if f.authorityState(t) != before {
		t.Fatal("time signing mutated authority")
	}
}

func TestRecoveryTimeHandlerDeliversRootTransitionWithCurrentTimeSignature(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newRecoveryTimeHandlerFixture(t)
	root := proto.CloneOf(f.snapshot.Root)
	root.Version++
	now, err := core.DispatchClock(t.Context(), devicedb.New(f.svc.Pool))
	if err != nil {
		t.Fatal(err)
	}
	root.ExpiresAt = timestamppb.New(now.Add(20 * time.Second))
	delegation := proto.CloneOf(f.snapshot.Delegation)
	delegation.RootVersion = root.GetVersion()
	delegation.Version++
	delegation.ExpiresAt = root.ExpiresAt
	rootEnvelope, err := f.svc.Authority.Sign(t.Context(), root, f.rootKeys...)
	if err != nil {
		t.Fatal(err)
	}
	delegationEnvelope, err := f.svc.Authority.Sign(t.Context(), delegation, f.rootKeys...)
	if err != nil {
		t.Fatal(err)
	}
	actor, ok := identity.PrincipalFromContext(f.ownerCtx)
	if !ok {
		t.Fatal("missing fixture authority owner")
	}
	tx, err := f.svc.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	update := &agentv1.UpdateExecutionTrustRequest{
		RootTransitions:    []*agentv1.ExecutionRootTransition{{PreviousQuorumEnvelope: rootEnvelope, NextQuorumEnvelope: rootEnvelope}},
		DelegationEnvelope: delegationEnvelope,
	}
	if _, err := f.svc.Execution.Apply(t.Context(), tx, update, actor.ID, "advance recovery time root"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := f.authorityState(t)
	response, err := f.client.GetRecoveryTime(t.Context(), connect.NewRequest(f.request))
	if err != nil {
		t.Fatal(err)
	}
	statement, acceptedRoot, acceptedDelegation, err := f.verifier.VerifyRecoveryTime(t.Context(), f.snapshot.Root, response.Msg, f.request, f.snapshot.AcceptedAt, 0)
	if err != nil || !proto.Equal(acceptedRoot, root) || !proto.Equal(acceptedDelegation, delegation) || !proto.Equal(response.Msg.GetTrustUpdate(), update) || !statement.GetExpiresAt().AsTime().Equal(root.GetExpiresAt().AsTime()) {
		t.Fatalf("current time did not authenticate from retained root: %v", err)
	}
	if f.authorityState(t) != before {
		t.Fatal("public root transition delivery mutated authority")
	}
}
