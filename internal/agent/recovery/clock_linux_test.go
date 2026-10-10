//go:build linux

package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/trust"
)

type recoveryTimeClient struct {
	*recoveryTestServer
	timeCall func(context.Context, *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error)
}

func (c *recoveryTimeClient) GetRecoveryTime(ctx context.Context, request *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
	return c.timeCall(ctx, request)
}

func TestRecoveryAuthenticatedTimeIgnoresRTCSkew(t *testing.T) {
	// The host RTC stays unchanged; the authenticated server and its complete
	// trust/credential fixture are decades before and after it. Run must perform
	// the whole bootstrap, proof, receipt, grant and effect path in either case.
	for _, year := range []int{2001, 2051} {
		t.Run(time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006"), func(t *testing.T) {
			r, server, provider := newRecoveryRunnerFixtureAt(t, time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC))
			if err := r.journal.Save(r.record); err != nil {
				t.Fatal(err)
			}
			clock := &Clock{monotonic: func() (time.Duration, error) { return 0, nil }}
			if err := Run(t.Context(), Options{Journal: r.journal, Key: r.key, Bootstrap: server.bootstrap, Client: server, Provider: provider, BootID: r.bootID, ImageSHA256: r.record.GetHandoff().GetRecoveryImageSha256(), Clock: clock}); err != nil {
				t.Fatal(err)
			}
			if provider.effects != 1 || server.reports != 1 {
				t.Fatalf("effects=%d reports=%d", provider.effects, server.reports)
			}
		})
	}
}

func TestRecoveryTimeIntervalCoversAsymmetricLatency(t *testing.T) {
	r, server, provider := newRecoveryRunnerFixture(t)
	base := server.now()
	elapsed := time.Duration(0)
	clock := &Clock{monotonic: func() (time.Duration, error) { return elapsed, nil }}
	client := &recoveryTimeClient{recoveryTestServer: server}
	client.timeCall = func(ctx context.Context, request *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
		server.r.clock.serverTime = base.Add(50 * time.Millisecond)
		response, err := server.GetRecoveryTime(ctx, request)
		elapsed = 100 * time.Millisecond
		server.r.clock.serverTime = base.Add(elapsed)
		return response, err
	}
	if err := r.journal.Save(r.record); err != nil {
		t.Fatal(err)
	}
	if err := Run(t.Context(), Options{Journal: r.journal, Key: r.key, Bootstrap: server.bootstrap, Client: client, Provider: provider, BootID: r.bootID, ImageSHA256: r.record.GetHandoff().GetRecoveryImageSha256(), Clock: clock}); err != nil {
		t.Fatal(err)
	}
	lower, upper, err := clock.Bounds()
	if err != nil || !lower.Equal(base.Add(50*time.Millisecond)) || !upper.Equal(base.Add(150*time.Millisecond)) {
		t.Fatalf("bounds %v %v: %v", lower, upper, err)
	}
	if provider.effects != 1 {
		t.Fatalf("effects=%d", provider.effects)
	}
	elapsed += time.Hour
	lower, upper, err = clock.Bounds()
	if err != nil || upper.Sub(lower) != 100*time.Millisecond || !lower.Equal(base.Add(time.Hour+50*time.Millisecond)) {
		t.Fatalf("elapsed bounds %v %v: %v", lower, upper, err)
	}
}

func TestRecoveryTimeBootstrapRejectsReplayWrongNonceKeyAndDelay(t *testing.T) {
	for _, name := range []string{"replay", "wrong_nonce", "wrong_key", "expiry", "monotonic_rollback"} {
		t.Run(name, func(t *testing.T) {
			r, server, _ := newRecoveryRunnerFixture(t)
			ticks := 0
			clock := &Clock{monotonic: func() (time.Duration, error) {
				ticks++
				if ticks == 1 {
					return time.Second, nil
				}
				if name == "expiry" {
					return 31 * time.Second, nil
				}
				if name == "monotonic_rollback" {
					return 0, nil
				}
				return time.Second, nil
			}}
			client := &recoveryTimeClient{recoveryTestServer: server}
			client.timeCall = func(ctx context.Context, req *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
				candidate := proto.CloneOf(req.Msg)
				if name == "wrong_nonce" || name == "replay" {
					candidate.Nonce = bytes.Repeat([]byte{99}, 32)
				}
				if name == "replay" {
					candidate.BootId = r.record.GetHandoff().GetOriginalBootId()
				}
				if name == "wrong_key" {
					_, key, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						return nil, err
					}
					original := server.start
					server.start = key
					defer func() { server.start = original }()
				}
				return server.GetRecoveryTime(ctx, connect.NewRequest(candidate))
			}
			if err := clock.bootstrap(t.Context(), r.verifier, client, r.record, r.delegation, r.bootID, server.now()); err == nil {
				t.Fatal("invalid bootstrap accepted")
			}
			if _, _, err := clock.Bounds(); err == nil {
				t.Fatal("failed bootstrap exposed time")
			}
			if err := clock.bootstrap(t.Context(), r.verifier, server, r.record, r.delegation, r.bootID, server.now()); err == nil {
				t.Fatal("failed bootstrap nonce reused")
			}
		})
	}
}

func TestRecoveryClockRejectsRollbackAndUsesUpperExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tick := 2 * time.Second
	clock := &Clock{ready: true, serverTime: now, sent: time.Second, received: 2 * time.Second, last: 2 * time.Second, monotonic: func() (time.Duration, error) { return tick, nil }}
	lower, upper, err := clock.Bounds()
	if err != nil || !lower.Equal(now) || !upper.Equal(now.Add(time.Second)) {
		t.Fatalf("bounds %v %v %v", lower, upper, err)
	}
	if err := unexpiredThrough(upper, now.Add(time.Second)); !errors.Is(err, ErrAuthorityExpired) {
		t.Fatalf("exact upper expiry admitted: %v", err)
	}
	if err := unexpiredThrough(upper, now.Add(time.Second+time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	tick--
	if _, _, err := clock.Bounds(); err == nil {
		t.Fatal("monotonic rollback admitted")
	}
	clock.monotonic = func() (time.Duration, error) { return 0, errors.New("clock unavailable") }
	if _, _, err := clock.Bounds(); err == nil {
		t.Fatal("clock failure fell back to RTC")
	}
}

func TestRecoveryTimeBootstrapBindsAllRequestFields(t *testing.T) {
	r, server, _ := newRecoveryRunnerFixture(t)
	clock := &Clock{monotonic: func() (time.Duration, error) { return 0, nil }}
	client := &recoveryTimeClient{recoveryTestServer: server}
	client.timeCall = func(ctx context.Context, req *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
		candidate := proto.CloneOf(req.Msg)
		candidate.MinimumRecoveryEpoch++
		return server.GetRecoveryTime(ctx, connect.NewRequest(candidate))
	}
	if err := clock.bootstrap(t.Context(), r.verifier, client, r.record, r.delegation, r.bootID, server.now()); err == nil {
		t.Fatal("signed different request accepted")
	}
}

func TestRecoveryStartUsesBothAuthenticatedBounds(t *testing.T) {
	r, server, provider := newRecoveryRunnerFixture(t)
	challenge, _, err := r.challenge(provider.plan)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := r.authorize(t.Context(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	intent := r.record.GetHandoff().GetIntent()
	grant, err := r.verifyStart(t.Context(), envelope, intent, challenge)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.sent = -30 * time.Second
	if _, err := r.verifyStart(t.Context(), envelope, intent, challenge); !errors.Is(err, ErrAuthorityExpired) {
		t.Fatalf("grant at upper expiry admitted: %v", err)
	}
	r.clock.sent = -2 * time.Second
	grant.NotBefore = timestamppb.New(server.now().Add(time.Second))
	envelope, err = r.authority.Sign(t.Context(), grant, server.start)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.verifyStart(t.Context(), envelope, intent, challenge); err == nil {
		t.Fatal("future grant admitted from upper rather than lower time")
	}
}

func TestRecoveryTimeRetainsNewDelegationBeforeAcquire(t *testing.T) {
	r, server, provider := newRecoveryRunnerFixture(t)
	current := proto.CloneOf(r.delegation)
	current.Version++
	current.MinimumRecoveryEpoch++
	delegation, err := r.authority.Sign(t.Context(), current, server.root)
	if err != nil {
		t.Fatal(err)
	}
	client := &recoveryTimeClient{recoveryTestServer: server}
	client.timeCall = func(ctx context.Context, request *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
		digest, err := trust.DeviceActionDigest(request.Msg)
		if err != nil {
			return nil, err
		}
		now := server.now()
		statement := &agentv1.RecoveryTimeStatement{DeploymentId: current.GetDeploymentId(), RequestSha256: digest[:], ServerTime: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), RootVersion: current.GetRootVersion(), DelegationVersion: current.GetVersion()}
		envelope, err := r.authority.Sign(ctx, statement, server.start)
		if err != nil {
			return nil, err
		}
		return connect.NewResponse(&recoveryv1.GetRecoveryTimeResponse{ServerTime: statement.ServerTime, TimeEnvelope: envelope, TrustUpdate: &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: delegation}}), nil
	}
	if err := r.journal.Save(r.record); err != nil {
		t.Fatal(err)
	}
	clock := &Clock{monotonic: func() (time.Duration, error) { return 0, nil }}
	err = Run(t.Context(), Options{Journal: r.journal, Key: r.key, Bootstrap: server.bootstrap, Client: client, Provider: provider, BootID: r.bootID, ImageSHA256: r.record.GetHandoff().GetRecoveryImageSha256(), Clock: clock})
	if err == nil || err.Error() != "recovery_time_trust_rollback" {
		t.Fatalf("old acquired delegation accepted: %v", err)
	}
	if server.acquisitions != 1 || server.authorizations != 0 || provider.effects != 0 {
		t.Fatalf("acquires=%d starts=%d effects=%d", server.acquisitions, server.authorizations, provider.effects)
	}
	consumed, err := r.journal.Consumed()
	if err != nil || consumed {
		t.Fatalf("consumed stale authority: %v %v", consumed, err)
	}
}

func TestRecoverySnapshotTrustCannotRegressSharedClock(t *testing.T) {
	r, server, _ := newRecoveryRunnerFixture(t)
	old := &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: r.record.GetDelegationEnvelope()}
	current := proto.CloneOf(r.delegation)
	current.Version++
	current.MinimumRecoveryEpoch++
	envelope, err := r.authority.Sign(t.Context(), current, server.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.verifyTrustUpdate(t.Context(), &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: envelope}); err != nil {
		t.Fatal(err)
	}
	// verifyTrustUpdate is the snapshot read path: it advances the boot-local
	// floor but intentionally leaves the exact NV-anchored journal unchanged.
	if r.delegation.GetVersion() != 1 {
		t.Fatal("snapshot changed retained journal delegation")
	}
	if _, _, err := r.verifyTrustUpdate(t.Context(), old); err == nil {
		t.Fatal("shared snapshot clock forgot newer authority")
	}
}

func TestRecoveryTimeRejectsHigherRootForkAcrossBootstrap(t *testing.T) {
	r, server, _ := newRecoveryRunnerFixture(t)
	newRoot := func(version uint64) (*agentv1.ExecutionRoot, ed25519.PrivateKey) {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		root := proto.CloneOf(r.record.GetAcceptedRoot())
		root.Version = version
		root.Keys = []*agentv1.ExecutionKey{{KeyId: id, PublicKey: public}}
		return root, key
	}
	sign := func(message proto.Message, key ed25519.PrivateKey) []byte {
		envelope, err := r.authority.Sign(t.Context(), message, key)
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	transition := func(root *agentv1.ExecutionRoot, previous, next ed25519.PrivateKey) *agentv1.ExecutionRootTransition {
		return &agentv1.ExecutionRootTransition{PreviousQuorumEnvelope: sign(root, previous), NextQuorumEnvelope: sign(root, next)}
	}
	rootA, keyA := newRoot(2)
	delegationA := proto.CloneOf(r.delegation)
	delegationA.Version, delegationA.RootVersion = 2, 2
	client := &recoveryTimeClient{recoveryTestServer: server}
	client.timeCall = func(ctx context.Context, request *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
		digest, err := trust.DeviceActionDigest(request.Msg)
		if err != nil {
			return nil, err
		}
		now := server.now()
		statement := &agentv1.RecoveryTimeStatement{DeploymentId: rootA.GetDeploymentId(), RequestSha256: digest[:], ServerTime: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), RootVersion: 2, DelegationVersion: 2}
		return connect.NewResponse(&recoveryv1.GetRecoveryTimeResponse{ServerTime: statement.ServerTime, TimeEnvelope: sign(statement, server.start), TrustUpdate: &agentv1.UpdateExecutionTrustRequest{RootTransitions: []*agentv1.ExecutionRootTransition{transition(rootA, server.root, keyA)}, DelegationEnvelope: sign(delegationA, keyA)}}), nil
	}
	clock := &Clock{monotonic: func() (time.Duration, error) { return 0, nil }}
	if err := clock.bootstrap(t.Context(), r.verifier, client, r.record, r.delegation, r.bootID, server.now()); err != nil {
		t.Fatal(err)
	}
	r.clock = clock
	rootB, keyB := newRoot(2)
	rootC, keyC := newRoot(3)
	delegationC := proto.CloneOf(r.delegation)
	delegationC.Version, delegationC.RootVersion = 3, 3
	update := &agentv1.UpdateExecutionTrustRequest{RootTransitions: []*agentv1.ExecutionRootTransition{transition(rootB, server.root, keyB), transition(rootC, keyB, keyC)}, DelegationEnvelope: sign(delegationC, keyC)}
	if _, _, err := r.verifyTrustUpdate(t.Context(), update); err == nil || err.Error() != "recovery_time_root_substitution" {
		t.Fatalf("fork bypassed authenticated root: %v", err)
	}
	// A valid extension through the exact authenticated root remains admissible.
	update.RootTransitions = []*agentv1.ExecutionRootTransition{transition(rootA, server.root, keyA), transition(rootC, keyA, keyC)}
	if _, _, err := r.verifyTrustUpdate(t.Context(), update); err != nil {
		t.Fatalf("exact root continuation rejected: %v", err)
	}
}
