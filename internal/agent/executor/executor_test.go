// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestBootstrapResumeDoesNotMintAnotherIdentity(t *testing.T) {
	now := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	fix := newFixture(t, now)
	svc := openExecutor(t, now)
	grant := "lg1_test-grant-secret-with-32-characters-minimum"
	first := prepare(t, svc, fix, grant, false)
	if bytes.Contains(mustProto(t, first), durable(t, svc).GetIdentityPrivateKey()[:ed25519.SeedSize]) {
		t.Fatal("bootstrap response exported a private key")
	}
	svc = reopen(t, svc, now.Add(3*time.Hour))
	resumed, err := svc.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{Resume: true}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.GetCsrPem(), resumed.Msg.GetCsrPem()) || resumed.Msg.GetPendingGrant() != grant || !resumed.Msg.GetResumed() {
		t.Fatal("resume did not return the stored attempt")
	}
	if _, err := svc.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{Resume: true, PendingGrant: "different-grant-value-with-32-characters"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("different grant replaced or was accepted: %v", err)
	}
	other := newFixture(t, now)
	if _, err := svc.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{ExecutionRootJson: other.root, BootstrapEnvelope: other.bundle, PendingGrant: grant})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("different trust was accepted: %v", err)
	}
}

func TestSessionAndRenewalAcksSurviveRestart(t *testing.T) {
	now := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	fix := newFixture(t, now)
	boot := uuid.NewString()
	svc := openExecutor(t, now, WithBootID(func() (string, error) { return boot, nil }), WithEntropy(zeros{}))
	grant := "lg1_test-grant-secret-with-32-characters-minimum"
	prepare(t, svc, fix, grant, false)
	device, generation := uuid.New(), uuid.New()
	cert := fix.leaf(t, publicOf(durable(t, svc).GetIdentityPrivateKey()), device, generation, now.Add(-11*24*time.Hour), now.Add(19*24*time.Hour))
	if _, err := svc.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: cert})); err != nil {
		t.Fatal(err)
	}
	if durable(t, svc).GetPendingGrant() != "" {
		t.Fatal("grant remained after certificate installation")
	}
	pending := session(t, svc)
	nextBoot := uuid.NewString()
	svc.setBoot(nextBoot)
	if !bytes.Equal(pending.GetPending().GetAuthorityProof(), session(t, svc).GetPending().GetAuthorityProof()) {
		t.Fatal("reboot replaced a pending acquisition")
	}
	if _, err := svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: pending.GetPending().GetRequestId(), ServerEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	svc = reopen(t, svc, now)
	svc.setBoot(nextBoot)
	if _, err := svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: uuid.NewString(), ServerEpoch: 1})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("wrong session UUID acknowledged the committed epoch: %v", err)
	}
	replayed, err := svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: pending.GetPending().GetRequestId(), ServerEpoch: 1}))
	if err != nil || !replayed.Msg.GetReplayed() {
		t.Fatalf("exact session ack was not durable: %v", err)
	}
	successor := session(t, svc)
	if successor.GetPending().GetBootId() != nextBoot || successor.GetPending().GetPredecessorEpoch() != 1 {
		t.Fatal("old-boot commit did not stage the current boot successor")
	}
	if _, err := svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: successor.GetPending().GetRequestId(), ServerEpoch: 2})); err != nil {
		t.Fatal(err)
	}
	renewed := renew(t, svc)
	before := durable(t, svc)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := svc.CommitRenewal(ctx, connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: renewed.GetIssuanceRequestId(), CertificatePem: cert})); connect.CodeOf(err) != connect.CodeCanceled && !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled renewal commit was not rejected: %v", err)
	}
	if !proto.Equal(before, durable(t, svc)) {
		t.Fatal("canceled renewal changed durable state")
	}
	nextCert := fix.leaf(t, publicOf(durable(t, svc).GetPendingRenewal().GetPrivateKey()), device, generation, now.Add(-time.Minute), now.Add(30*24*time.Hour))
	installed, err := svc.CommitRenewal(t.Context(), connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: renewed.GetIssuanceRequestId(), CertificatePem: nextCert}))
	if err != nil {
		t.Fatal(err)
	}
	svc = reopen(t, svc, now.Add(10*time.Minute))
	replay, err := svc.CommitRenewal(t.Context(), connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: renewed.GetIssuanceRequestId(), CertificatePem: nextCert}))
	if err != nil || !replay.Msg.GetReplayed() || !bytes.Equal(replay.Msg.GetCertificateSha256(), installed.Msg.GetCertificateSha256()) {
		t.Fatalf("renewal ack was not durable: %v", err)
	}
	if _, err := svc.CommitRenewal(t.Context(), connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: renewed.GetIssuanceRequestId(), CertificatePem: cert})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed renewal ack was accepted: %v", err)
	}
	message := append([]byte("                                                                TLS 1.3, client CertificateVerify\x00"), bytes.Repeat([]byte{1}, 32)...)
	hash := sha256.Sum256(parseCert(t, nextCert).Raw)
	signed, err := svc.SignTLSClientMessage(t.Context(), connect.NewRequest(&agentv1.SignTLSClientMessageRequest{CertificateSha256: hash[:], Message: message}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignTLSClientMessage(t.Context(), connect.NewRequest(&agentv1.SignTLSClientMessageRequest{CertificateSha256: hash[:], Message: bytes.Repeat([]byte{2}, 130)})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-CertificateVerify message was signed: %v", err)
	}
	want, err := trust.SignTLSClientMessage(ed25519.PrivateKey(durable(t, svc).GetIdentityPrivateKey()), message)
	if err != nil || !bytes.Equal(signed.Msg.GetSignature(), want) {
		t.Fatalf("TLS signature did not use the installed key: %v", err)
	}
	svc = reopen(t, svc, now.Add(30*time.Minute))
	priorHash := sha256.Sum256(parseCert(t, cert).Raw)
	if _, err := svc.SignTLSClientMessage(t.Context(), connect.NewRequest(&agentv1.SignTLSClientMessageRequest{CertificateSha256: priorHash[:], Message: message})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("prior key remained usable after the retain window: %v", err)
	}
}

func TestExpiredBootstrapDoesNotReplaceTrust(t *testing.T) {
	now := time.Date(2031, 1, 2, 3, 0, 0, 0, time.UTC)
	fix := newFixture(t, now)
	svc := openExecutor(t, now)
	prepare(t, svc, fix, "lg1_test-grant-secret-with-32-characters-minimum", false)
	svc = reopen(t, svc, now.Add(3*time.Hour))
	status, err := svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil || status.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_PENDING_ENROLLMENT {
		t.Fatalf("expired persisted bootstrap became a new trust or hold: %v", err)
	}
}

func openExecutor(t *testing.T, now time.Time, opts ...Option) *Service {
	t.Helper()
	opts = append([]Option{WithClock(func() time.Time { return now })}, opts...)
	svc, err := New(t.Context(), protectedDir(t), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func reopen(t *testing.T, svc *Service, now time.Time) *Service {
	t.Helper()
	dir, boot, entropy := svc.directory, svc.bootID, svc.entropy
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := New(t.Context(), dir, WithClock(func() time.Time { return now }), WithBootID(boot), WithEntropy(entropy))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	return next
}

func (s *Service) setBoot(id string) {
	s.bootID = func() (string, error) { return id, nil }
}

func prepare(t *testing.T, svc *Service, fix fixture, grant string, resume bool) *agentv1.PrepareBootstrapResponse {
	t.Helper()
	response, err := svc.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{ExecutionRootJson: fix.root, BootstrapEnvelope: fix.bundle, PendingGrant: grant, Resume: resume}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

func session(t *testing.T, svc *Service) *agentv1.PrepareSessionResponse {
	t.Helper()
	response, err := svc.PrepareSession(t.Context(), connect.NewRequest(&agentv1.PrepareSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

func renew(t *testing.T, svc *Service) *agentv1.PrepareRenewalResponse {
	t.Helper()
	response, err := svc.PrepareRenewal(t.Context(), connect.NewRequest(&agentv1.PrepareRenewalRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

func durable(t *testing.T, svc *Service) *agentv1.ExecutorJournalState {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	state, _, err := svc.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func publicOf(key []byte) ed25519.PublicKey {
	return ed25519.PublicKey(key[ed25519.SeedSize:])
}

func mustProto(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func parseCert(t *testing.T, encoded []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("missing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
