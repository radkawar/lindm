//go:build linux

package executor

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
)

func TestStartupKeepsExclusiveDirectoryLock(t *testing.T) {
	for _, provisioned := range []bool{false, true} {
		name := "fresh"
		if provisioned {
			name = "provisioned"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2031, 7, 1, 0, 0, 0, 0, time.UTC)
			fix := newFixture(t, now)
			directory := protectedDir(t)
			const grant = "lg1_test-grant-secret-with-32-characters-minimum"
			if provisioned {
				key, csr, err := newSoftwareKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				store, err := journal.Initialize(t.Context(), directory, &agentv1.ExecutorJournalState{
					FormatVersion: 1, InstallationId: uuid.NewString(),
					ExecutionRootJson: fix.root, BootstrapEnvelope: fix.bundle,
					BootstrapVerifiedAt: protoTimestamp(now), EnrollmentTransactionId: uuid.NewString(),
					IdentityPrivateKey: key, EnrollmentCsrPem: csr, PendingGrant: grant,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			svc, err := New(t.Context(), directory, WithClock(func() time.Time { return now }))
			if err != nil {
				t.Fatalf("start %s executor: %v", name, err)
			}
			t.Cleanup(func() { _ = svc.Close() })
			assertExclusive := func() {
				t.Helper()
				other, err := New(t.Context(), directory)
				if other != nil {
					_ = other.Close()
				}
				if !errors.Is(err, ErrBusy) {
					t.Fatalf("second executor acquired the directory: %v", err)
				}
				store, err := journal.Open(t.Context(), directory)
				if store != nil {
					_ = store.Close()
				}
				if !errors.Is(err, journal.ErrAlreadyOpen) {
					t.Fatalf("independent journal acquired the executor directory: %v", err)
				}
			}
			assertExclusive()
			status, err := svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			want := agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED
			if provisioned {
				want = agentv1.Lifecycle_LIFECYCLE_PENDING_ENROLLMENT
			}
			if status.Msg.GetLifecycle() != want {
				t.Fatalf("startup lifecycle = %v, want %v", status.Msg.GetLifecycle(), want)
			}
			pending := prepare(t, svc, fix, grant, provisioned)
			assertExclusive()
			svc = reopen(t, svc, now)
			assertExclusive()
			resumed := prepare(t, svc, fix, grant, true)
			if !bytes.Equal(pending.GetCsrPem(), resumed.GetCsrPem()) || pending.GetEnrollmentTransactionId() != resumed.GetEnrollmentTransactionId() {
				t.Fatal("reopening changed the durable enrollment attempt")
			}
			if err := svc.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := journal.Open(t.Context(), directory)
			if err != nil {
				t.Fatalf("closing executor did not release the directory: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExpiredPriorCredentialIsDurablyRemoved(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "request"
		if restart {
			name = "startup"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2031, 7, 1, 0, 0, 0, 0, time.UTC)
			svc, fix, pending := pendingRenewalFixture(t, now)
			state := durable(t, svc)
			cert := fix.leaf(t, publicOf(state.GetPendingRenewal().GetPrivateKey()), uuid.MustParse(state.GetDeviceId()), uuid.MustParse(state.GetEnrollmentGeneration()), now.Add(-time.Minute), now.Add(30*24*time.Hour))
			if _, err := svc.CommitRenewal(t.Context(), connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: pending.GetIssuanceRequestId(), CertificatePem: cert})); err != nil {
				t.Fatal(err)
			}
			prior := durable(t, svc).GetPriorCredential()
			if prior == nil || !bytes.Equal(prior.GetPrivateKey(), state.GetIdentityPrivateKey()) {
				t.Fatal("renewal did not retain the old key during overlap")
			}
			expires := prior.GetRetainUntil().AsTime()
			if restart {
				svc = reopen(t, svc, expires)
			} else {
				svc.clock = func() time.Time { return expires }
				if _, err := svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{})); err != nil {
					t.Fatal(err)
				}
			}
			if durable(t, svc).GetPriorCredential() != nil {
				t.Fatal("expired prior private key remains in the live journal")
			}
			assertPriorAbsentAfterJournalReopen(t, svc)
		})
	}
}

func TestRecoveredRenewalDoesNotPersistExpiredPriorCredential(t *testing.T) {
	now := time.Date(2031, 7, 1, 0, 0, 0, 0, time.UTC)
	svc, fix, pending := pendingRenewalFixture(t, now)
	state := durable(t, svc)
	recoveredAt := parseCert(t, state.GetCertificatePem()).NotAfter.Add(time.Minute)
	svc = reopen(t, svc, recoveredAt)
	resumed := renew(t, svc)
	if resumed.GetIssuanceRequestId() != pending.GetIssuanceRequestId() || !bytes.Equal(resumed.GetRetrievalProof(), pending.GetRetrievalProof()) {
		t.Fatal("expiry replaced the pending issuance instead of resuming retrieval")
	}
	cert := fix.leaf(t, publicOf(state.GetPendingRenewal().GetPrivateKey()), uuid.MustParse(state.GetDeviceId()), uuid.MustParse(state.GetEnrollmentGeneration()), recoveredAt.Add(-time.Minute), recoveredAt.Add(30*24*time.Hour))
	installed, err := svc.CommitRenewal(t.Context(), connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: pending.GetIssuanceRequestId(), CertificatePem: cert}))
	if err != nil {
		t.Fatal(err)
	}
	if durable(t, svc).GetPriorCredential() != nil || installed.Msg.GetPriorRetainUntil() != nil {
		t.Fatal("recovered issuance retained an already-expired prior credential")
	}
	assertPriorAbsentAfterJournalReopen(t, svc)
}

func pendingRenewalFixture(t *testing.T, now time.Time) (*Service, fixture, *agentv1.PrepareRenewalResponse) {
	t.Helper()
	fix := newFixture(t, now)
	boot := uuid.NewString()
	svc := openExecutor(t, now, WithBootID(func() (string, error) { return boot, nil }))
	prepare(t, svc, fix, "lg1_test-grant-secret-with-32-characters-minimum", false)
	device, generation := uuid.New(), uuid.New()
	// A short-lived leaf is already renewal-due without an artificial journal edit.
	cert := fix.leaf(t, publicOf(durable(t, svc).GetIdentityPrivateKey()), device, generation, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := svc.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: cert})); err != nil {
		t.Fatal(err)
	}
	pending := session(t, svc)
	if _, err := svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: pending.GetPending().GetRequestId(), ServerEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	return svc, fix, renew(t, svc)
}

func assertPriorAbsentAfterJournalReopen(t *testing.T, svc *Service) {
	t.Helper()
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := journal.Open(t.Context(), svc.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	state, _, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.GetPriorCredential() != nil {
		t.Fatal("prior private key removal was not durable across journal reopen")
	}
}
