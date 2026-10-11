//go:build linux

package executor

import (
	"bytes"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

func attestResource(t *testing.T, f *resourceFixture, status *agentv1.ResourceExecutionStatus) (*agentv1.AttestResourceExecutionResponse, *agentv1.ResourceExecutionAttestation) {
	t.Helper()
	nonce := [32]byte{1, 2, 3}
	response, err := f.svc.AttestResourceExecution(t.Context(), connect.NewRequest(&agentv1.AttestResourceExecutionRequest{ActionId: status.GetActionId(), Nonce: nonce[:]}))
	if err != nil {
		t.Fatal(err)
	}
	state := durable(t, f.svc)
	binding := &trust.ResourceAttestationBinding{
		DeploymentID: f.fix.deploy, DeviceID: uuid.MustParse(state.GetDeviceId()),
		EnrollmentGeneration: uuid.MustParse(state.GetEnrollmentGeneration()),
		SessionEpoch:         state.GetSessionEpoch(), ActionID: uuid.MustParse(status.GetActionId()),
		IntentSHA256: [32]byte(status.GetIntentSha256()), Nonce: nonce,
	}
	verified, err := f.svc.authority.VerifyResourceAttestation(t.Context(), response.Msg.GetAttestationEnvelope(), response.Msg.GetCertificatePem(), f.fix.ca, binding, f.svc.now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg, verified
}

func TestResourceAttestationPreservesHistoryAfterRevocationAndClockRollback(t *testing.T) {
	f := newResourceFixture(t, true)
	intent := f.intent(t, 1)
	prepared, _ := f.prepare(t, intent)
	before, revision := resourceRow(t, f.svc, intent.GetActionId())
	plans, verifies := f.native.plans.Load(), f.native.verifies.Load()
	// Revoke execution authority and introduce real fixture drift. Attestation
	// must describe retained evidence, not invoke a provider or authorize work.
	revoked := delegationDocument(f.fix.deploy.String(), 1, 2, 0, f.now)
	callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, revoked, f.fix.rootKey)})
	f.native.mu.Lock()
	f.native.observation.ActiveState, f.native.observation.SubState = "inactive", "dead"
	setBoundaryFingerprint(f.native.observation)
	f.native.mu.Unlock()
	f.wall.Store(f.now.Add(-10 * time.Second).UnixNano())
	_, attestation := attestResource(t, f, prepared.GetStatus())
	if !proto.Equal(attestation.GetStatus(), prepared.GetStatus()) || attestation.GetActionRevision() != uint64(revision) {
		t.Fatal("attestation replaced historical evidence or revision")
	}
	if !attestation.GetIssuedAt().AsTime().Before(attestation.GetStatus().GetCompletedAt().AsTime()) {
		t.Fatal("attestation rewrote observed timestamps after clock rollback")
	}
	after, afterRevision := resourceRow(t, f.svc, intent.GetActionId())
	if !proto.Equal(before, after) || afterRevision != revision || f.native.plans.Load() != plans || f.native.verifies.Load() != verifies || f.native.effects.Load() != 0 {
		t.Fatal("attestation mutated history or touched the native provider")
	}
}

func TestResourceAttestationDoesNotConsumeOrExpirePreparedWork(t *testing.T) {
	f := newResourceFixture(t, false)
	pauseResourceConsumer(t, f.svc)
	intent := f.intent(t, 1)
	prepared, _ := f.prepare(t, intent)
	before, revision := resourceRow(t, f.svc, intent.GetActionId())
	f.wall.Store(f.now.Add(time.Minute).UnixNano())
	f.bootClock.Add(uint64(time.Minute))
	_, attestation := attestResource(t, f, prepared.GetStatus())
	after, afterRevision := resourceRow(t, f.svc, intent.GetActionId())
	if attestation.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED || !proto.Equal(before, after) || afterRevision != revision || f.native.applies.Load() != 0 {
		t.Fatal("history attestation acted as a work transition or effect authorization")
	}
}

func TestResourceAttestationRequiresCurrentIdentityAndSession(t *testing.T) {
	for _, fence := range []string{"expired-certificate", "pending-renewal", "pending-session", "other-boot"} {
		t.Run(fence, func(t *testing.T) {
			f := newResourceFixture(t, true)
			pauseResourceConsumer(t, f.svc)
			intent := f.intent(t, 1)
			prepared, _ := f.prepare(t, intent)
			switch fence {
			case "expired-certificate":
				f.wall.Store(f.now.Add(24 * time.Hour).UnixNano())
			case "pending-renewal":
				f.wall.Store(durable(t, f.svc).GetRenewAfter().AsTime().UnixNano())
				renew(t, f.svc)
			case "pending-session", "other-boot":
				f.boot = uuid.NewString()
				if fence == "pending-session" {
					session(t, f.svc)
				}
			}
			_, err := f.svc.AttestResourceExecution(t.Context(), connect.NewRequest(&agentv1.AttestResourceExecutionRequest{ActionId: intent.GetActionId(), Nonce: make([]byte, 32)}))
			if connect.CodeOf(err) != connect.CodeFailedPrecondition {
				t.Fatalf("unusable identity/session authenticated a report: %v", err)
			}
			// The historical local read remains available; it is not a remotely
			// authenticated report and must not acquire the new signing fences.
			local, err := f.svc.GetResourceExecution(t.Context(), connect.NewRequest(&agentv1.GetResourceExecutionRequest{ActionId: intent.GetActionId()}))
			if err != nil || !proto.Equal(local.Msg.GetStatus(), prepared.GetStatus()) {
				t.Fatalf("signing fence made historical local evidence unavailable: %v", err)
			}
		})
	}
}

func TestResourceAttestationClipsLifetimeToActiveCertificate(t *testing.T) {
	f := newResourceFixture(t, true)
	prepared, _ := f.prepare(t, f.intent(t, 1))
	f.wall.Store(f.now.Add(24*time.Hour - 5*time.Second).UnixNano())
	_, attestation := attestResource(t, f, prepared.GetStatus())
	if !attestation.GetExpiresAt().AsTime().Equal(f.now.Add(24*time.Hour)) || attestation.GetExpiresAt().AsTime().Sub(attestation.GetIssuedAt().AsTime()) != 5*time.Second {
		t.Fatal("attestation extended authority past the active certificate")
	}
}

func TestResourceAttestationUsesRenewedKeyForOriginalExecutionHistory(t *testing.T) {
	f := newResourceFixture(t, false)
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	startResource(t, f.svc, intent.GetActionId(), f.grant(t, intent))
	status := awaitResourceTerminal(t, f.svc, intent.GetActionId())
	original, _ := resourceRow(t, f.svc, intent.GetActionId())
	state := durable(t, f.svc)
	renewAt := state.GetRenewAfter().AsTime()
	f.wall.Store(renewAt.UnixNano())
	pending := renew(t, f.svc)
	nextCertificate := f.fix.leaf(t, publicOf(durable(t, f.svc).GetPendingRenewal().GetPrivateKey()), uuid.MustParse(state.GetDeviceId()), uuid.MustParse(state.GetEnrollmentGeneration()), renewAt.Add(-time.Minute), renewAt.Add(24*time.Hour))
	// Enrollment and renewal accept a PEM leaf after an issuer's textual
	// preamble. The new attestation boundary must still emit one canonical leaf.
	encodedCertificate := append([]byte("Issuer-exported device certificate\n"), nextCertificate...)
	if _, err := f.svc.CommitRenewal(t.Context(), connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: pending.GetIssuanceRequestId(), CertificatePem: encodedCertificate})); err != nil {
		t.Fatal(err)
	}
	// The original leaf and execution delegation are now expired. Historical
	// challenge verification must use acceptance time; new proofs use the new key.
	f.wall.Store(f.now.Add(25 * time.Hour).UnixNano())
	response, attestation := attestResource(t, f, status)
	if !bytes.Equal(response.GetCertificatePem(), nextCertificate) || bytes.Equal(response.GetCertificatePem(), original.GetChallengeCertificatePem()) || !proto.Equal(attestation.GetStatus(), status) {
		t.Fatal("renewal replaced history or retained the old attestation certificate")
	}
	if err := f.svc.authority.Verify(t.Context(), response.GetAttestationEnvelope(), new(agentv1.ResourceExecutionAttestation), 1, publicOf(state.GetIdentityPrivateKey())); err == nil {
		t.Fatal("renewed attestation was signed by the retired identity key")
	}
}
