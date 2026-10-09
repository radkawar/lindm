//go:build integration

package device

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/trust"
)

func TestServiceDispatchDeviceClockSkew(t *testing.T) {
	for _, skew := range []time.Duration{-90 * time.Second, 90 * time.Second, 3 * time.Minute} {
		t.Run(skew.String(), func(t *testing.T) {
			f := newDispatchFixture(t)
			f.assign(t, nil)
			work := f.work(t)
			intent := f.intent(t, work)
			if lifetime := intent.GetExpiresAt().AsTime().Sub(intent.GetNotBefore().AsTime()); lifetime != 12*time.Minute {
				t.Fatalf("intent lifetime %s, want twelve minutes", lifetime)
			}
			tx, err := f.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			snapshot, verifier, err := f.service.execution.CurrentInTransaction(t.Context(), tx)
			if err != nil {
				_ = tx.Rollback(t.Context())
				t.Fatal(err)
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			deviceNow := time.Now().UTC().Add(skew)
			if skew < trust.MaxDeviceClockSkew {
				if _, err := verifier.VerifyServiceIntent(t.Context(), snapshot.Root, snapshot.Delegation, work.GetIntentEnvelope(), deviceNow); err != nil {
					t.Fatalf("intent rejected within device-clock tolerance: %v", err)
				}
			}
			challenge := f.challenge(t, work)
			challenge.IssuedAt = timestamppb.New(deviceNow)
			challenge.ExpiresAt = timestamppb.New(deviceNow.Add(30 * time.Second))
			request := &devicev1.AuthorizeServiceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, challenge, f.key)}
			response, err := f.service.AuthorizeServiceStart(f.deviceCtx, connect.NewRequest(request))
			if skew > trust.MaxDeviceClockSkew {
				dispatchError(t, err, connect.CodeFailedPrecondition, "device_clock_skew")
			} else {
				if err != nil {
					t.Fatalf("challenge rejected within device-clock tolerance: %v", err)
				}
				grant, err := verifier.VerifyServiceStart(t.Context(), snapshot.Root, snapshot.Delegation, response.Msg.GetStartGrantEnvelope(), intent, challenge, deviceNow)
				if err != nil {
					t.Fatalf("device rejected grant in its own clock domain: %v", err)
				}
				if !grant.GetNotBefore().AsTime().Equal(deviceNow) || grant.GetExpiresAt().AsTime().After(challenge.GetExpiresAt().AsTime()) || grant.GetExpiresAt().AsTime().Sub(deviceNow) > 30*time.Second {
					t.Fatal("grant extended device challenge or residual authorization window")
				}
			}
			result := f.result(t, work, 1, agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED, false)
			attestation := new(agentv1.ServiceExecutionAttestation)
			if err := f.service.authority.Verify(t.Context(), result.GetAttestationEnvelope(), attestation, 1, f.principal.PublicKey); err != nil {
				t.Fatal(err)
			}
			attestation.IssuedAt = timestamppb.New(deviceNow)
			attestation.ExpiresAt = timestamppb.New(deviceNow.Add(30 * time.Second))
			result.AttestationEnvelope = f.sign(t, attestation, f.key)
			_, err = f.service.ReportServiceResult(f.deviceCtx, connect.NewRequest(result))
			if skew > trust.MaxDeviceClockSkew {
				dispatchError(t, err, connect.CodeFailedPrecondition, "device_clock_skew")
				return
			}
			if err != nil {
				t.Fatalf("attestation rejected within device-clock tolerance: %v", err)
			}
			// Tolerating device wall-clock skew must never extend the server's
			// nonce lifetime, even when the device-signed interval remains valid.
			work = f.work(t)
			attestation.Nonce = work.GetResultNonce()
			attestation.ActionRevision++
			result.AttestationEnvelope = f.sign(t, attestation, f.key)
			if _, err := f.pool.Exec(t.Context(), "UPDATE service_actions SET nonce_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", work.GetActionId()); err != nil {
				t.Fatal(err)
			}
			_, err = f.service.ReportServiceResult(f.deviceCtx, connect.NewRequest(result))
			dispatchError(t, err, connect.CodePermissionDenied, "service_result_nonce_rejected")
		})
	}
}
