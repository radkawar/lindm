//go:build linux

package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1connect "lindm/gen/lindm/recovery/v1/recoveryv1connect"
	"lindm/internal/trust"
)

// SnapshotOptions is used only by the TPM custody loader after it authenticates
// the original capsule and reads the unconsumed current NV digest. Key is borrowed
// locked custody; Bootstrap and Client come from the signed image configuration.
// BootID identifies the actual new recovery boot, not the original root boot.
type SnapshotOptions struct {
	Key            ed25519.PrivateKey
	Bootstrap      *trust.Bootstrap
	Client         recoveryv1connect.RecoveryServiceClient
	BootID         string
	Initial        *agentv1.RecoveryJournal
	ExpectedSHA256 []byte
	Clock          *Clock
	ProvisionedAt  time.Time
}

// FetchSnapshot performs exactly one purpose-restricted read. It authenticates
// original custody with the same verifier as Run, checks current signed trust,
// and returns only bytes matching the independently retained TPM NV digest.
// It cannot authorize a grant, update a journal, consume an effect, or retry.
// The caller must re-read NV and compare the digest before parsing these bytes.
func FetchSnapshot(ctx context.Context, options SnapshotOptions) ([]byte, error) {
	if options.Initial == nil || len(options.ExpectedSHA256) != sha256.Size || options.Initial.GetHandoff().GetCustody() != agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM {
		return nil, errors.New("recovery_snapshot_custody_required")
	}
	at := options.Initial.GetTrustAcceptedAt().AsTime()
	r, err := authenticateRunner(ctx, Options{Key: options.Key, Bootstrap: options.Bootstrap, Client: options.Client, BootID: options.BootID, ImageSHA256: options.Initial.GetHandoff().GetRecoveryImageSha256(), Clock: options.Clock, ProvisionedAt: options.ProvisionedAt}, options.Initial, &at)
	if err != nil {
		return nil, err
	}
	return r.fetchSnapshot(ctx, options.ExpectedSHA256)
}

func (r *runner) fetchSnapshot(ctx context.Context, expected []byte) ([]byte, error) {
	work, err := r.acquire(ctx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(work.GetIntentEnvelope(), r.record.GetIntentEnvelope()) {
		return nil, errors.New("recovery_snapshot_intent_rejected")
	}
	if _, _, err := r.verifyTrustUpdate(ctx, work.GetTrustUpdate()); err != nil {
		return nil, err
	}
	journal := work.GetJournal()
	if journal == nil {
		return nil, errors.New("recovery_snapshot_missing")
	}
	encoded, matched, err := matchingSnapshot(journal, expected)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, errors.New("recovery_snapshot_nv_digest_mismatch")
	}
	if !bytes.Equal(journal.GetCredentialEnvelope(), r.record.GetCredentialEnvelope()) || !bytes.Equal(journal.GetIntentEnvelope(), r.record.GetIntentEnvelope()) || !proto.Equal(journal.GetHandoff(), r.record.GetHandoff()) || !proto.Equal(journal.GetCredentialRoot(), r.record.GetCredentialRoot()) || !bytes.Equal(journal.GetCredentialDelegationEnvelope(), r.record.GetCredentialDelegationEnvelope()) || !proto.Equal(journal.GetCheckpoint(), work.GetCheckpoint()) {
		return nil, errors.New("recovery_snapshot_binding_rejected")
	}
	if journal.GetStartedAt() != nil || journal.GetCheckpoint().GetPhase() == agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED || journal.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING {
		return nil, errors.New("recovery_snapshot_effect_consumed")
	}
	return encoded, nil
}

// The server stores the exact preack snapshot and returns the same message with
// its durable receipt inserted. Those are the only two legitimate NV anchors at
// this boundary. Never synthesize a new timestamp, grant, phase or trust version.
func matchingSnapshot(journal *agentv1.RecoveryJournal, expected []byte) ([]byte, bool, error) {
	if len(expected) != sha256.Size {
		return nil, false, errors.New("recovery_snapshot_digest_required")
	}
	candidate := journal
	for variant := range 2 {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(candidate)
		if err != nil {
			return nil, false, err
		}
		if len(encoded) > 512<<10 {
			return nil, false, errors.New("recovery_snapshot_too_large")
		}
		digest := sha256.Sum256(encoded)
		if bytes.Equal(digest[:], expected) {
			return encoded, true, nil
		}
		if variant == 1 || len(journal.GetCheckpointReceiptEnvelope()) == 0 {
			break
		}
		candidate = proto.CloneOf(journal)
		candidate.CheckpointReceiptEnvelope = nil
	}
	return nil, false, nil
}
