// SPDX-License-Identifier: Apache-2.0

//go:build linux

package recovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

func snapshotFixture(t *testing.T) (SnapshotOptions, *recoveryTestServer, *recoveryTestProvider) {
	t.Helper()
	r, server, provider := newRecoveryRunnerFixture(t)
	r.credential.Handoff.Custody = agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM
	envelope, err := r.authority.Sign(t.Context(), r.credential, server.start)
	if err != nil {
		t.Fatal(err)
	}
	r.record.CredentialEnvelope = envelope
	initial := proto.CloneOf(r.record)
	server.snapshot = proto.CloneOf(initial)
	checkpoint := &agentv1.RecoveryCheckpoint{CredentialId: r.credential.GetCredentialId(), ActionId: r.credential.GetHandoff().GetIntent().GetActionId(), BootId: r.bootID, ExecutorIncarnation: r.incarnation, Sequence: 1, Phase: agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED, At: timestamppb.Now()}
	server.snapshot.Checkpoint = checkpoint
	server.checkpoint = proto.CloneOf(checkpoint)
	digest, err := trust.DeviceActionDigest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &agentv1.RecoveryCheckpointReceipt{CredentialId: checkpoint.GetCredentialId(), ActionId: checkpoint.GetActionId(), Sequence: 1, CheckpointSha256: digest[:], StoredAt: timestamppb.Now(), RootVersion: 1, DelegationVersion: 1}
	server.snapshot.CheckpointReceiptEnvelope, err = r.authority.Sign(t.Context(), receipt, server.start)
	if err != nil {
		t.Fatal(err)
	}
	return SnapshotOptions{Key: r.key, Bootstrap: server.bootstrap, Client: server, BootID: r.bootID, Initial: initial, Clock: &Clock{monotonic: func() (time.Duration, error) { return 0, nil }}}, server, provider
}

func snapshotBytes(t *testing.T, journal *agentv1.RecoveryJournal) ([]byte, []byte) {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return encoded, digest[:]
}

func TestFetchSnapshotSelectsOnlyExactNVState(t *testing.T) {
	for _, receipt := range []bool{false, true} {
		name := "preack"
		if receipt {
			name = "receipt_persisted"
		}
		t.Run(name, func(t *testing.T) {
			options, server, provider := snapshotFixture(t)
			candidate := proto.CloneOf(server.snapshot)
			if !receipt {
				candidate.CheckpointReceiptEnvelope = nil
			}
			want, digest := snapshotBytes(t, candidate)
			options.ExpectedSHA256 = digest
			before := proto.CloneOf(options.Initial)
			keyBefore := bytes.Clone(options.Key)
			got, err := FetchSnapshot(t.Context(), options)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("snapshot did not match exact TPM anchored bytes")
			}
			if !proto.Equal(options.Initial, before) || !bytes.Equal(options.Key, keyBefore) {
				t.Fatal("read-only reconstruction mutated custody")
			}
			if server.acquisitions != 1 || server.authorizations != 0 || server.effects != 0 || server.reports != 0 || provider.effects != 0 {
				t.Fatal("snapshot retrieval escaped single restricted read")
			}
		})
	}
}

func TestFetchSnapshotRejectsMissingTamperedAndConsumedState(t *testing.T) {
	for _, name := range []string{"missing", "wrong_digest", "changed_credential", "changed_handoff", "consumed", "unknown_fields", "changed_trust", "changed_receipt"} {
		t.Run(name, func(t *testing.T) {
			options, server, provider := snapshotFixture(t)
			_, options.ExpectedSHA256 = snapshotBytes(t, server.snapshot)
			switch name {
			case "missing":
				server.snapshot = nil
			case "wrong_digest":
				options.ExpectedSHA256 = bytes.Repeat([]byte{1}, 32)
			case "changed_credential":
				server.snapshot.CredentialEnvelope = []byte("other signed credential")
				_, options.ExpectedSHA256 = snapshotBytes(t, server.snapshot)
			case "changed_handoff":
				server.snapshot.Handoff.OriginalBootId = uuid.NewString()
				_, options.ExpectedSHA256 = snapshotBytes(t, server.snapshot)
			case "consumed":
				server.snapshot.StartedAt = timestamppb.Now()
				server.snapshot.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
				_, options.ExpectedSHA256 = snapshotBytes(t, server.snapshot)
			case "unknown_fields":
				server.snapshot.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 0x01})
				_, options.ExpectedSHA256 = snapshotBytes(t, server.snapshot)
			case "changed_trust":
				server.r.record.DelegationEnvelope = []byte("unauthenticated delegation")
			case "changed_receipt":
				server.snapshot.CheckpointReceiptEnvelope = []byte("different receipt")
			}
			if _, err := FetchSnapshot(t.Context(), options); err == nil {
				t.Fatal("untrusted or consumed snapshot accepted")
			}
			if server.acquisitions > 1 || server.authorizations != 0 || server.effects != 0 || server.reports != 0 || provider.effects != 0 {
				t.Fatal("snapshot failure retried or caused effects")
			}
		})
	}
}

func TestFetchSnapshotRejectsWrongKeyAndOriginalBootBeforeNetwork(t *testing.T) {
	for _, name := range []string{"key", "boot", "custody", "digest"} {
		t.Run(name, func(t *testing.T) {
			options, server, _ := snapshotFixture(t)
			_, options.ExpectedSHA256 = snapshotBytes(t, server.snapshot)
			switch name {
			case "key":
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				options.Key = key
			case "boot":
				options.BootID = options.Initial.GetHandoff().GetOriginalBootId()
			case "custody":
				options.Initial.Handoff.Custody = agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET
			case "digest":
				options.ExpectedSHA256 = nil
			}
			if _, err := FetchSnapshot(t.Context(), options); err == nil {
				t.Fatal("invalid reconstruction identity accepted")
			}
			if server.acquisitions != 0 {
				t.Fatal("invalid custody reached server")
			}
		})
	}
}
