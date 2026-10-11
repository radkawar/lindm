package dispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/gen/lindm/recovery/v1/recoveryv1connect"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

var _ recoveryv1connect.RecoveryServiceHandler = (*Service)(nil)

// RecoveryHandler is mounted only on the pinned enrollment/admin TLS origin.
// Proofs confer no Principal and cannot authenticate ordinary device/admin RPCs.
func (s *Service) RecoveryHandler() (string, http.Handler) {
	path, handler := recoveryv1connect.NewRecoveryServiceHandler(s, s.HandlerOptions()...)
	return path, http.MaxBytesHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := core.Bound(r.Context())
		defer cancel()
		if err := s.Acquire(ctx); err != nil {
			core.WriteRPCError(w, r, core.MapErr(err))
			return
		}
		defer s.Release()
		handler.ServeHTTP(w, r.WithContext(ctx))
	}), core.MaxMessageBytes+core.MaxMessageOverhead)
}

type recoveryAdmission struct {
	row         devicedb.DeviceActionRecovery
	action      devicedb.DeviceAction
	credential  *agentv1.DeviceActionRecoveryCredential
	proof       *agentv1.RecoveryRequestProof
	proofSHA256 [32]byte
}

// Exact credential bytes are looked up by their server-retained digest before
// any untrusted envelope is decoded. Public key and scope come solely from the
// previously verified original-device handoff committed with the BOOT grant.
func (s *Service) authenticateRecovery(ctx context.Context, envelope, proof []byte, operation agentv1.RecoveryOperation, payload proto.Message) (*recoveryAdmission, error) {
	digest := sha256.Sum256(envelope)
	row, err := devicedb.New(s.Pool).GetRecoveryCredential(ctx, digest[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "recovery_credential_rejected")
	}
	if err != nil {
		return nil, core.MapErr(err)
	}
	if !bytes.Equal(row.CredentialEnvelope, envelope) {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "recovery_credential_rejected")
	}
	credential := new(agentv1.DeviceActionRecoveryCredential)
	if proto.Unmarshal(row.CredentialDocument, credential) != nil || !bytes.Equal(credential.GetHandoff().GetRecoveryPublicKey(), row.PublicKey) {
		return nil, core.MapErr(core.ErrInternalState)
	}
	now, err := core.DispatchClock(ctx, devicedb.New(s.Pool))
	if err != nil {
		return nil, core.MapErr(err)
	}
	verified, err := s.Authority.VerifyRecoveryRequestProof(ctx, proof, envelope, credential, operation, payload, now)
	if err != nil {
		if errors.Is(err, trust.ErrRecoveryRequestPayloadMismatch) || errors.Is(err, trust.ErrRecoveryRequestClockAhead) || errors.Is(err, trust.ErrRecoveryRequestExpired) {
			return nil, rpcreason.Error(connect.CodePermissionDenied, err.Error())
		}
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_request_rejected")
	}
	action, err := devicedb.New(s.Pool).GetDeviceAction(ctx, row.ActionID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	return &recoveryAdmission{row: row, action: action, credential: credential, proof: verified, proofSHA256: sha256.Sum256(proof)}, nil
}

// All mutating callers acquire principal and execution-authority locks first.
// Even the action-scoped key is fenced by original device/generation/session.
func lockRecovery(ctx context.Context, q *devicedb.Queries, admission *recoveryAdmission, history bool) (devicedb.DeviceAction, devicedb.DeviceActionRecovery, time.Time, error) {
	device, err := q.GetDeviceForUpdate(ctx, admission.action.DeviceID)
	if err != nil {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, err
	}
	if device.State != core.StateActive || device.CurrentGenerationID == nil || *device.CurrentGenerationID != admission.action.GenerationID {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, core.ErrDeviceRevoked
	}
	generation, err := q.GetGenerationAuthority(ctx, admission.action.GenerationID)
	if err != nil {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, err
	}
	if generation.State != core.StateActive || generation.SessionEpoch != admission.row.SessionEpoch {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, core.ErrSessionFenced
	}
	certificate, err := q.GetCertificateByID(ctx, admission.row.CertificateID)
	if err != nil {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, err
	}
	if certificate.DeviceID != admission.action.DeviceID || certificate.GenerationID != admission.action.GenerationID || (certificate.Status != "active" && certificate.Status != "overlapping") {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, core.ErrCertificateRejected
	}
	action, err := q.LockDeviceAction(ctx, admission.row.ActionID)
	if err != nil {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, err
	}
	row, err := q.LockDeviceActionRecovery(ctx, action.ID)
	if err != nil {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, err
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, err
	}
	if !history && !core.EnrollmentIssuanceResumable(certificate, now) {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, core.ErrCertificateRejected
	}
	if row.CredentialID != admission.row.CredentialID || !bytes.Equal(row.CredentialEnvelope, admission.row.CredentialEnvelope) {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, core.ErrInternalState
	}
	// Proof freshness is checked again after locks. Historical reads and terminal
	// reports can reconcile expired credentials; no such path grants a new effect.
	if now.Before(admission.proof.GetIssuedAt().AsTime()) || !now.Before(admission.proof.GetExpiresAt().AsTime()) || (!history && !now.Before(row.ExpiresAt.Time)) {
		return devicedb.DeviceAction{}, devicedb.DeviceActionRecovery{}, time.Time{}, rpcreason.Error(connect.CodePermissionDenied, "recovery_authority_expired")
	}
	return action, row, now, nil
}

func recoveryRequestReplay(ctx context.Context, q *devicedb.Queries, admission *recoveryAdmission, response proto.Message) (bool, error) {
	id, _ := uuid.Parse(admission.proof.GetRequestId())
	receipt, err := q.GetRecoveryRequest(ctx, devicedb.GetRecoveryRequestParams{CredentialID: admission.row.CredentialID, RequestID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(receipt.RequestSha256, admission.proofSHA256[:]) || !bytes.Equal(receipt.Nonce, admission.proof.GetNonce()) {
		return false, rpcreason.Error(connect.CodeAlreadyExists, "recovery_request_conflict")
	}
	if proto.Unmarshal(receipt.ResponseDocument, response) != nil {
		return false, core.ErrInternalState
	}
	return true, nil
}
func storeRecoveryRequest(ctx context.Context, q *devicedb.Queries, admission *recoveryAdmission, response proto.Message) error {
	count, err := q.RecoveryRequestCount(ctx, admission.row.CredentialID)
	if err != nil {
		return err
	}
	if count >= 262144 {
		return rpcreason.Error(connect.CodeResourceExhausted, "recovery_request_capacity")
	}
	encoded, err := proto.Marshal(response)
	if err != nil {
		return err
	}
	id, _ := uuid.Parse(admission.proof.GetRequestId())
	return q.InsertRecoveryRequest(ctx, devicedb.InsertRecoveryRequestParams{CredentialID: admission.row.CredentialID, RequestID: id, Nonce: admission.proof.GetNonce(), RequestSha256: admission.proofSHA256[:], ResponseDocument: encoded})
}
func recoveryCheckpoint(row devicedb.DeviceActionRecovery) (*agentv1.RecoveryCheckpoint, error) {
	if len(row.CheckpointDocument) == 0 {
		return nil, nil
	}
	checkpoint := new(agentv1.RecoveryCheckpoint)
	if proto.Unmarshal(row.CheckpointDocument, checkpoint) != nil {
		return nil, core.ErrInternalState
	}
	return checkpoint, nil
}

func recoveryJournal(row devicedb.DeviceActionRecovery) (*agentv1.RecoveryJournal, error) {
	if len(row.JournalDocument) == 0 {
		return nil, nil
	}
	journal := new(agentv1.RecoveryJournal)
	if proto.Unmarshal(row.JournalDocument, journal) != nil {
		return nil, core.ErrInternalState
	}
	// The preack snapshot and exact receipt are the two deterministic candidates
	// anchored by TPM NV before and after the runtime's local acknowledgment save.
	journal.CheckpointReceiptEnvelope = row.CheckpointReceiptEnvelope
	return journal, nil
}
func recoveryJournalDocument(journal *agentv1.RecoveryJournal, checkpoint *agentv1.RecoveryCheckpoint, action devicedb.DeviceAction, row devicedb.DeviceActionRecovery, credential *agentv1.DeviceActionRecoveryCredential, root *agentv1.ExecutionRoot, delegation []byte) ([]byte, error) {
	if journal == nil || proto.Size(journal) > 512<<10 || !bytes.Equal(journal.GetCredentialEnvelope(), row.CredentialEnvelope) || !bytes.Equal(journal.GetIntentEnvelope(), action.IntentEnvelope) || !proto.Equal(journal.GetHandoff(), credential.GetHandoff()) || !proto.Equal(journal.GetCheckpoint(), checkpoint) || len(journal.GetCheckpointReceiptEnvelope()) != 0 || !bytes.Equal(journal.GetStartGrantEnvelope(), row.StartGrantEnvelope) || !proto.Equal(journal.GetAcceptedRoot(), root) || !bytes.Equal(journal.GetDelegationEnvelope(), delegation) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_journal_binding_rejected")
	}
	credentialRoot := new(agentv1.ExecutionRoot)
	if protojson.Unmarshal(row.RootJson, credentialRoot) != nil {
		return nil, core.ErrInternalState
	}
	if !proto.Equal(journal.GetCredentialRoot(), credentialRoot) || !bytes.Equal(journal.GetCredentialDelegationEnvelope(), row.DelegationEnvelope) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_journal_trust_rejected")
	}
	if len(row.ChallengeDocument) > 0 {
		challenge := new(agentv1.DeviceActionChallenge)
		if proto.Unmarshal(row.ChallengeDocument, challenge) != nil {
			return nil, core.ErrInternalState
		}
		if !proto.Equal(journal.GetChallenge(), challenge) {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_journal_challenge_rejected")
		}
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(journal)
}

// Clear authentication wrappers before hashing, never the typed operation data.
func RecoveryAcquirePayload(request *recoveryv1.AcquireRecoveryWorkRequest) *recoveryv1.AcquireRecoveryWorkRequest {
	copy := proto.CloneOf(request)
	copy.CredentialEnvelope = nil
	copy.RequestProof = nil
	return copy
}
func RecoveryStartPayload(request *recoveryv1.AuthorizeRecoveryStartRequest) *recoveryv1.AuthorizeRecoveryStartRequest {
	copy := proto.CloneOf(request)
	copy.CredentialEnvelope = nil
	copy.RequestProof = nil
	return copy
}
func RecoveryCheckpointPayload(request *recoveryv1.CheckpointRecoveryActionRequest) *recoveryv1.CheckpointRecoveryActionRequest {
	copy := proto.CloneOf(request)
	copy.CredentialEnvelope = nil
	copy.RequestProof = nil
	return copy
}
func RecoveryResultPayload(request *recoveryv1.ReportRecoveryResultRequest) *recoveryv1.ReportRecoveryResultRequest {
	copy := proto.CloneOf(request)
	copy.CredentialEnvelope = nil
	copy.RequestProof = nil
	return copy
}
