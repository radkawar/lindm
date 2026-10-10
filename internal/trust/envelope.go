// Package trust validates domain-separated agent authority using standard DSSE.
package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"buf.build/go/protovalidate"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/protodata"
)

const (
	BootstrapType                      = "application/vnd.lindm.bootstrap.v1+protobuf"
	RenewalType                        = "application/vnd.lindm.renewal-intent.v1+protobuf"
	RetrievalType                      = "application/vnd.lindm.issuance-retrieval.v1+protobuf"
	SessionType                        = "application/vnd.lindm.session-acquisition.v1+protobuf"
	ExecutionRootType                  = "application/vnd.lindm.execution-root.v1+protobuf"
	DelegationType                     = "application/vnd.lindm.execution-delegation.v1+protobuf"
	ServiceIntentType                  = "application/vnd.lindm.service-intent.v1+protobuf"
	ServiceChallengeType               = "application/vnd.lindm.service-challenge.v1+protobuf"
	ServiceStartType                   = "application/vnd.lindm.service-start.v1+protobuf"
	ServiceAttestationType             = "application/vnd.lindm.service-attestation.v1+protobuf"
	DeviceActionIntentType             = "application/vnd.lindm.device-action-intent.v1+protobuf"
	DeviceActionChallengeType          = "application/vnd.lindm.device-action-challenge.v1+protobuf"
	DeviceActionStartType              = "application/vnd.lindm.device-action-start.v1+protobuf"
	DeviceActionAttestationType        = "application/vnd.lindm.device-action-attestation.v1+protobuf"
	DeviceActionEscrowReceiptType      = "application/vnd.lindm.device-action-escrow-receipt.v1+protobuf"
	DeviceActionInventoryReceiptType   = "application/vnd.lindm.device-action-inventory-receipt.v1+protobuf"
	DeviceActionRecoveryHandoffType    = "application/vnd.lindm.device-action-recovery-handoff.v1+protobuf"
	DeviceActionRecoveryCredentialType = "application/vnd.lindm.device-action-recovery-credential.v1+protobuf"
	DeviceActionRecoveryBootType       = "application/vnd.lindm.device-action-recovery-boot.v1+protobuf"
	RecoveryRequestProofType           = "application/vnd.lindm.recovery-request-proof.v1+protobuf"
	RecoveryCheckpointReceiptType      = "application/vnd.lindm.recovery-checkpoint-receipt.v1+protobuf"
	RecoveryTimeType                   = "application/vnd.lindm.recovery-time.v1+protobuf"
	ProvisioningRetrievalType          = "application/vnd.lindm.provisioning-retrieval.v1+protobuf"
	OfflineAuthorizationType           = "application/vnd.lindm.offline-enrollment-authorization.v1+protobuf"
	OfflineRequestType                 = "application/vnd.lindm.offline-enrollment-request.v1+protobuf"
	OfflineResponseType                = "application/vnd.lindm.offline-enrollment-response.v1+protobuf"
	maxEnvelopeBytes                   = 512 << 10
	maxSignatures                      = 16
)

// Authority compiles the finite set of signed payload schemas before use.
// It holds no signing keys and is safe for concurrent verification.
type Authority struct{ validator protovalidate.Validator }

func New() (*Authority, error) {
	validator, err := protovalidate.New(protovalidate.WithMessages(
		&agentv1.ExecutionRoot{}, &agentv1.BootstrapBundle{},
		&agentv1.RenewalIntent{}, &agentv1.IssuanceRetrieval{}, &agentv1.SessionAcquisition{},
		&agentv1.ExecutionRootTransition{}, &agentv1.ExecutionDelegation{},
		&agentv1.ServiceExecutionIntent{}, &agentv1.ServiceExecutionChallenge{}, &agentv1.ServiceExecutionStartGrant{},
		&agentv1.ServiceExecutionAttestation{},
		&agentv1.DeviceActionIntent{}, &agentv1.DeviceActionChallenge{}, &agentv1.DeviceActionStartGrant{},
		&agentv1.DeviceActionAttestation{}, &agentv1.DeviceActionEscrowReceipt{},
		&agentv1.DeviceActionInventoryReceipt{},
		&agentv1.DeviceActionRecoveryHandoff{}, &agentv1.DeviceActionRecoveryCredential{}, &agentv1.DeviceActionRecoveryBootGrant{},
		&agentv1.RecoveryRequestProof{}, &agentv1.RecoveryCheckpointReceipt{}, &agentv1.RecoveryCheckpoint{},
		&agentv1.RecoveryTimeStatement{}, &recoveryv1.GetRecoveryTimeRequest{}, &recoveryv1.GetRecoveryTimeResponse{},
		&enrollmentv1.ProvisioningRetrieval{},
		&agentv1.OfflineEnrollmentAuthorization{}, &agentv1.OfflineEnrollmentRequestProof{}, &agentv1.OfflineEnrollmentResponse{},
	), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, fmt.Errorf("compile agent authority schema: %w", err)
	}
	return &Authority{validator: validator}, nil
}

// KeyID identifies an Ed25519 key by its DER SubjectPublicKeyInfo digest.
func KeyID(public ed25519.PublicKey) (string, error) {
	if len(public) != ed25519.PublicKeySize {
		return "", errors.New("invalid Ed25519 public key")
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

func payloadType(message proto.Message) (string, error) {
	if message == nil || !message.ProtoReflect().IsValid() {
		return "", errors.New("missing signed authority payload")
	}
	switch message.(type) {
	case *agentv1.ExecutionRoot:
		return ExecutionRootType, nil
	case *agentv1.ExecutionDelegation:
		return DelegationType, nil
	case *agentv1.BootstrapBundle:
		return BootstrapType, nil
	case *agentv1.RenewalIntent:
		return RenewalType, nil
	case *agentv1.IssuanceRetrieval:
		return RetrievalType, nil
	case *agentv1.SessionAcquisition:
		return SessionType, nil
	case *agentv1.ServiceExecutionIntent:
		return ServiceIntentType, nil
	case *agentv1.ServiceExecutionChallenge:
		return ServiceChallengeType, nil
	case *agentv1.ServiceExecutionStartGrant:
		return ServiceStartType, nil
	case *agentv1.ServiceExecutionAttestation:
		return ServiceAttestationType, nil
	case *agentv1.DeviceActionIntent:
		return DeviceActionIntentType, nil
	case *agentv1.DeviceActionChallenge:
		return DeviceActionChallengeType, nil
	case *agentv1.DeviceActionStartGrant:
		return DeviceActionStartType, nil
	case *agentv1.DeviceActionAttestation:
		return DeviceActionAttestationType, nil
	case *agentv1.DeviceActionEscrowReceipt:
		return DeviceActionEscrowReceiptType, nil
	case *agentv1.DeviceActionInventoryReceipt:
		return DeviceActionInventoryReceiptType, nil
	case *agentv1.DeviceActionRecoveryHandoff:
		return DeviceActionRecoveryHandoffType, nil
	case *agentv1.DeviceActionRecoveryCredential:
		return DeviceActionRecoveryCredentialType, nil
	case *agentv1.DeviceActionRecoveryBootGrant:
		return DeviceActionRecoveryBootType, nil
	case *agentv1.RecoveryRequestProof:
		return RecoveryRequestProofType, nil
	case *agentv1.RecoveryCheckpointReceipt:
		return RecoveryCheckpointReceiptType, nil
	case *agentv1.RecoveryTimeStatement:
		return RecoveryTimeType, nil
	case *enrollmentv1.ProvisioningRetrieval:
		return ProvisioningRetrievalType, nil
	case *agentv1.OfflineEnrollmentAuthorization:
		return OfflineAuthorizationType, nil
	case *agentv1.OfflineEnrollmentRequestProof:
		return OfflineRequestType, nil
	case *agentv1.OfflineEnrollmentResponse:
		return OfflineResponseType, nil
	default:
		return "", errors.New("unsupported signed authority payload")
	}
}

// Sign signs a validated typed payload with distinct pure Ed25519 keys.
// Local RPC must construct payloads from protected state, not expose this API.
func (a *Authority) Sign(ctx context.Context, message proto.Message, keys ...ed25519.PrivateKey) ([]byte, error) {
	kind, err := payloadType(message)
	if err != nil {
		return nil, err
	}
	if err := a.validator.Validate(message); err != nil {
		return nil, errors.New("invalid signed authority payload")
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return nil, errors.New("unknown signed authority fields")
	}
	if len(keys) == 0 || len(keys) > maxSignatures {
		return nil, errors.New("invalid signing key count")
	}
	signers := make([]dsse.Signer, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if len(key) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid Ed25519 private key")
		}
		public := ed25519.PublicKey(key[ed25519.SeedSize:])
		id, err := KeyID(public)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[id]; exists {
			return nil, errors.New("duplicate signing key")
		}
		seen[id] = struct{}{}
		signers = append(signers, &edSigner{edVerifier: edVerifier{public: public, id: id}, private: key})
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	signer, err := dsse.NewEnvelopeSigner(signers...)
	if err != nil {
		return nil, err
	}
	envelope, err := signer.SignPayload(ctx, kind, payload)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxEnvelopeBytes {
		return nil, errors.New("signed authority exceeds size limit")
	}
	return encoded, nil
}

// Verify verifies exact envelope bytes against distinct known keys and quorum.
// Destination remains unchanged on any failure. Authorization bindings and current
// state must be checked by the caller after cryptographic/schema validation.
func (a *Authority) Verify(ctx context.Context, encoded []byte, destination proto.Message, threshold int, publicKeys ...ed25519.PublicKey) error {
	kind, err := payloadType(destination)
	if err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > maxEnvelopeBytes || len(publicKeys) > maxSignatures {
		return errors.New("invalid signed authority size")
	}
	var envelope dsse.Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return errors.New("invalid signed envelope")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing signed envelope data")
	}
	if envelope.PayloadType != kind || len(envelope.Signatures) == 0 || len(envelope.Signatures) > maxSignatures {
		return errors.New("invalid signed authority domain or signature count")
	}
	verifiers := make([]dsse.Verifier, 0, len(publicKeys))
	seen := make(map[string]struct{}, len(publicKeys))
	for _, public := range publicKeys {
		id, err := KeyID(public)
		if err != nil {
			return err
		}
		if _, exists := seen[id]; exists {
			return errors.New("duplicate verification key")
		}
		seen[id] = struct{}{}
		verifiers = append(verifiers, &edVerifier{public: public, id: id})
	}
	verifier, err := dsse.NewMultiEnvelopeVerifier(threshold, verifiers...)
	if err != nil {
		return errors.New("invalid authority quorum")
	}
	_, payload, err := verifier.VerifyAndDecode(ctx, &envelope)
	if err != nil {
		return errors.New("signed authority verification failed")
	}
	candidate := destination.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(payload, candidate); err != nil {
		return errors.New("invalid signed authority payload")
	}
	if err := protodata.ValidateClosed(candidate.ProtoReflect()); err != nil {
		return errors.New("unknown signed authority fields")
	}
	if err := a.validator.Validate(candidate); err != nil {
		return errors.New("invalid signed authority payload")
	}
	proto.Reset(destination)
	proto.Merge(destination, candidate)
	return nil
}

type edVerifier struct {
	public ed25519.PublicKey
	id     string
}

func (v *edVerifier) KeyID() (string, error)   { return v.id, nil }
func (v *edVerifier) Public() crypto.PublicKey { return v.public }
func (v *edVerifier) Verify(ctx context.Context, message, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ed25519.Verify(v.public, message, signature) {
		return errors.New("invalid Ed25519 signature")
	}
	return nil
}

type edSigner struct {
	edVerifier
	private ed25519.PrivateKey
}

func (s *edSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ed25519.Sign(s.private, message), nil
}
