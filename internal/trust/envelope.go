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
	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	BootstrapType    = "application/vnd.lindm.bootstrap.v1+protobuf"
	RenewalType      = "application/vnd.lindm.renewal-intent.v1+protobuf"
	RetrievalType    = "application/vnd.lindm.issuance-retrieval.v1+protobuf"
	SessionType      = "application/vnd.lindm.session-acquisition.v1+protobuf"
	maxEnvelopeBytes = 512 << 10
	maxSignatures    = 16
)

// Authority compiles the finite set of signed payload schemas before use.
// It holds no signing keys and is safe for concurrent verification.
type Authority struct{ validator protovalidate.Validator }

func New() (*Authority, error) {
	validator, err := protovalidate.New(protovalidate.WithMessages(
		&agentv1.ExecutionRoot{}, &agentv1.BootstrapBundle{},
		&agentv1.RenewalIntent{}, &agentv1.IssuanceRetrieval{}, &agentv1.SessionAcquisition{},
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
	case *agentv1.BootstrapBundle:
		return BootstrapType, nil
	case *agentv1.RenewalIntent:
		return RenewalType, nil
	case *agentv1.IssuanceRetrieval:
		return RetrievalType, nil
	case *agentv1.SessionAcquisition:
		return SessionType, nil
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
	if unknownFields(message.ProtoReflect()) {
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
	if unknownFields(candidate.ProtoReflect()) {
		return errors.New("unknown signed authority fields")
	}
	if err := a.validator.Validate(candidate); err != nil {
		return errors.New("invalid signed authority payload")
	}
	proto.Reset(destination)
	proto.Merge(destination, candidate)
	return nil
}

// Authority schemas have nested timestamps but no maps. Walk present messages
// so an unrecognized nested field cannot bypass strict signed-schema handling.
func unknownFields(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsMap() {
			unknown = true
			return false
		}
		if field.Message() == nil {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := range list.Len() {
				if unknownFields(list.Get(i).Message()) {
					unknown = true
					return false
				}
			}
		} else {
			unknown = unknownFields(value.Message())
		}
		return !unknown
	})
	return unknown
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
