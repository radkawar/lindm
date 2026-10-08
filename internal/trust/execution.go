package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
)

// ExecutionVerifier checks execution authority against the separately provisioned
// trust domains. It is immutable and does not persist rollback counters. Callers
// supply the last durably accepted root/version/epoch and atomically persist each
// returned update before using it. A verified document alone cannot start work.
type ExecutionVerifier struct {
	authority      *Authority
	deploymentID   string
	initialVersion uint64
	reserved       map[[sha256.Size]byte]struct{}
}

// NewExecutionVerifier takes a Bootstrap previously returned by VerifyBootstrap.
// Reserved TLS and release public keys are copied as fingerprints; subsequent
// mutation of the supplied bootstrap cannot change this verifier's trust domains.
func (a *Authority) NewExecutionVerifier(bootstrap *Bootstrap) (*ExecutionVerifier, error) {
	if bootstrap == nil || bootstrap.Root == nil || bootstrap.Bundle == nil || bootstrap.Root.GetDeploymentId() != bootstrap.Bundle.GetDeploymentId() {
		return nil, errors.New("verified bootstrap is required")
	}
	if err := a.validateExecutionMessage(bootstrap.Root); err != nil {
		return nil, err
	}
	v := &ExecutionVerifier{
		authority: a, deploymentID: bootstrap.Root.GetDeploymentId(),
		initialVersion: bootstrap.Root.GetVersion(), reserved: make(map[[sha256.Size]byte]struct{}),
	}
	for _, encoded := range [][]byte{bootstrap.Bundle.GetTransportCaPem(), bootstrap.Bundle.GetDeviceCaPem()} {
		if len(encoded) == 0 || len(encoded) > 65536 {
			return nil, errors.New("missing or oversized bootstrap certificates")
		}
		for len(bytes.TrimSpace(encoded)) != 0 {
			block, rest := pem.Decode(encoded)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("invalid bootstrap certificate")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("invalid bootstrap certificate")
			}
			v.reserved[sha256.Sum256(certificate.RawSubjectPublicKeyInfo)] = struct{}{}
			encoded = rest
		}
	}
	release, err := metadata.Root().FromBytes(bootstrap.Bundle.GetReleaseRootJson())
	if err != nil {
		return nil, errors.New("invalid bootstrap release root")
	}
	for _, key := range release.Signed.Keys {
		if key == nil {
			return nil, errors.New("missing bootstrap release key")
		}
		public, err := key.ToPublicKey()
		if err != nil {
			return nil, errors.New("invalid bootstrap release key")
		}
		digest, err := publicKeyDigest(public)
		if err != nil {
			return nil, err
		}
		v.reserved[digest] = struct{}{}
	}
	return v, nil
}

// VerifyRootTransition requires consecutive versions and both independent
// quorums. Neither an expired current root nor an expired intermediate root can
// restore online execution authority; those cases require owner reprovisioning.
func (v *ExecutionVerifier) VerifyRootTransition(ctx context.Context, current *agentv1.ExecutionRoot, transition *agentv1.ExecutionRootTransition, now time.Time) (*agentv1.ExecutionRoot, error) {
	if err := v.authority.validateExecutionMessage(transition); err != nil {
		return nil, err
	}
	previousKeys, err := v.rootKeys(current, now)
	if err != nil {
		return nil, err
	}
	if current.GetVersion() == math.MaxUint64 {
		return nil, errors.New("execution root version exhausted")
	}
	next := new(agentv1.ExecutionRoot)
	if err := v.authority.Verify(ctx, transition.GetPreviousQuorumEnvelope(), next, int(current.GetThreshold()), previousKeys...); err != nil {
		return nil, err
	}
	if next.GetVersion() != current.GetVersion()+1 {
		return nil, errors.New("execution root transition is not consecutive")
	}
	nextKeys, err := v.rootKeys(next, now)
	if err != nil {
		return nil, err
	}
	endorsed := new(agentv1.ExecutionRoot)
	if err := v.authority.Verify(ctx, transition.GetNextQuorumEnvelope(), endorsed, int(next.GetThreshold()), nextKeys...); err != nil {
		return nil, err
	}
	if !proto.Equal(next, endorsed) {
		return nil, errors.New("execution root quorums endorsed different roots")
	}
	return next, nil
}

// VerifyDelegation accepts only a new, root-bound delegation snapshot. Exact
// retransmissions are handled by the caller against its durable accepted bytes;
// they must never extend validity or lower version/recovery-epoch fences.
func (v *ExecutionVerifier) VerifyDelegation(ctx context.Context, root *agentv1.ExecutionRoot, envelope []byte, previousVersion, minimumEpoch uint64, now time.Time) (*agentv1.ExecutionDelegation, error) {
	keys, err := v.rootKeys(root, now)
	if err != nil {
		return nil, err
	}
	delegation := new(agentv1.ExecutionDelegation)
	if err := v.authority.Verify(ctx, envelope, delegation, int(root.GetThreshold()), keys...); err != nil {
		return nil, err
	}
	if delegation.GetDeploymentId() != v.deploymentID || delegation.GetRootVersion() != root.GetVersion() || delegation.GetVersion() <= previousVersion || delegation.GetMinimumRecoveryEpoch() < minimumEpoch {
		return nil, errors.New("execution delegation binding or rollback fence rejected")
	}
	if now.Before(delegation.GetNotBefore().AsTime()) || !now.Before(delegation.GetExpiresAt().AsTime()) || delegation.GetNotBefore().AsTime().Before(root.GetNotBefore().AsTime()) || delegation.GetExpiresAt().AsTime().After(root.GetExpiresAt().AsTime()) {
		return nil, errors.New("execution delegation exceeds current root validity")
	}
	for _, delegate := range delegation.GetDelegates() {
		if _, err := v.executionKey(delegate.GetKey()); err != nil {
			return nil, err
		}
		for _, rootKey := range root.GetKeys() {
			if delegate.GetKey().GetKeyId() == rootKey.GetKeyId() {
				return nil, errors.New("offline root key cannot be an online delegate")
			}
		}
	}
	return delegation, nil
}

func (v *ExecutionVerifier) rootKeys(root *agentv1.ExecutionRoot, now time.Time) ([]ed25519.PublicKey, error) {
	if err := v.authority.validateExecutionMessage(root); err != nil {
		return nil, err
	}
	if root.GetDeploymentId() != v.deploymentID || root.GetVersion() < v.initialVersion || now.Before(root.GetNotBefore().AsTime()) || !now.Before(root.GetExpiresAt().AsTime()) {
		return nil, errors.New("execution root binding or validity rejected")
	}
	keys := make([]ed25519.PublicKey, 0, len(root.GetKeys()))
	for _, key := range root.GetKeys() {
		public, err := v.executionKey(key)
		if err != nil {
			return nil, err
		}
		keys = append(keys, public)
	}
	return keys, nil
}

func (v *ExecutionVerifier) executionKey(key *agentv1.ExecutionKey) (ed25519.PublicKey, error) {
	public := ed25519.PublicKey(key.GetPublicKey())
	if len(public) != ed25519.PublicKeySize {
		return nil, errors.New("invalid execution key length")
	}
	digest, err := publicKeyDigest(public)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(digest[:]) != key.GetKeyId() {
		return nil, errors.New("execution key identity mismatch")
	}
	if _, reserved := v.reserved[digest]; reserved {
		return nil, errors.New("TLS or release key cannot authorize execution")
	}
	return public, nil
}

func (a *Authority) validateExecutionMessage(message proto.Message) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return errors.New("missing execution trust document")
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return errors.New("unknown execution trust fields")
	}
	if err := a.validator.Validate(message); err != nil {
		return errors.New("invalid execution trust document")
	}
	return nil
}

func publicKeyDigest(public crypto.PublicKey) ([sha256.Size]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return [sha256.Size]byte{}, errors.New("invalid execution trust public key")
	}
	return sha256.Sum256(der), nil
}
