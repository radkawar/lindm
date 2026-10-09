package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"

	"lindm/internal/trust"
)

// ExecutionSigning holds online plan and start private keys loaded from
// protected PKCS#8 files. Loading them is only resource resolution: it does not
// admit a delegation or authorize issuance. Callers must check the current
// authenticated delegation before signing, including exclusion of a rotated
// current root that is outside the pinned bootstrap domain.
type ExecutionSigning struct {
	PlanKey    ed25519.PrivateKey
	StartKey   ed25519.PrivateKey
	PlanKeyID  string
	StartKeyID string
}

func (s *ExecutionSigning) String() string {
	if s == nil {
		return "<nil>"
	}
	return "execution signing plan=" + s.PlanKeyID + " start=" + s.StartKeyID
}

func (s *ExecutionSigning) GoString() string { return s.String() }

func (s *ExecutionSigning) MarshalJSON() ([]byte, error) {
	return nil, errors.New("execution signing keys cannot be serialized")
}

func (d *Document) executionSigning(verifier *trust.ExecutionVerifier) (*ExecutionSigning, error) {
	configured := d.Proto.GetExecutionSigning()
	if configured == nil {
		return nil, nil
	}
	if verifier == nil {
		return nil, errors.New("execution signing requires an execution bootstrap")
	}
	planPath := reference(d.base, configured.GetPlanKeyFile())
	startPath := reference(d.base, configured.GetStartKeyFile())
	if planPath == startPath || filepath.Clean(planPath) == filepath.Clean(startPath) {
		return nil, errors.New("plan and start signing keys must use distinct files")
	}
	plan, err := readExecutionSigningKey(planPath)
	if err != nil {
		return nil, fmt.Errorf("read execution_signing.plan_key_file: %w", err)
	}
	start, err := readExecutionSigningKey(startPath)
	if err != nil {
		return nil, fmt.Errorf("read execution_signing.start_key_file: %w", err)
	}
	// Parsing has already established the exact Ed25519 private-key shape.
	planPublic := ed25519.PublicKey(plan[ed25519.SeedSize:])
	startPublic := ed25519.PublicKey(start[ed25519.SeedSize:])
	if bytes.Equal(planPublic, startPublic) {
		return nil, errors.New("plan and start signing keys must be distinct")
	}
	if err := verifier.OnlineKeySeparated(planPublic); err != nil {
		return nil, fmt.Errorf("plan signing key: %w", err)
	}
	if err := verifier.OnlineKeySeparated(startPublic); err != nil {
		return nil, fmt.Errorf("start signing key: %w", err)
	}
	planID, err := trust.KeyID(planPublic)
	if err != nil {
		return nil, fmt.Errorf("read execution_signing.plan_key_file: %w", err)
	}
	startID, err := trust.KeyID(startPublic)
	if err != nil {
		return nil, fmt.Errorf("read execution_signing.start_key_file: %w", err)
	}
	return &ExecutionSigning{PlanKey: plan, StartKey: start, PlanKeyID: planID, StartKeyID: startID}, nil
}

func readExecutionSigningKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := readFile(path, true)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return parseExecutionSigningKey(encoded)
}

func parseExecutionSigningKey(encoded []byte) (ed25519.PrivateKey, error) {
	trimmed := bytes.TrimSpace(encoded)
	// pem.Decode searches past malformed sections. A valid prefix alone does
	// not prove it decoded that section rather than a later fallback key.
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PRIVATE KEY-----")) ||
		bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 ||
		bytes.Count(trimmed, []byte("-----END ")) != 1 {
		return nil, errExecutionSigningKey
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errExecutionSigningKey
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errExecutionSigningKey
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errExecutionSigningKey
	}
	return key, nil
}

var errExecutionSigningKey = errors.New("execution signing key must be one unencrypted PKCS#8 Ed25519 PRIVATE KEY")
