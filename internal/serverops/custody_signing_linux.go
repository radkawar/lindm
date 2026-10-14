// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"

	"buf.build/go/protovalidate"
	"filippo.io/age"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

// CustodySigningOptions contains in-memory passphrases, never command strings.
// An external custodian uses its separately encrypted standard age identity and
// explicit root-key ciphertexts; generated onboarding uses the encrypted export.
type CustodySigningOptions struct {
	ExportFile, IdentityFile       string
	Passphrase, IdentityPassphrase []byte
	KeyFiles                       []string
}

// LoadCustodySigningKeys never writes decrypted identities or PKCS8 to disk. The
// independently retained public root, not the export's own root, selects authority.
// The caller must lock secret memory before reading passwords, and clear keys.
func LoadCustodySigningKeys(ctx context.Context, options CustodySigningOptions, root *agentv1.ExecutionRoot) (_ []ed25519.PrivateKey, err error) {
	if root == nil {
		return nil, errors.New("operations: independent_execution_root_required")
	}
	var identities []age.Identity
	var embedded []*agentv1.ServerRecoveryCustodyArtifact
	if options.ExportFile != "" {
		identities, embedded, err = loadGeneratedCustody(ctx, options, root)
		if err != nil {
			return nil, err
		}
	}
	if options.IdentityFile != "" {
		external, loadErr := loadIdentities(ctx, options.IdentityFile, options.IdentityPassphrase)
		if loadErr != nil {
			return nil, loadErr
		}
		identities = append(identities, external...)
	}
	if len(identities) == 0 || len(identities) > 19 {
		return nil, errors.New("operations: encrypted_custodian_identity_required")
	}
	if len(options.KeyFiles) > 16 {
		return nil, errors.New("operations: excessive_custody_key_inputs")
	}
	trusted := map[string]bool{}
	for _, key := range root.GetKeys() {
		id, idErr := trust.KeyID(ed25519.PublicKey(key.GetPublicKey()))
		if idErr != nil {
			return nil, errors.New("operations: invalid_independent_root_key")
		}
		trusted[id] = true
	}
	var keys []ed25519.PrivateKey
	defer func() {
		if err != nil {
			for _, key := range keys {
				clear(key)
			}
		}
	}()
	seenKeys := map[string]bool{}
	add := func(ciphertext io.Reader, required bool) error {
		plain, decryptErr := age.Decrypt(ciphertext, identities...)
		if decryptErr != nil {
			if !required {
				return nil
			}
			return errors.New("operations: custody_key_decryption_failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(plain, 16385))
		if readErr != nil || len(data) > 16384 {
			clear(data)
			return errors.New("operations: custody_key_decryption_or_size_failed")
		}
		defer clear(data)
		key, parseErr := parseQuorumKey(data)
		if parseErr != nil {
			return parseErr
		}
		id, idErr := trust.KeyID(ed25519.PublicKey(key[ed25519.SeedSize:]))
		if idErr != nil {
			clear(key)
			return idErr
		}
		if !trusted[id] {
			clear(key)
			return errors.New("operations: custody_key_not_in_independent_root")
		}
		if seenKeys[id] {
			clear(key)
			return errors.New("operations: duplicate_custody_signer")
		}
		seenKeys[id] = true
		keys = append(keys, key)
		return nil
	}
	if len(options.KeyFiles) == 0 {
		for _, artifact := range embedded {
			if artifact.GetName() == "sealed-pki-ca.age" {
				continue
			}
			if err = add(bytes.NewReader(artifact.GetEncryptedData()), false); err != nil {
				return nil, err
			}
		}
	} else {
		for _, path := range options.KeyFiles {
			data, readErr := readOperationFile(path, 1<<20, true)
			if readErr != nil {
				return nil, readErr
			}
			if err = add(bytes.NewReader(data), true); err != nil {
				return nil, err
			}
		}
	}
	if len(keys) < int(root.GetThreshold()) {
		return nil, errors.New("operations: custody_root_quorum_unavailable")
	}
	return keys, nil
}

func loadGeneratedCustody(ctx context.Context, options CustodySigningOptions, root *agentv1.ExecutionRoot) ([]age.Identity, []*agentv1.ServerRecoveryCustodyArtifact, error) {
	data, err := decryptPassphraseFile(ctx, options.ExportFile, options.Passphrase, 8<<20)
	if err != nil {
		return nil, nil, err
	}
	defer clear(data)
	exported := new(agentv1.ServerRecoveryCustodyExport)
	if err = protojson.Unmarshal(data, exported); err != nil {
		return nil, nil, errors.New("operations: invalid_custody_export")
	}
	if err = protovalidate.Validate(exported); err != nil {
		return nil, nil, errors.New("operations: invalid_custody_export")
	}
	if exported.GetDeploymentId() != root.GetDeploymentId() || exported.GetExecutionRoot().GetDeploymentId() != root.GetDeploymentId() {
		return nil, nil, errors.New("operations: custody_deployment_mismatch")
	}
	if err = validateArtifactInventory(exported.GetArtifacts(), true); err != nil {
		return nil, nil, err
	}
	seen := map[uint32]bool{}
	recipients := map[string]bool{}
	var identities []age.Identity
	for _, entry := range exported.GetIdentities() {
		identity, parseErr := age.ParseX25519Identity(entry.GetPrivateIdentity())
		if parseErr != nil || identity.Recipient().String() != entry.GetPublicRecipient() || seen[entry.GetCustodianIndex()] || recipients[entry.GetPublicRecipient()] {
			return nil, nil, errors.New("operations: invalid_custodian_identity_binding")
		}
		seen[entry.GetCustodianIndex()] = true
		recipients[entry.GetPublicRecipient()] = true
		identities = append(identities, identity)
	}
	return identities, exported.GetArtifacts(), nil
}

func parseQuorumKey(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("operations: custody_pkcs8_key_required")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("operations: invalid_custody_key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("operations: custody_ed25519_key_required")
	}
	return key, nil
}

// DigestCiphertext validates explicit offline input custody before hashing it.
func digestBytes(path string) (_ []byte, err error) {
	file, stat, err := openOperationFile(path, maxArchive, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, maxArchive+1))
	if err != nil || count != stat.Size {
		return nil, errors.New("operations: ciphertext_changed_or_size_exceeded")
	}
	return hash.Sum(nil), nil
}
