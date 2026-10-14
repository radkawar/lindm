// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

const capturedCAPath = ".release-input/ca-certificates.crt"

type signingExclusions struct{ spki, fingerprints, homes []string }

func normalizeSHA256(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("releasebuild: expected a 64-hex SHA256 pin")
	}
	return value, nil
}

func pinnedDocument(path, pin string, limit int64) ([]byte, string, error) {
	normalized, err := normalizeSHA256(pin)
	if err != nil {
		return nil, "", err
	}
	data, err := readBounded(path, limit)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != normalized {
		return nil, "", errors.New("releasebuild: authenticated input digest mismatch")
	}
	return data, normalized, nil
}

// Trust inventory pins are authenticated deployment inputs supplied by the
// release custodian, not identifiers copied from unauthenticated metadata.
func loadTrustInventory(path, pin string) (*signingExclusions, error) {
	data, _, err := pinnedDocument(path, pin, 4<<20)
	if err != nil {
		return nil, err
	}
	inventory := new(releasev1.SigningTrustInventory)
	if err := protojson.Unmarshal(data, inventory); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(inventory); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	add := func(public crypto.PublicKey) error {
		id, _, err := keyID(public)
		if err != nil {
			return err
		}
		seen[id] = true
		return nil
	}
	for _, group := range [][]string{inventory.GetExecutionPublicKeysPem(), inventory.GetTlsPublicKeysOrCertificatesPem()} {
		for _, encoded := range group {
			public, err := inventoryPublicKey(encoded)
			if err != nil {
				return nil, err
			}
			if err := add(public); err != nil {
				return nil, err
			}
		}
	}
	root, err := metadata.Root().FromBytes(inventory.GetTufRootJson())
	if err != nil {
		return nil, err
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		definition := root.Signed.Roles[role]
		if definition == nil || definition.Threshold < 1 || len(definition.KeyIDs) < definition.Threshold {
			return nil, errors.New("releasebuild: inventory TUF root has incomplete roles")
		}
		for _, id := range definition.KeyIDs {
			if root.Signed.Keys[id] == nil {
				return nil, errors.New("releasebuild: inventory TUF role key missing")
			}
		}
	}
	// Convert every key, including keys not currently assigned a role. go-tuf's
	// canonical-JSON key IDs are deliberately never compared with SPKI digests.
	for _, key := range root.Signed.Keys {
		if key == nil {
			return nil, errors.New("releasebuild: inventory contains null root key")
		}
		public, err := key.ToPublicKey()
		if err != nil {
			return nil, err
		}
		if err := add(public); err != nil {
			return nil, err
		}
	}
	targets, err := metadata.Targets().FromBytes(inventory.GetTufTargetsJson())
	if err != nil {
		return nil, err
	}
	// This inventory forbids key reuse; it does not authorize an update.
	// Authenticate the offline delegation without dropping old exclusion keys
	// merely because the captured root or targets metadata has expired.
	if err := root.VerifyDelegate(metadata.TARGETS, targets); err != nil {
		return nil, err
	}
	delegations := targets.Signed.Delegations
	if delegations == nil || len(delegations.Keys) == 0 || len(delegations.Roles) == 0 || delegations.SuccinctRoles != nil {
		return nil, errors.New("releasebuild: inventory targets must contain explicit delegated roles and keys")
	}
	for _, role := range delegations.Roles {
		if role.Name == "" || role.Threshold < 1 || len(role.KeyIDs) < role.Threshold {
			return nil, errors.New("releasebuild: inventory targets has incomplete delegation")
		}
		for _, id := range role.KeyIDs {
			if delegations.Keys[id] == nil {
				return nil, errors.New("releasebuild: inventory delegated key missing")
			}
		}
	}
	// Include every key in the signed delegation key map, even if retired from
	// all active roles. Actual SPKI identity flows to both signing paths.
	for _, key := range delegations.Keys {
		if key == nil {
			return nil, errors.New("releasebuild: inventory contains null delegated key")
		}
		public, err := key.ToPublicKey()
		if err != nil {
			return nil, err
		}
		if err := add(public); err != nil {
			return nil, err
		}
	}
	out := &signingExclusions{}
	for id := range seen {
		out.spki = append(out.spki, id)
	}
	sort.Strings(out.spki)
	for _, value := range inventory.GetNativeRejectFingerprints() {
		value = strings.ToUpper(strings.TrimSpace(value))
		decoded, err := hex.DecodeString(value)
		if err != nil || (len(decoded) != 20 && len(decoded) != 32) {
			return nil, errors.New("releasebuild: invalid native exclusion fingerprint")
		}
		out.fingerprints = append(out.fingerprints, value)
	}
	for _, value := range inventory.GetNativeRejectHomePrefixes() {
		value = strings.TrimSpace(value)
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return nil, errors.New("releasebuild: native excluded homes must be absolute clean paths")
		}
		out.homes = append(out.homes, value)
	}
	return out, nil
}

// inventoryPublicKey decodes one PEM public key or certificate; private or other
// key material is rejected.
func inventoryPublicKey(encoded string) (crypto.PublicKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("releasebuild: inventory entry must contain one public key or certificate")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return certificate.PublicKey, nil
	default:
		return nil, errors.New("releasebuild: inventory contains nonpublic key material")
	}
}

func loadCABundle(path, pin string) ([]byte, string, error) {
	data, digest, err := pinnedDocument(path, pin, 4<<20)
	if err != nil {
		return nil, "", err
	}
	remaining := bytes.TrimSpace(data)
	count := 0
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, "", errors.New("releasebuild: CA input must contain only PEM certificates")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, "", errors.New("releasebuild: malformed CA bundle")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", err
		}
		if !certificate.IsCA || !certificate.BasicConstraintsValid {
			return nil, "", errors.New("releasebuild: OCI trust input contains a non-CA certificate")
		}
		count++
		if count > 1024 {
			return nil, "", errors.New("releasebuild: too many CA certificates")
		}
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, "", errors.New("releasebuild: empty OCI CA bundle")
	}
	return data, digest, nil
}
