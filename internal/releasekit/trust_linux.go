// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasekit

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/pki"
)

func publicPEM(public crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func parsePublic(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("releasekit: expected one Ed25519 public PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("releasekit: expected Ed25519 public key")
	}
	return public, nil
}

func validateCA(data []byte) error {
	if len(data) == 0 || len(data) > maxFileSize {
		return errors.New("releasekit: explicitly approved CA bundle required, bounded to 4 MiB")
	}
	rest := bytes.TrimSpace(data)
	count := 0
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("releasekit: CA bundle must contain only certificates")
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("releasekit: invalid CA certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		if !pki.IsReleaseCAAnchor(cert) {
			return errors.New("releasekit: CA bundle contains a non-CA certificate")
		}
		count++
		rest = bytes.TrimSpace(remaining)
	}
	if count == 0 {
		return errors.New("releasekit: empty CA bundle")
	}
	return nil
}

func signedBytes[T metadata.Roles](meta *metadata.Metadata[T], key ed25519.PrivateKey) ([]byte, error) {
	signer, err := signature.LoadSignerVerifier(key, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if _, err := meta.Sign(signer); err != nil {
		return nil, err
	}
	return meta.ToBytes(false)
}

func metaBinding(data []byte) *metadata.MetaFiles {
	sum := sha256.Sum256(data)
	return &metadata.MetaFiles{Version: 1, Length: int64(len(data)), Hashes: metadata.Hashes{"sha256": sum[:]}}
}

func trustDocuments(keys []ed25519.PrivateKey, ca []byte) (map[string][]byte, error) {
	documents := map[string][]byte{CAFile: ca}
	attestation, err := publicPEM(ed25519.PublicKey(keys[0][ed25519.SeedSize:]))
	if err != nil {
		return nil, err
	}
	documents[AttestationPublicFile] = attestation
	execution, err := publicPEM(ed25519.PublicKey(keys[1][ed25519.SeedSize:]))
	if err != nil {
		return nil, err
	}
	tls, err := publicPEM(ed25519.PublicKey(keys[2][ed25519.SeedSize:]))
	if err != nil {
		return nil, err
	}
	expires := time.Now().UTC().AddDate(1, 0, 0)
	root := metadata.Root(expires)
	for index, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		key, err := metadata.KeyFromPublicKey(ed25519.PublicKey(keys[index+3][ed25519.SeedSize:]))
		if err != nil {
			return nil, err
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			return nil, err
		}
	}
	documents[RootFile], err = signedBytes(root, keys[3])
	if err != nil {
		return nil, err
	}
	targets := metadata.Targets(expires)
	delegatedKey, err := metadata.KeyFromPublicKey(ed25519.PublicKey(keys[7][ed25519.SeedSize:]))
	if err != nil {
		return nil, err
	}
	delegatedID, err := delegatedKey.ID()
	if err != nil {
		return nil, err
	}
	targets.Signed.Delegations = &metadata.Delegations{
		Keys:  map[string]*metadata.Key{delegatedID: delegatedKey},
		Roles: []metadata.DelegatedRole{{Name: "release", KeyIDs: []string{delegatedID}, Threshold: 1, Terminating: true, Paths: []string{"releases/*"}}},
	}
	for _, name := range []string{AttestationPublicFile, CAFile} {
		target, err := (&metadata.TargetFiles{}).FromBytes(name, documents[name], "sha256")
		if err != nil {
			return nil, err
		}
		targets.Signed.Targets[name] = target
	}
	documents["targets.json"], err = signedBytes(targets, keys[4])
	if err != nil {
		return nil, err
	}
	documents["delegated.json"], err = signedBytes(metadata.Targets(expires), keys[7])
	if err != nil {
		return nil, err
	}
	snapshot := metadata.Snapshot(expires)
	snapshot.Signed.Meta = map[string]*metadata.MetaFiles{"targets.json": metaBinding(documents["targets.json"]), "release.json": metaBinding(documents["delegated.json"])}
	documents["snapshot.json"], err = signedBytes(snapshot, keys[5])
	if err != nil {
		return nil, err
	}
	timestamp := metadata.Timestamp(expires)
	timestamp.Signed.Meta = map[string]*metadata.MetaFiles{"snapshot.json": metaBinding(documents["snapshot.json"])}
	documents["timestamp.json"], err = signedBytes(timestamp, keys[6])
	if err != nil {
		return nil, err
	}
	inventory := &releasev1.SigningTrustInventory{
		ExecutionPublicKeysPem:         []string{string(execution)},
		TlsPublicKeysOrCertificatesPem: []string{string(tls)},
		TufRootJson:                    documents[RootFile], TufTargetsJson: documents["targets.json"],
	}
	if err := protovalidate.Validate(inventory); err != nil {
		return nil, err
	}
	documents[InventoryFile], err = protojson.Marshal(inventory)
	if err != nil {
		return nil, err
	}
	return documents, nil
}

func makePins(documents map[string][]byte, fingerprint string) []byte {
	var out strings.Builder
	out.WriteString("lindm-production-key-kit-v1\n")
	fmt.Fprintf(&out, "package-fingerprint %s\n", fingerprint)
	for _, name := range publicFiles {
		fmt.Fprintf(&out, "sha256 %s %s\n", name, digest(documents[name]))
	}
	return []byte(out.String())
}

func publicSummary(documents map[string][]byte, fingerprint string) (*Public, error) {
	public, err := parsePublic(documents[AttestationPublicFile])
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return &Public{AttestationKeyID: digest(spki), PackageFingerprint: fingerprint, InventorySHA256: digest(documents[InventoryFile]), CASHA256: digest(documents[CAFile])}, nil
}

// validateTrust also returns public identities in the fixed archive key order.
func validateTrust(documents map[string][]byte) ([]ed25519.PublicKey, error) {
	inventory := new(releasev1.SigningTrustInventory)
	if err := protojson.Unmarshal(documents[InventoryFile], inventory); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(inventory); err != nil {
		return nil, err
	}
	if len(inventory.ExecutionPublicKeysPem) != 1 || len(inventory.TlsPublicKeysOrCertificatesPem) != 1 || len(inventory.NativeRejectFingerprints) != 0 || len(inventory.NativeRejectHomePrefixes) != 0 {
		return nil, errors.New("releasekit: unexpected inventory domains")
	}
	if !bytes.Equal(inventory.TufRootJson, documents[RootFile]) || !bytes.Equal(inventory.TufTargetsJson, documents["targets.json"]) {
		return nil, errors.New("releasekit: inventory metadata mismatch")
	}
	var keys []ed25519.PublicKey
	for _, data := range [][]byte{documents[AttestationPublicFile], []byte(inventory.ExecutionPublicKeysPem[0]), []byte(inventory.TlsPublicKeysOrCertificatesPem[0])} {
		key, err := parsePublic(data)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	root, err := metadata.Root().FromBytes(documents[RootFile])
	if err != nil {
		return nil, err
	}
	if len(root.Signed.Keys) != 4 || len(root.Signed.Roles) != 4 {
		return nil, errors.New("releasekit: incomplete TUF root")
	}
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		definition := root.Signed.Roles[role]
		if definition == nil || definition.Threshold != 1 || len(definition.KeyIDs) != 1 {
			return nil, errors.New("releasekit: invalid TUF role")
		}
		key, err := tufPublic(root.Signed.Keys[definition.KeyIDs[0]])
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		return nil, err
	}
	targets, err := metadata.Targets().FromBytes(documents["targets.json"])
	if err != nil {
		return nil, err
	}
	if err := root.VerifyDelegate(metadata.TARGETS, targets); err != nil {
		return nil, err
	}
	delegations := targets.Signed.Delegations
	if delegations == nil || len(delegations.Keys) != 1 || len(delegations.Roles) != 1 || delegations.SuccinctRoles != nil {
		return nil, errors.New("releasekit: incomplete TUF delegation")
	}
	role := delegations.Roles[0]
	if role.Name != "release" || role.Threshold != 1 || len(role.KeyIDs) != 1 || !role.Terminating || len(role.Paths) != 1 || role.Paths[0] != "releases/*" || len(role.PathHashPrefixes) != 0 {
		return nil, errors.New("releasekit: unexpected TUF delegation")
	}
	key, err := tufPublic(delegations.Keys[role.KeyIDs[0]])
	if err != nil {
		return nil, err
	}
	keys = append(keys, key)
	delegated, err := metadata.Targets().FromBytes(documents["delegated.json"])
	if err != nil {
		return nil, err
	}
	if err := targets.VerifyDelegate("release", delegated); err != nil {
		return nil, err
	}
	if len(delegated.Signed.Targets) != 0 || delegated.Signed.Delegations != nil {
		return nil, errors.New("releasekit: unexpected initial delegated targets")
	}
	if len(targets.Signed.Targets) != 2 {
		return nil, errors.New("releasekit: incomplete initial public targets")
	}
	for _, name := range []string{AttestationPublicFile, CAFile} {
		target := targets.Signed.Targets[name]
		if target == nil {
			return nil, errors.New("releasekit: missing public target")
		}
		if err := target.VerifyLengthHashes(documents[name]); err != nil {
			return nil, err
		}
	}
	snapshot, err := metadata.Snapshot().FromBytes(documents["snapshot.json"])
	if err != nil {
		return nil, err
	}
	if err := root.VerifyDelegate(metadata.SNAPSHOT, snapshot); err != nil {
		return nil, err
	}
	if len(snapshot.Signed.Meta) != 2 {
		return nil, errors.New("releasekit: incomplete snapshot")
	}
	for name, file := range map[string]string{"targets.json": "targets.json", "release.json": "delegated.json"} {
		if err := verifyMeta(snapshot.Signed.Meta[name], documents[file]); err != nil {
			return nil, err
		}
	}
	timestamp, err := metadata.Timestamp().FromBytes(documents["timestamp.json"])
	if err != nil {
		return nil, err
	}
	if err := root.VerifyDelegate(metadata.TIMESTAMP, timestamp); err != nil {
		return nil, err
	}
	if len(timestamp.Signed.Meta) != 1 {
		return nil, errors.New("releasekit: incomplete timestamp")
	}
	if err := verifyMeta(timestamp.Signed.Meta["snapshot.json"], documents["snapshot.json"]); err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	for _, key := range keys {
		if seen[string(key)] {
			return nil, errors.New("releasekit: production signing domains must have distinct keys")
		}
		seen[string(key)] = true
	}
	return keys, nil
}

func tufPublic(key *metadata.Key) (ed25519.PublicKey, error) {
	if key == nil {
		return nil, errors.New("releasekit: missing TUF key")
	}
	parsed, err := key.ToPublicKey()
	if err != nil {
		return nil, err
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("releasekit: expected Ed25519 TUF key")
	}
	return public, nil
}

func verifyMeta(meta *metadata.MetaFiles, data []byte) error {
	if meta == nil || meta.Version != 1 || meta.Length != int64(len(data)) || len(meta.Hashes) != 1 {
		return errors.New("releasekit: metadata binding mismatch")
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(meta.Hashes["sha256"], sum[:]) {
		return errors.New("releasekit: metadata hash mismatch")
	}
	return nil
}

func validatePublic(documents map[string][]byte) (*Public, error) {
	if err := validateCA(documents[CAFile]); err != nil {
		return nil, err
	}
	if _, err := validateTrust(documents); err != nil {
		return nil, err
	}
	fingerprint, err := validatePackagePublic(documents[PackagePublicFile])
	if err != nil {
		return nil, err
	}
	if _, err := ageRecipient(documents[BackupRecipientFile]); err != nil {
		return nil, err
	}
	pins := makePins(documents, fingerprint)
	if !bytes.Equal(pins, documents[PinsFile]) {
		return nil, errors.New("releasekit: public pins mismatch")
	}
	key, err := parsePublic(documents[AttestationPublicFile])
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, pins, documents["pins.sig"]) {
		return nil, errors.New("releasekit: public pins signature mismatch")
	}
	return publicSummary(documents, fingerprint)
}
