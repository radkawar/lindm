// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"buf.build/go/protovalidate"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigstoredsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

const statementType = "application/vnd.in-toto+json"
const manifestType = "application/vnd.lindm.release.v1+json"

// AttestationKey requires deliberate custody and an independently pinned public
// identity. Production requires a separately authenticated inventory. Path uses
// an owned purpose sidecar; PrivateKeyPEM instead accepts an unlocked custody
// secret with an explicit Purpose. The two sources are mutually exclusive.
type AttestationKey struct {
	Path, KeyID, Custody, TrustInventory, TrustInventorySHA256 string
	PrivateKeyPEM                                              []byte
	Purpose                                                    string
}
type releaseSigner struct {
	signer     signature.SignerVerifier
	public     []byte
	private    ed25519.PrivateKey
	id         string
	exclusions *signingExclusions
}

func keyID(public crypto.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// GenerateDevelopmentKey creates a conspicuously marked, dedicated signing key.
// Production key material must instead be provisioned explicitly by its custodian.
func GenerateDevelopmentKey(directory string) (string, error) {
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", err
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := writeNew(filepath.Join(directory, "attestation.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return "", err
	}
	if err := writeNew(filepath.Join(directory, "attestation.pem.purpose"), []byte("development-release-attestation\n"), 0600); err != nil {
		return "", err
	}
	id, encoded, err := keyID(public)
	if err != nil {
		return "", err
	}
	return id, writeNew(filepath.Join(directory, "attestation.pub"), encoded, 0644)
}

func loadSigner(key AttestationKey) (*releaseSigner, error) {
	if key.Custody != "production" && key.Custody != "development" {
		return nil, errors.New("releasebuild: explicit signing custody required")
	}
	if (key.Path == "") == (len(key.PrivateKeyPEM) == 0) || (key.Path != "" && key.Purpose != "") {
		return nil, errors.New("releasebuild: exactly one signing key source required")
	}
	exclusions := &signingExclusions{}
	if key.Custody == "production" || key.TrustInventory != "" || key.TrustInventorySHA256 != "" {
		var err error
		exclusions, err = loadTrustInventory(key.TrustInventory, key.TrustInventorySHA256)
		if err != nil {
			return nil, fmt.Errorf("releasebuild: authenticated signing trust inventory required: %w", err)
		}
	}
	expected, err := normalizeSHA256(key.KeyID)
	if err != nil {
		return nil, err
	}
	data := key.PrivateKeyPEM
	if key.Path != "" {
		purpose, err := readProtected(key.Path+".purpose", 128)
		if err != nil {
			return nil, err
		}
		if string(purpose) != key.Custody+"-release-attestation\n" {
			return nil, errors.New("releasebuild: wrong signing purpose")
		}
		data, err = readProtected(key.Path, 16384)
		if err != nil {
			return nil, err
		}
		defer clear(data)
	} else if key.Custody != "production" || key.Purpose != "production-release-attestation" || len(data) > 16384 {
		return nil, errors.New("releasebuild: memory key requires bounded production release-attestation purpose")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("releasebuild: expected PKCS8 key only")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("releasebuild: dedicated Ed25519 key required")
	}
	retained := false
	defer func() {
		if !retained {
			clear(private)
		}
	}()
	id, public, err := keyID(private.Public())
	if err != nil {
		return nil, err
	}
	if id != expected || slices.Contains(exclusions.spki, id) {
		return nil, errors.New("releasebuild: unpinned or cross-domain signing key")
	}
	signer, err := signature.LoadSignerVerifier(private, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	retained = true
	return &releaseSigner{signer: signer, public: public, private: private, id: id, exclusions: exclusions}, nil
}

func (s *releaseSigner) close() {
	clear(s.private)
	s.private, s.signer = nil, nil
}

func readProtected(path string, limit int64) (data []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Getuid()) || info.Size() > limit {
		return nil, errors.New("releasebuild: key and purpose must be owned bounded mode-0600 regular files")
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("releasebuild: key exceeded bound")
	}
	return data, err
}

func (s *releaseSigner) sign(payload []byte, kind string) ([]byte, error) {
	if len(payload) > maxDocument {
		return nil, errors.New("releasebuild: signing document exceeds bound")
	}
	wrapped := sigstoredsse.WrapSignerVerifier(s.signer, kind)
	envelope, err := wrapped.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	if err := wrapped.VerifySignature(bytes.NewReader(envelope), nil); err != nil {
		return nil, err
	}
	return envelope, nil
}

func (s *releaseSigner) statement(artifact *releasev1.ReleaseArtifact, predicateType string, predicate any) ([]byte, error) {
	data, err := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": []any{map[string]any{"name": artifact.GetPath(), "digest": map[string]string{"sha256": artifact.GetSha256()}}}, "predicateType": predicateType, "predicate": predicate})
	if err != nil {
		return nil, err
	}
	return s.sign(data, statementType)
}

func verifyEnvelope(encoded []byte, kind string, verifier signature.Verifier) ([]byte, error) {
	if len(encoded) > maxDocument {
		return nil, errors.New("releasebuild: envelope exceeds bound")
	}
	var envelope dsse.Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, err
	}
	if envelope.PayloadType != kind || len(envelope.Signatures) != 1 {
		return nil, errors.New("releasebuild: wrong DSSE type or signature count")
	}
	if err := sigstoredsse.WrapVerifier(verifier).VerifySignature(bytes.NewReader(encoded), nil); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(envelope.Payload)
}

// Verify checks an exported release with an externally pinned attestation key;
// bundled public keys alone never establish authority. Native repository/TUF
// signatures remain independent checks, not implied by this verification.
func Verify(ctx context.Context, directory, publicKeyPath, expectedKeyID string) (*releasev1.ReleaseManifest, error) {
	normalized, err := normalizeSHA256(expectedKeyID)
	if err != nil {
		return nil, err
	}
	expectedKeyID = normalized
	publicPEM, err := readBounded(publicKeyPath, 16384)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("releasebuild: invalid public key")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	id, _, err := keyID(public)
	if err != nil {
		return nil, err
	}
	if id != expectedKeyID {
		return nil, errors.New("releasebuild: public key pin mismatch")
	}
	verifier, err := signature.LoadVerifier(public, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	envelope, err := readBounded(filepath.Join(directory, "release.json.dsse"), maxDocument)
	if err != nil {
		return nil, err
	}
	payload, err := verifyEnvelope(envelope, manifestType, verifier)
	if err != nil {
		return nil, err
	}
	document, err := readBounded(filepath.Join(directory, "release.json"), maxDocument)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(payload, document) {
		return nil, errors.New("releasebuild: manifest signature mismatch")
	}
	manifest, err := verifyManifestPayload(ctx, directory, payload, id)
	if err != nil {
		return nil, err
	}
	bundle, err := verifyEmbeddedRepository(ctx, directory, manifest, expectedKeyID)
	if err != nil {
		return nil, err
	}
	var bundleDigest string
	if bundle != "" {
		bundleDigest, err = treeDigest(bundle)
		if err != nil {
			return nil, err
		}
	}
	for _, build := range manifest.GetBuilds() {
		if build.GetSourceSha256() != manifest.GetSourceSha256() || len(build.GetUnsignedSha256()) != len(manifest.GetArtifacts()) {
			return nil, errors.New("releasebuild: inconsistent signed build observation")
		}
	}
	seen := map[string]bool{}
	for _, artifact := range manifest.GetArtifacts() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		names := []string{artifact.GetPath(), artifact.GetSbomPath(), artifact.GetProvenancePath(), artifact.GetSignaturePath()}
		// The detached OpenPGP signature authenticates itself against the
		// package signer; consumers (pacman, PublishArch, the agent) verify it.
		if artifact.GetNativeSignaturePath() != "" {
			names = append(names, artifact.GetNativeSignaturePath())
		}
		for _, name := range names {
			if filepath.Base(name) != name || name == "." || seen[name] {
				return nil, errors.New("releasebuild: unsafe or duplicate release path")
			}
			seen[name] = true
			info, err := os.Lstat(filepath.Join(directory, name))
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, errors.New("releasebuild: exported links forbidden")
			}
		}
		sum, size, err := digestFile(filepath.Join(directory, artifact.GetPath()))
		if err != nil {
			return nil, err
		}
		if sum != artifact.GetSha256() || size != artifact.GetSize() || artifact.GetUnsignedSha256() != artifact.GetSecondUnsignedSha256() {
			return nil, errors.New("releasebuild: artifact or reproducibility mismatch")
		}
		for _, build := range manifest.GetBuilds() {
			if build.GetUnsignedSha256()[artifact.GetPath()] != artifact.GetUnsignedSha256() {
				return nil, errors.New("releasebuild: build observation digest mismatch")
			}
		}
		sbomPredicate, provenancePredicate, err := verifyAttestations(directory, artifact, sum, verifier)
		if err != nil {
			return nil, err
		}
		if artifact.GetProduct() == "lindmd" {
			if err := verifyBundleProvenance(provenancePredicate, bundleDigest); err != nil {
				return nil, err
			}
		}
		if artifact.GetFormat() == "oci" {
			if err := verifyOCICA(filepath.Join(directory, artifact.GetPath()), artifact, sbomPredicate, provenancePredicate, bundleForProduct(artifact.GetProduct(), bundle)); err != nil {
				return nil, err
			}
		}
	}
	return manifest, nil
}

func verifyManifestPayload(ctx context.Context, directory string, payload []byte, expectedKeyID string) (*releasev1.ReleaseManifest, error) {
	manifest := new(releasev1.ReleaseManifest)
	if err := protojson.Unmarshal(payload, manifest); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(manifest); err != nil {
		return nil, err
	}
	if manifest.GetAttestationKeyId() != expectedKeyID {
		return nil, errors.New("releasebuild: manifest key mismatch")
	}
	if err := verifyLicenseFiles(ctx, directory, manifest.GetLicenseSha256()); err != nil {
		return nil, err
	}
	return manifest, nil
}

// verifyAttestations checks the artifact's SBOM, provenance and release
// signature statements against the pinned verifier and the artifact digest. It
// returns the SBOM and provenance predicates.
func verifyAttestations(directory string, artifact *releasev1.ReleaseArtifact, sum string, verifier signature.Verifier) (sbomPredicate, provenancePredicate json.RawMessage, err error) {
	for _, item := range []struct{ path, kind string }{{artifact.GetSbomPath(), "https://cyclonedx.org/bom"}, {artifact.GetProvenancePath(), "https://slsa.dev/provenance/v1"}, {artifact.GetSignaturePath(), "https://lindm.invalid/release/artifact/v1"}} {
		encoded, err := readBounded(filepath.Join(directory, item.path), maxDocument)
		if err != nil {
			return nil, nil, err
		}
		statement, err := verifyEnvelope(encoded, statementType, verifier)
		if err != nil {
			return nil, nil, err
		}
		var decoded struct {
			Type          string          `json:"_type"`
			PredicateType string          `json:"predicateType"`
			Predicate     json.RawMessage `json:"predicate"`
			Subject       []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
		}
		if err := json.Unmarshal(statement, &decoded); err != nil {
			return nil, nil, err
		}
		if decoded.Type != "https://in-toto.io/Statement/v1" || decoded.PredicateType != item.kind || len(decoded.Subject) != 1 || decoded.Subject[0].Name != artifact.GetPath() || decoded.Subject[0].Digest["sha256"] != sum {
			return nil, nil, fmt.Errorf("releasebuild: attestation subject/type mismatch: %s", item.path)
		}
		if item.path == artifact.GetSbomPath() {
			sbomPredicate = decoded.Predicate
		}
		if item.path == artifact.GetProvenancePath() {
			provenancePredicate = decoded.Predicate
		}
	}
	return sbomPredicate, provenancePredicate, nil
}
