// SPDX-License-Identifier: Apache-2.0

package offlinebundle

import (
	"bytes"
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
	"regexp"
	"syscall"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigstoredsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

const (
	payloadType     = "application/vnd.lindm.offline-bundle.v1+json"
	maxKeyBytes     = 16 << 10
	maxManifestSize = 32 << 20
)

var keyIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// SigningKey is explicit bundle-signing custody: a mode-0600 PKCS#8 Ed25519
// key with a "<custody>-offline-bundle-signing" purpose sidecar and an
// independently pinned SPKI SHA-256. It is never a release-attestation,
// package, TUF, execution or TLS key.
type SigningKey struct{ Path, KeyID, Custody string }

type bundleSigner struct {
	signer  signature.SignerVerifier
	id      string
	custody string
}

// KeyID returns the SHA-256 of the public key's SubjectPublicKeyInfo DER and
// its PEM encoding.
func KeyID(public crypto.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// GenerateDevelopmentKey creates a conspicuously development-only bundle key in
// a new directory. Production custody is provisioned by its custodian.
func GenerateDevelopmentKey(directory string) (string, error) {
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(encoded)
	if err := writeNewFile(filepath.Join(directory, "bundle.pem"), encoded, 0600); err != nil {
		return "", err
	}
	if err := writeNewFile(filepath.Join(directory, "bundle.pem.purpose"), []byte("development-offline-bundle-signing\n"), 0600); err != nil {
		return "", err
	}
	id, publicPEM, err := KeyID(public)
	if err != nil {
		return "", err
	}
	return id, writeNewFile(filepath.Join(directory, "bundle.pub"), publicPEM, 0644)
}

func loadSigningKey(key SigningKey) (*bundleSigner, error) {
	if key.Custody != "production" && key.Custody != "development" {
		return nil, errors.New("offlinebundle: explicit signing custody required")
	}
	if !keyIDPattern.MatchString(key.KeyID) {
		return nil, errors.New("offlinebundle: pinned lowercase SHA-256 key ID required")
	}
	purpose, err := readOwnedPrivate(key.Path+".purpose", 128)
	if err != nil {
		return nil, err
	}
	if string(purpose) != key.Custody+"-offline-bundle-signing\n" {
		return nil, errors.New("offlinebundle: wrong signing key purpose")
	}
	data, err := readOwnedPrivate(key.Path, maxKeyBytes)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("offlinebundle: expected one PKCS#8 private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("offlinebundle: dedicated Ed25519 key required")
	}
	id, _, err := KeyID(private.Public())
	if err != nil {
		return nil, err
	}
	if id != key.KeyID {
		return nil, errors.New("offlinebundle: signing key does not match its pinned ID")
	}
	signer, err := signature.LoadSignerVerifier(private, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return &bundleSigner{signer: signer, id: id, custody: key.Custody}, nil
}

func (s *bundleSigner) sign(payload []byte) ([]byte, error) {
	if len(payload) > maxManifestSize {
		return nil, errors.New("offlinebundle: manifest exceeds bound")
	}
	wrapped := sigstoredsse.WrapSignerVerifier(s.signer, payloadType)
	envelope, err := wrapped.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	if err := wrapped.VerifySignature(bytes.NewReader(envelope), nil); err != nil {
		return nil, err
	}
	return envelope, nil
}

// Verifier is an independently pinned bundle-signing public key.
type Verifier struct {
	verifier signature.Verifier
	id       string
}

// LoadVerifier reads a PEM SubjectPublicKeyInfo and requires it to match the
// separately pinned key ID. A public key shipped inside a bundle is never used.
func LoadVerifier(path, keyID string) (*Verifier, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, errors.New("offlinebundle: pinned lowercase SHA-256 key ID required")
	}
	data, err := readBoundedRegular(path, maxKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read bundle public key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("offlinebundle: expected one PEM public key")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if _, ok := public.(ed25519.PublicKey); !ok {
		return nil, errors.New("offlinebundle: Ed25519 bundle key required")
	}
	id, _, err := KeyID(public)
	if err != nil {
		return nil, err
	}
	if id != keyID {
		return nil, errors.New("offlinebundle: public key does not match its pinned ID")
	}
	verifier, err := signature.LoadVerifier(public, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return &Verifier{verifier: verifier, id: id}, nil
}

// open verifies exactly one DSSE signature of the bundle payload type and
// returns the authenticated payload bytes.
func (v *Verifier) open(encoded []byte) ([]byte, error) {
	if len(encoded) > 2*maxManifestSize {
		return nil, errors.New("offlinebundle: envelope exceeds bound")
	}
	var envelope dsse.Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode bundle envelope: %w", err)
	}
	if envelope.PayloadType != payloadType || len(envelope.Signatures) != 1 {
		return nil, errors.New("offlinebundle: wrong envelope type or signature count")
	}
	if err := sigstoredsse.WrapVerifier(v.verifier).VerifySignature(bytes.NewReader(encoded), nil); err != nil {
		return nil, fmt.Errorf("offlinebundle: bundle signature rejected: %w", err)
	}
	return base64.StdEncoding.DecodeString(envelope.Payload)
}

func readOwnedPrivate(path string, limit int64) (data []byte, err error) {
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
		return nil, errors.New("offlinebundle: key and purpose must be owned bounded mode-0600 regular files")
	}
	return readLimited(f, limit)
}

func readBoundedRegular(path string, limit int64) (data []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("offlinebundle: bounded regular file required")
	}
	return readLimited(f, limit)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("offlinebundle: input exceeds bound")
	}
	return data, nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	return f.Sync()
}
