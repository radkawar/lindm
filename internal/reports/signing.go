package reports

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
)

const manifestDomain = "lindm-report-manifest-v1\x00"
const auditDomain = "lindm-audit-v1\x00"

func signingAlgorithm(key crypto.PublicKey) (string, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return "", errors.New("reports: RSA key must be at least 2048 bits")
		}
		return "RSA-PSS-SHA256", nil
	case *ecdsa.PublicKey:
		return "ECDSA-SHA256", nil
	case ed25519.PublicKey:
		return "Ed25519", nil
	default:
		return "", errors.New("reports: unsupported signing key")
	}
}

func (s *Service) signManifest(manifest *integrationsv1.ReportManifest) ([]byte, error) {
	manifest.Version = 1
	manifest.SignatureAlgorithm = s.algorithm
	manifest.PublicKeySha256 = s.fingerprint[:]
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode report manifest: %w", err)
	}
	message := append([]byte(manifestDomain), encoded...)
	var options crypto.SignerOpts = crypto.Hash(0)
	if s.algorithm != "Ed25519" {
		digest := sha256.Sum256(message)
		message = digest[:]
		options = crypto.SHA256
		if s.algorithm == "RSA-PSS-SHA256" {
			options = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		}
	}
	s.signMu.Lock()
	signature, err := s.signer.Sign(rand.Reader, message, options)
	s.signMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("sign report manifest: %w", err)
	}
	return proto.Marshal(&integrationsv1.ReportSignedManifest{
		Manifest: encoded, Signature: signature, PublicKeyDer: s.publicKey, CertificateDer: s.certificates,
	})
}

// VerifyReportArtifact checks an archive without a database or server connection.
// The SPKI SHA-256 pin must come from a separate trusted channel. For incremental
// audit exports pass the previous verified manifest to reject missing prefixes or
// cross-chain substitution. A nil checkpoint accepts only the all-zero genesis.
// TLS key rotation requires independently approving a new pin; an embedded key or
// certificate never grants trust. Retain old pins alongside their signed archives.
// Audit selections authenticate the server's signed selection and individual
// original rows, not chain continuity or independent completeness. They cannot
// consume or produce a continuation checkpoint.
func VerifyReportArtifact(reader io.Reader, signed *integrationsv1.ReportSignedManifest, pin []byte, checkpoint *integrationsv1.ReportManifest) (*integrationsv1.ReportManifest, error) {
	if signed == nil || len(pin) != sha256.Size {
		return nil, errors.New("reports: trusted signing pin required")
	}
	fingerprint := sha256.Sum256(signed.GetPublicKeyDer())
	if !bytes.Equal(pin, fingerprint[:]) {
		return nil, errors.New("reports: signing pin mismatch")
	}
	key, err := x509.ParsePKIXPublicKey(signed.GetPublicKeyDer())
	if err != nil {
		return nil, fmt.Errorf("parse archive public key: %w", err)
	}
	manifest := &integrationsv1.ReportManifest{}
	if err := proto.Unmarshal(signed.GetManifest(), manifest); err != nil {
		return nil, fmt.Errorf("decode archive manifest: %w", err)
	}
	algorithm, err := signingAlgorithm(key)
	if err != nil || manifest.GetVersion() != 1 || manifest.GetSignatureAlgorithm() != algorithm || !bytes.Equal(manifest.GetPublicKeySha256(), pin) {
		return nil, errors.New("reports: unsupported or inconsistent manifest")
	}
	message := append([]byte(manifestDomain), signed.GetManifest()...)
	digest := sha256.Sum256(message)
	valid := false
	switch public := key.(type) {
	case ed25519.PublicKey:
		valid = ed25519.Verify(public, message, signed.GetSignature())
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(public, digest[:], signed.GetSignature())
	case *rsa.PublicKey:
		valid = rsa.VerifyPSS(public, crypto.SHA256, digest[:], signed.GetSignature(), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) == nil
	}
	if !valid {
		return nil, errors.New("reports: invalid archive signature")
	}
	if manifest.GetByteCount() > maxArtifactBytes || manifest.GetRowCount() > maxReportRows {
		return nil, errors.New("reports: archive exceeds supported bounds")
	}
	limited := &io.LimitedReader{R: reader, N: int64(manifest.GetByteCount()) + 1}
	hash := sha256.New()
	stream := io.TeeReader(limited, hash)
	switch manifest.GetKind() {
	case integrationsv1.ReportKind_REPORT_KIND_AUDIT:
		if manifest.GetAuditFilter() != nil {
			return nil, errors.New("reports: selection is not an audit checkpoint")
		}
		if err := verifyAuditRows(stream, manifest, checkpoint); err != nil {
			return nil, err
		}
	case integrationsv1.ReportKind_REPORT_KIND_AUDIT_SELECTION:
		if checkpoint != nil {
			return nil, errors.New("reports: selection cannot consume an audit checkpoint")
		}
		if err := verifyAuditSelection(stream, manifest); err != nil {
			return nil, err
		}
	case integrationsv1.ReportKind_REPORT_KIND_INVENTORY, integrationsv1.ReportKind_REPORT_KIND_COMPLIANCE, integrationsv1.ReportKind_REPORT_KIND_FINDINGS:
		if _, err := io.Copy(io.Discard, stream); err != nil {
			return nil, fmt.Errorf("read report archive: %w", err)
		}
	default:
		return nil, errors.New("reports: unsupported report kind")
	}
	if limited.N != 1 || !bytes.Equal(hash.Sum(nil), manifest.GetContentSha256()) {
		return nil, errors.New("reports: archive length or digest mismatch")
	}
	return manifest, nil
}

func verifyAuditRows(reader io.Reader, manifest, checkpoint *integrationsv1.ReportManifest) error {
	chain, err := uuid.Parse(manifest.GetChainId())
	if err != nil || manifest.GetFormat() != integrationsv1.ReportFormat_REPORT_FORMAT_JSONL || len(manifest.GetAfterHash()) != sha256.Size || len(manifest.GetFinalHash()) != sha256.Size {
		return errors.New("reports: invalid audit chain metadata")
	}
	sequence, previous := manifest.GetAfterSequence(), manifest.GetAfterHash()
	if checkpoint == nil {
		if sequence != 0 || !bytes.Equal(previous, make([]byte, sha256.Size)) {
			return errors.New("reports: audit genesis checkpoint required")
		}
	} else if checkpoint.GetKind() != integrationsv1.ReportKind_REPORT_KIND_AUDIT || checkpoint.GetChainId() != manifest.GetChainId() || checkpoint.GetFinalSequence() != sequence || !bytes.Equal(checkpoint.GetFinalHash(), previous) {
		return errors.New("reports: audit checkpoint discontinuity")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 32*1024), 64*1024)
	var rows uint64
	for scanner.Scan() {
		record := &integrationsv1.AuditChainRecord{}
		if err := protojson.Unmarshal(scanner.Bytes(), record); err != nil {
			return fmt.Errorf("decode audit row: %w", err)
		}
		if record.GetSequence() != sequence+1 || !bytes.Equal(record.GetPreviousHash(), previous) {
			return errors.New("reports: audit row discontinuity")
		}
		hash := sha256.New()
		_, _ = hash.Write([]byte(auditDomain))
		_, _ = hash.Write(chain[:])
		var bigEndian [8]byte
		binary.BigEndian.PutUint64(bigEndian[:], record.GetSequence())
		_, _ = hash.Write(bigEndian[:])
		_, _ = hash.Write(previous)
		// Authenticate the complete stored JSON, including target_device_id and
		// details. Never rebuild these bytes from a parsed display projection.
		_, _ = hash.Write(record.GetPayload())
		if !bytes.Equal(hash.Sum(nil), record.GetRowHash()) {
			return errors.New("reports: audit row hash mismatch")
		}
		sequence, previous = record.GetSequence(), record.GetRowHash()
		rows++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read audit archive: %w", err)
	}
	if rows != manifest.GetRowCount() || sequence != manifest.GetFinalSequence() || !bytes.Equal(previous, manifest.GetFinalHash()) || sequence > manifest.GetCapturedHeadSequence() || (sequence == manifest.GetCapturedHeadSequence() && !bytes.Equal(previous, manifest.GetCapturedHeadHash())) {
		return errors.New("reports: audit final checkpoint mismatch")
	}
	return nil
}
