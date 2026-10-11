package measuredboot

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

const (
	maxPublicBytes    = 1024
	maxQuoteBytes     = 2048
	maxSignatureBytes = 1024
	p256Bytes         = 32
)

// ErrRejected is wrapped by every Verify and VerifyQuoteSignature failure.
var ErrRejected = errors.New("recovery_attestation_rejected")

var (
	errAttestationKeyEncoding   = errors.New("measuredboot: attestation_key_encoding")
	errAttestationKeyType       = errors.New("measuredboot: attestation_key_type")
	errAttestationKeyAttributes = errors.New("measuredboot: attestation_key_attributes")
	errAttestationKeyPolicy     = errors.New("measuredboot: attestation_key_policy")
	errAttestationKeyParameters = errors.New("measuredboot: attestation_key_parameters")
	errAttestationKeyPoint      = errors.New("measuredboot: attestation_key_point")
)

// AttestationKeyTemplate returns the restricted ECDSA P-256/SHA-256 signing
// key template for the recovery attestation key. Unique is left empty.
func AttestationKeyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

// ValidateAttestationKey parses a marshaled TPMT_PUBLIC and returns its key
// only if it is exactly AttestationKeyTemplate with a valid P-256 point.
func ValidateAttestationKey(public []byte) (*ecdsa.PublicKey, error) {
	if len(public) > maxPublicBytes {
		return nil, errAttestationKeyEncoding
	}
	parsed, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return nil, errAttestationKeyEncoding
	}
	template := AttestationKeyTemplate()
	if parsed.Type != template.Type || parsed.NameAlg != template.NameAlg {
		return nil, errAttestationKeyType
	}
	if !bytes.Equal(tpm2.Marshal(parsed.ObjectAttributes), tpm2.Marshal(template.ObjectAttributes)) {
		return nil, errAttestationKeyAttributes
	}
	if len(parsed.AuthPolicy.Buffer) != 0 {
		return nil, errAttestationKeyPolicy
	}
	parameters, err := parsed.Parameters.ECCDetail()
	if err != nil {
		return nil, errAttestationKeyParameters
	}
	templateParameters, err := template.Parameters.ECCDetail()
	if err != nil || !bytes.Equal(tpm2.Marshal(*parameters), tpm2.Marshal(*templateParameters)) {
		return nil, errAttestationKeyParameters
	}
	point, err := parsed.Unique.ECC()
	if err != nil || len(point.X.Buffer) != p256Bytes || len(point.Y.Buffer) != p256Bytes {
		return nil, errAttestationKeyPoint
	}
	// Reject trailing or non-canonical bytes: the input must be exactly the
	// template carrying this point.
	template.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, point)
	if !bytes.Equal(tpm2.Marshal(template), public) {
		return nil, errAttestationKeyEncoding
	}
	uncompressed := make([]byte, 0, 1+2*p256Bytes)
	uncompressed = append(uncompressed, 4)
	uncompressed = append(uncompressed, point.X.Buffer...)
	uncompressed = append(uncompressed, point.Y.Buffer...)
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, errAttestationKeyPoint
	}
	return key, nil
}

// VerifyQuoteSignature verifies that signature, a marshaled TPMT_SIGNATURE, is
// an ECDSA/SHA-256 signature by the attestation key public over the marshaled
// TPMS_ATTEST quote. It does not check the quote contents.
func VerifyQuoteSignature(public, quote, signature []byte) error {
	key, err := ValidateAttestationKey(public)
	if err != nil {
		return rejected("attestation_key", err)
	}
	return verifyQuoteSignature(key, quote, signature)
}

func verifyQuoteSignature(key *ecdsa.PublicKey, quote, signature []byte) error {
	if len(quote) > maxQuoteBytes || len(signature) > maxSignatureBytes {
		return rejected("quote_signature", nil)
	}
	parsed, err := tpm2.Unmarshal[tpm2.TPMTSignature](signature)
	if err != nil || parsed.SigAlg != tpm2.TPMAlgECDSA || !bytes.Equal(tpm2.Marshal(*parsed), signature) {
		return rejected("quote_signature", err)
	}
	ecc, err := parsed.Signature.ECDSA()
	if err != nil || ecc.Hash != tpm2.TPMAlgSHA256 || len(ecc.SignatureR.Buffer) > p256Bytes || len(ecc.SignatureS.Buffer) > p256Bytes {
		return rejected("quote_signature", err)
	}
	digest := sha256.Sum256(quote)
	r := new(big.Int).SetBytes(ecc.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecc.SignatureS.Buffer)
	if !ecdsa.Verify(key, digest[:], r, s) {
		return rejected("quote_signature", nil)
	}
	return nil
}

// Expected is the server-side expectation for one measured recovery boot.
type Expected struct {
	AttestationKeyPublic []byte
	QualifyingData       []byte
	KernelSHA256         []byte
	InitrdSHA256         []byte
	KernelPath           string
	InitrdPath           string
	KernelOptions        string
}

// Evidence is what the recovery submits: the marshaled TPMS_ATTEST exactly as
// signed, the marshaled TPMT_SIGNATURE and the raw TCG event log.
type Evidence struct {
	Quote     []byte
	Signature []byte
	EventLog  []byte
}

// Verify admits a measured recovery boot only if the quote is signed by the
// expected attestation key over the expected qualifying data and the SHA-256
// digest of PCRs 4, 7, 8 and 9 replayed from the event log, Secure Boot is
// enabled, and the final GRUB boot loaded exactly the expected kernel, options
// and initramfs. Every error wraps ErrRejected.
func Verify(expected Expected, evidence Evidence) error {
	key, err := ValidateAttestationKey(expected.AttestationKeyPublic)
	if err != nil {
		return rejected("attestation_key", err)
	}
	if len(expected.QualifyingData) != sha256.Size || len(expected.KernelSHA256) != sha256.Size || len(expected.InitrdSHA256) != sha256.Size ||
		expected.KernelPath == "" || expected.InitrdPath == "" || expected.KernelOptions == "" {
		return rejected("expected_invalid", nil)
	}
	if err := verifyQuoteSignature(key, evidence.Quote, evidence.Signature); err != nil {
		return err
	}
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](evidence.Quote)
	if err != nil || !bytes.Equal(tpm2.Marshal(*attest), evidence.Quote) {
		return rejected("quote_encoding", err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue || attest.Type != tpm2.TPMSTAttestQuote {
		return rejected("quote_type", nil)
	}
	if subtle.ConstantTimeCompare(attest.ExtraData.Buffer, expected.QualifyingData) != 1 {
		return rejected("quote_qualifying_data", nil)
	}
	info, err := attest.Attested.Quote()
	if err != nil {
		return rejected("quote_type", err)
	}
	if !bytes.Equal(tpm2.Marshal(info.PCRSelect), tpm2.Marshal(quoteSelection())) {
		return rejected("quote_pcr_selection", nil)
	}
	events, err := ParseEventLog(evidence.EventLog)
	if err != nil {
		return rejected("event_log", err)
	}
	pcrs, err := Replay(events, QuotePCRs[:])
	if err != nil {
		return rejected("event_log_replay", err)
	}
	h := sha256.New()
	for _, pcr := range QuotePCRs {
		value := pcrs[pcr]
		h.Write(value[:])
	}
	if !bytes.Equal(info.PCRDigest.Buffer, h.Sum(nil)) {
		return rejected("quote_pcr_digest", nil)
	}
	if err := SecureBootEnabled(events); err != nil {
		return rejected("secure_boot", err)
	}
	loaded, err := FinalGRUBBoot(events)
	if err != nil {
		return rejected("grub_boot", err)
	}
	switch {
	case loaded.KernelPath != expected.KernelPath:
		return rejected("kernel_path", nil)
	case !bytes.Equal(loaded.KernelSHA256, expected.KernelSHA256):
		return rejected("kernel_digest", nil)
	case loaded.KernelOptions != expected.KernelOptions:
		return rejected("kernel_options", nil)
	case loaded.InitrdPath != expected.InitrdPath:
		return rejected("initrd_path", nil)
	case !bytes.Equal(loaded.InitrdSHA256, expected.InitrdSHA256):
		return rejected("initrd_digest", nil)
	}
	return nil
}

// quoteSelection is the single SHA-256 selection of QuotePCRs with a 3-octet
// (PCR 0-23) select bitmap.
func quoteSelection() tpm2.TPMLPCRSelection {
	bitmap := make([]byte, 3)
	for _, pcr := range QuotePCRs {
		bitmap[pcr/8] |= 1 << (pcr % 8)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: bitmap}}}
}

func rejected(reason string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrRejected, reason)
	}
	return fmt.Errorf("%w: %s: %w", ErrRejected, reason, err)
}
