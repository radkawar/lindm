package recoveryboot

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/pkcs7"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Authenticode verification replaces `sbverify --cert`, which EL distributions
// do not ship. go-uefi supplies the PE/COFF Authenticode hash and the PKCS#7
// and SpcIndirectDataContent parsers; it does not by itself bind the signed
// messageDigest attribute to the signed content, require authenticated
// attributes, or bound the certificate table. Every predicate below is
// therefore enforced here before a signature is accepted. The only
// cryptographic primitives used are SHA-256 and crypto/x509's RSA check.
const (
	maxAuthenticodeImageBytes       = 1 << 30
	maxAuthenticodeCertificateBytes = 1 << 20
	maxAuthenticodeTableBytes       = 1 << 20
	winCertificateHeaderBytes       = 8
	winCertificateRevision          = 0x0200
	winCertificateTypePKCSSigned    = 0x0002
)

var (
	errAuthenticode         = errors.New("recoveryboot: authenticode_invalid")
	errAuthenticodeUnsigned = errors.New("recoveryboot: authenticode_unsigned")
	oidRSASHA256            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// verifyAuthenticode verifies the image's single Authenticode signature with
// exactly the pinned PEM certificate as signer. Like UEFI and sbverify, it
// does not evaluate certificate validity time.
func verifyAuthenticode(imagePath, certificatePath string) error {
	certificate, err := readSignerCertificate(certificatePath)
	if err != nil {
		return err
	}
	image, err := os.OpenFile(imagePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = image.Close() }()
	info, err := image.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxAuthenticodeImageBytes {
		return errAuthenticode
	}
	return verifyAuthenticodeImage(image, info.Size(), certificate)
}

func readSignerCertificate(name string) (*x509.Certificate, error) {
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAuthenticodeCertificateBytes+1))
	if err = errors.Join(err, file.Close()); err != nil {
		return nil, err
	}
	if len(data) > maxAuthenticodeCertificateBytes {
		return nil, errAuthenticode
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("recoveryboot: signer_certificate_invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("recoveryboot: signer_certificate_invalid: %w", err)
	}
	return certificate, nil
}

// verifyAuthenticodeImage contains third-party parser panics as verification
// failures; a malformed image must never terminate the verifying process.
func verifyAuthenticodeImage(image io.ReaderAt, size int64, certificate *x509.Certificate) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errAuthenticode
		}
	}()
	reader := io.NewSectionReader(image, 0, size)
	if err := validateCertificateTable(reader, size); err != nil {
		return err
	}
	binary, err := authenticode.Parse(reader)
	if err != nil {
		return errAuthenticode
	}
	signatures, err := binary.Signatures()
	if err != nil || len(signatures) != 1 || signatures[0].CertType != winCertificateTypePKCSSigned {
		return errAuthenticode
	}
	signed, err := authenticode.ParseAuthenticode(signatures[0].Certificate)
	if err != nil || !signed.Algid.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256) || len(signed.Digest) != sha256.Size {
		return errAuthenticode
	}
	if !bytes.Equal(binary.Hash(crypto.SHA256), signed.Digest) {
		return errAuthenticode
	}
	return verifySignedContent(signed.Pkcs, certificate)
}

// validateCertificateTable requires one 8-byte-aligned attribute certificate
// table at end of file, after headers and all section data, holding exactly one
// PKCS#7 WIN_CERTIFICATE with zero padding. No trailing data is accepted.
func validateCertificateTable(image *io.SectionReader, size int64) error {
	file, err := pe.NewFile(image)
	if err != nil {
		return errAuthenticode
	}
	var directory pe.DataDirectory
	var headers uint32
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if header.NumberOfRvaAndSizes <= pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			return errAuthenticodeUnsigned
		}
		directory, headers = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY], header.SizeOfHeaders
	case *pe.OptionalHeader32:
		if header.NumberOfRvaAndSizes <= pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			return errAuthenticodeUnsigned
		}
		directory, headers = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY], header.SizeOfHeaders
	default:
		return errAuthenticode
	}
	if directory.VirtualAddress == 0 && directory.Size == 0 {
		return errAuthenticodeUnsigned
	}
	start, length := int64(directory.VirtualAddress), int64(directory.Size)
	if start == 0 || length < winCertificateHeaderBytes || length > maxAuthenticodeTableBytes || start%8 != 0 || length%8 != 0 || start+length != size {
		return errAuthenticode
	}
	end := int64(headers)
	for _, section := range file.Sections {
		if section.Size != 0 {
			end = max(end, int64(section.Offset)+int64(section.Size))
		}
	}
	if end > start {
		return errAuthenticode
	}
	table := make([]byte, length)
	if _, err := image.ReadAt(table, start); err != nil {
		return errAuthenticode
	}
	entry := int64(binary.LittleEndian.Uint32(table))
	if entry <= winCertificateHeaderBytes || entry > length || (entry+7)&^7 != length ||
		binary.LittleEndian.Uint16(table[4:]) != winCertificateRevision || binary.LittleEndian.Uint16(table[6:]) != winCertificateTypePKCSSigned {
		return errAuthenticode
	}
	for _, padding := range table[entry:] {
		if padding != 0 {
			return errAuthenticode
		}
	}
	return nil
}

// verifySignedContent enforces the PKCS#7 predicates that the parser leaves
// unchecked: one signer equal to the pinned certificate, SHA-256 digesting,
// authenticated contentType and messageDigest bound to the exact signed
// SpcIndirectDataContent, then the RSA signature over those attributes.
func verifySignedContent(signed *pkcs7.PKCS7, certificate *x509.Certificate) error {
	if signed == nil || !signed.OID.Equal(authenticode.OIDSpcIndirectDataContent) || len(signed.SignerInfo) != 1 {
		return errAuthenticode
	}
	signer := signed.SignerInfo[0]
	if signer.IssuerAndSerialnumber == nil || !bytes.Equal(signer.IssuerAndSerialnumber.RawIssuer, certificate.RawIssuer) ||
		signer.IssuerAndSerialnumber.SerialNumber == nil || signer.IssuerAndSerialnumber.SerialNumber.Cmp(certificate.SerialNumber) != 0 {
		return errAuthenticode
	}
	if signer.DigestAlgorithm == nil || !signer.DigestAlgorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256) ||
		signer.EncryptedDigestAlgorithm == nil || (!signer.EncryptedDigestAlgorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSA) && !signer.EncryptedDigestAlgorithm.Algorithm.Equal(oidRSASHA256)) {
		return errAuthenticode
	}
	attributes := signer.AuthenticatedAttributes
	if attributes == nil || !attributes.ContentType.Equal(authenticode.OIDSpcIndirectDataContent) || len(attributes.MessageDigest) != sha256.Size {
		return errAuthenticode
	}
	// Authenticode digests the SpcIndirectDataContent value octets, excluding
	// the outer SEQUENCE tag and length.
	content := cryptobyte.String(signed.ContentInfo)
	var value cryptobyte.String
	if !content.ReadASN1(&value, cbasn1.SEQUENCE) || !content.Empty() {
		return errAuthenticode
	}
	digest := sha256.Sum256(value)
	if !bytes.Equal(digest[:], attributes.MessageDigest) {
		return errAuthenticode
	}
	if err := certificate.CheckSignature(x509.SHA256WithRSA, attributes.RawBytes, signer.EncryptedDigest); err != nil {
		return errAuthenticode
	}
	return nil
}
