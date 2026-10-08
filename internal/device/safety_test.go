package device

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	devicev1 "lindm/gen/lindm/device/v1"
)

func TestCSRRejectsAuthorityAndUnapprovedKeys(t *testing.T) {
	t.Parallel()
	if _, err := parseDeviceCSR(mustCSR(t, p256Key(t), &x509.CertificateRequest{})); err != nil {
		t.Fatalf("valid P-256 CSR: %v", err)
	}
	ed := mustCSR(t, ed25519Key(t), &x509.CertificateRequest{SignatureAlgorithm: x509.PureEd25519})
	if _, err := parseDeviceCSR(ed); err != nil {
		t.Fatalf("valid Ed25519 CSR: %v", err)
	}

	uri, err := url.Parse("urn:attacker:device")
	if err != nil {
		t.Fatal(err)
	}
	withSAN := mustCSR(t, p256Key(t), &x509.CertificateRequest{URIs: []*url.URL{uri}})
	if _, err := parseDeviceCSR(withSAN); !errors.Is(err, errCSRIdentity) {
		t.Fatalf("SAN CSR error = %v", err)
	}
	withSubject := mustCSR(t, p256Key(t), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "chosen-by-client"}})
	if _, err := parseDeviceCSR(withSubject); !errors.Is(err, errCSRIdentity) {
		t.Fatalf("subject CSR error = %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseDeviceCSR(mustCSR(t, p384, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA384})); !errors.Is(err, errCSRAlgorithm) {
		t.Fatalf("P-384 CSR error = %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseDeviceCSR(mustCSR(t, rsaKey, &x509.CertificateRequest{SignatureAlgorithm: x509.SHA256WithRSA})); !errors.Is(err, errCSRAlgorithm) {
		t.Fatalf("RSA CSR error = %v", err)
	}
	valid := mustCSR(t, p256Key(t), &x509.CertificateRequest{})
	valid[len(valid)-2] ^= 0xff
	if _, err := parseDeviceCSR(valid); err == nil {
		t.Fatal("tampered CSR was accepted")
	}
}

func TestIssuedCertificateIsServerIdentityOnly(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca, signer := testCA(t, now.Add(90*24*time.Hour))
	deployment, deviceID, generation := uuid.New(), uuid.New(), uuid.New()
	deviceKey := p256Key(t)
	uri, err := url.Parse("urn:attacker:keep-me-out")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseDeviceCSR(mustCSR(t, deviceKey, &x509.CertificateRequest{URIs: []*url.URL{uri}, Subject: pkix.Name{CommonName: "client"}})); err == nil {
		t.Fatal("authority-bearing CSR must not reach issuance")
	}
	issued, err := issueCertificate(ca, signer, &deviceKey.PublicKey, deployment, deviceID, generation, now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(issued.PEM, []byte("PRIVATE KEY")) {
		t.Fatal("issued PEM contains a private key")
	}
	cert := parseCertPEM(t, issued.PEM)
	if err := issuedIdentityOK(cert, deployment, deviceID, generation); err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName == "client" || len(cert.URIs) != 1 || cert.URIs[0].String() == uri.String() {
		t.Fatalf("client identity leaked into certificate: %s", cert.URIs)
	}
	if !cert.NotAfter.After(now.Add(29*24*time.Hour)) || cert.NotAfter.After(now.Add(certLifetime+time.Second)) {
		t.Fatalf("lifetime = %s", cert.NotAfter.Sub(now))
	}
	if cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 128 {
		t.Fatalf("serial = %s", cert.SerialNumber)
	}
	second, err := issueCertificate(ca, signer, &deviceKey.PublicKey, deployment, deviceID, generation, now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(issued.Serial, second.Serial) {
		t.Fatal("serial was not random")
	}
}

func TestCertificateLifetimeHonorsCAExpiry(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	caEnd := now.Add(10 * 24 * time.Hour)
	ca, signer := testCA(t, caEnd)
	deviceKey := p256Key(t)
	issued, err := issueCertificate(ca, signer, &deviceKey.PublicKey, uuid.New(), uuid.New(), uuid.New(), now)
	if err != nil {
		t.Fatal(err)
	}
	if issued.NotAfter.After(ca.NotAfter) {
		t.Fatalf("issued %s after CA %s", issued.NotAfter, ca.NotAfter)
	}
	if issued.NotAfter.Before(now.Add(9 * 24 * time.Hour)) {
		t.Fatalf("issued %s ignored remaining CA life", issued.NotAfter)
	}
}

func TestOverlapIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	if got := overlapUntil(now, now.Add(30*24*time.Hour)); !got.Equal(now.Add(renewalOverlap)) {
		t.Fatalf("overlap = %s", got.Sub(now))
	}
	soon := now.Add(5 * time.Minute)
	if got := overlapUntil(now, soon); !got.Equal(soon) {
		t.Fatalf("short cert overlap = %s", got)
	}
}

func TestInventoryDigestDetectsChangedContent(t *testing.T) {
	t.Parallel()
	base := &devicev1.ReportInventoryRequest{
		EnrollmentGeneration: uuid.NewString(),
		BootId:               uuid.NewString(),
		Sequence:             2,
		Hostname:             "host",
		OsId:                 "debian",
		OsVersion:            "12",
		Architecture:         "amd64",
		PackagesComplete:     true,
		Packages:             []*devicev1.Package{{Name: "openssh", Version: "1:9.2p1-2", Architecture: "amd64", Manager: "apt"}},
	}
	same := &devicev1.ReportInventoryRequest{
		EnrollmentGeneration: base.EnrollmentGeneration,
		BootId:               base.BootId,
		Sequence:             base.Sequence,
		Hostname:             base.Hostname,
		OsId:                 base.OsId,
		OsVersion:            base.OsVersion,
		Architecture:         base.Architecture,
		PackagesComplete:     true,
		Packages:             []*devicev1.Package{{Name: "openssh", Version: "1:9.2p1-2", Architecture: "amd64", Manager: "apt"}},
	}
	changed := &devicev1.ReportInventoryRequest{
		EnrollmentGeneration: base.EnrollmentGeneration,
		BootId:               base.BootId,
		Sequence:             base.Sequence,
		Hostname:             "other",
		OsId:                 base.OsId,
		OsVersion:            base.OsVersion,
		Architecture:         base.Architecture,
		PackagesComplete:     true,
		Packages:             same.Packages,
	}
	if !bytes.Equal(inventoryDigest(base), inventoryDigest(same)) {
		t.Fatal("identical observations produced different digests")
	}
	if bytes.Equal(inventoryDigest(base), inventoryDigest(changed)) {
		t.Fatal("changed hostname did not change digest")
	}
}

func TestGrantHashIsNotTheSecret(t *testing.T) {
	t.Parallel()
	secret, hash, err := newGrantSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 32 || len(secret) > 256 || len(hash) != 32 || bytes.Equal(hash, []byte(secret)) {
		t.Fatal("grant secret was not hashed")
	}
}

func TestCursorRejectsGarbage(t *testing.T) {
	t.Parallel()
	when := time.Date(2026, 10, 8, 1, 2, 3, 4000, time.UTC)
	id := uuid.New()
	token, err := encodeCursor(when, id)
	if err != nil {
		t.Fatal(err)
	}
	gotWhen, gotID, err := decodeCursor(token)
	if err != nil || !gotWhen.Equal(when.Truncate(time.Microsecond)) || gotID != id {
		t.Fatalf("round trip %s %s %v", gotWhen, gotID, err)
	}
	if _, _, err := decodeCursor("not-a-cursor"); err == nil {
		t.Fatal("garbage cursor accepted")
	}
}

func testCA(t *testing.T, notAfter time.Time) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "lindm-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func ed25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustCSR(t *testing.T, key crypto.Signer, template *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parseCertPEM(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("certificate PEM missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
