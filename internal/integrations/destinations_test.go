// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
)

func TestDestinationTrustRejectsPrivateMaterial(t *testing.T) {
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(receiver.Close)
	certificate := receiver.TLS.Certificates[0]
	public := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))
	privateDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	for _, value := range []string{private + public, public + private, "secret-before\n" + public, public + "secret-after", " \n"} {
		if err := validateTrust(&integrationsv1.DestinationConfig{Kind: integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK, Endpoint: receiver.URL, PinnedCaPem: value}); err == nil {
			t.Fatal("accepted private or unparsed bytes into public destination trust metadata")
		}
	}
	if err := validateTrust(&integrationsv1.DestinationConfig{Kind: integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK, Endpoint: receiver.URL, PinnedCaPem: public + public}); err != nil {
		t.Fatalf("valid certificate-only bundle rejected: %v", err)
	}
}

func TestCertificateSummariesIdentifyPinnedCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Date(2030, 5, 1, 12, 0, 0, 0, time.UTC)
	issue := func(subject pkix.Name) []byte {
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subject, NotBefore: notAfter.AddDate(-1, 0, 0), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	named := issue(pkix.Name{CommonName: "SOC receiver CA", Organization: []string{"Example"}})
	unnamed := issue(pkix.Name{Organization: []string{"Example"}, OrganizationalUnit: []string{"Security"}})
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: named})) + "\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unnamed}))
	summaries := certificateSummaries(bundle)
	if len(summaries) != 2 {
		t.Fatalf("summarized %d of 2 bundled certificates", len(summaries))
	}
	digest := sha256.Sum256(named)
	fingerprint := strings.ToUpper(hex.EncodeToString(digest[:]))
	var pairs []string
	for i := 0; i < len(fingerprint); i += 2 {
		pairs = append(pairs, fingerprint[i:i+2])
	}
	first := summaries[0]
	if first.Subject != "SOC receiver CA" || !first.NotAfter.AsTime().Equal(notAfter) || first.Sha256Fingerprint != strings.Join(pairs, ":") {
		t.Fatalf("named certificate summary %v", first)
	}
	if summaries[1].Subject != "OU=Security,O=Example" {
		t.Fatalf("certificate without a common name summarized as %q", summaries[1].Subject)
	}
	if certificateSummaries("") != nil {
		t.Fatal("summarized a destination without pinned trust")
	}
}
