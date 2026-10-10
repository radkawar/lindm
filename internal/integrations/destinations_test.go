package integrations

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

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
