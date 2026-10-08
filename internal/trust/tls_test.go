package trust

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTLSMessageSignerAuthenticatesWithoutDigestOracle(t *testing.T) {
	key := testKey(t)
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	bridge, err := NewTLSMessageSigner(public, func(message []byte) ([]byte, error) { return SignTLSClientMessage(key, message) })
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(clientCertificateVerifyPrefix), make([]byte, 32)...)
	signature, err := bridge.SignMessage(rand.Reader, message, crypto.Hash(0))
	if err != nil || !ed25519.Verify(public, message, signature) {
		t.Fatalf("valid TLS message signature: %v", err)
	}
	for _, invalid := range [][]byte{
		[]byte("DSSEv1 1 x 1 y"),
		bytes.Replace(message, []byte("client"), []byte("server"), 1),
		message[:len(message)-1],
		append(bytes.Clone(message), 0),
		make([]byte, 32),
	} {
		if _, err := SignTLSClientMessage(key, invalid); err == nil {
			t.Fatal("accepted non-client-CertificateVerify authority")
		}
	}
	digest := sha256.Sum256(message)
	if _, err := bridge.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("accepted a digest-only signing oracle")
	}
	for _, opts := range []crypto.SignerOpts{crypto.SHA256, &ed25519.Options{Context: "renewal"}, (*ed25519.Options)(nil), nil} {
		if _, err := bridge.SignMessage(rand.Reader, message, opts); err == nil {
			t.Fatal("accepted forbidden signature options")
		}
	}

	// Exercise Go's real TLS 1.3 client path: it must upgrade crypto.Signer to
	// crypto.MessageSigner instead of invoking the forbidden digest entry point.
	now := time.Now()
	serverRootKey, clientRootKey := testKey(t), testKey(t)
	serverRoot := decodeCertificate(t, testCA(t, serverRootKey, now, x509.ExtKeyUsageServerAuth))
	clientRoot := decodeCertificate(t, testCA(t, clientRootKey, now, x509.ExtKeyUsageClientAuth))
	serverKey := testKey(t)
	serverLeaf := tlsLeaf(t, serverRoot, serverRootKey, serverKey, now, x509.ExtKeyUsageServerAuth)
	clientLeaf := tlsLeaf(t, clientRoot, clientRootKey, key, now, x509.ExtKeyUsageClientAuth)
	clientRoots, serverRoots := x509.NewCertPool(), x509.NewCertPool()
	clientRoots.AddCert(clientRoot)
	serverRoots.AddCert(serverRoot)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || r.TLS.VerifiedChains[0][0].Subject.CommonName != "authenticated-device" {
			http.Error(w, "unverified device", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{serverLeaf}, PrivateKey: serverKey}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: serverRoots, Certificates: []tls.Certificate{{Certificate: [][]byte{clientLeaf}, PrivateKey: bridge}}}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		t.Fatalf("device authentication failed: %d %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
}

func tlsLeaf(t *testing.T, ca *x509.Certificate, caKey, key ed25519.PrivateKey, now time.Time, usage x509.ExtKeyUsage) []byte {
	t.Helper()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "authenticated-device"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true}
	if usage == x509.ExtKeyUsageServerAuth {
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
