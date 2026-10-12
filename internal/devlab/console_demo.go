package devlab

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

// ConsoleDemo describes the fixture-owned loopback HTTPS origin. It holds no
// credentials; the origin's private key never leaves this process.
type ConsoleDemo struct {
	// WebhookURL accepts and discards webhook deliveries.
	WebhookURL string
	// CAPEM is the origin's ephemeral certificate authority, for pinning.
	CAPEM string
}

type consoleDemoOrigin struct {
	server *http.Server
	done   chan error
}

func (o *consoleDemoOrigin) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := o.server.Shutdown(ctx)
	if serveErr := <-o.done; !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	return err
}

// ConfigureConsoleDemo enables real registry-derived vendor feeds through the
// revalidating cache, plus an owned webhook sink and assistance relay. Only the
// webhook uses the ephemeral CA. Call once, before enrolling demo devices.
func (f *AuthorityFixture) ConfigureConsoleDemo(ctx context.Context, advisories *configv1.AdvisoryConfig, cacheDir string) (*ConsoleDemo, error) {
	if f.closed || f.local == nil || f.ConsoleOrigin == consoleOrigin || f.demo != nil {
		return nil, errors.New("console demo requires one live dynamic local console fixture")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	if document.Proto.GetAdvisories() != nil || document.Proto.GetAssistance() != nil {
		return nil, errors.New("console demo advisories or assistance are already configured")
	}

	authority, certificate, err := consoleDemoCertificate()
	if err != nil {
		return nil, err
	}
	shared, err := os.ReadFile(filepath.Join(FixturePath(f.repository), "transport-ca.crt"))
	if err != nil {
		return nil, err
	}
	const trusted = "console-demo-trusted-ca.pem"
	if err := os.WriteFile(filepath.Join(f.directory, trusted), append(shared, authority...), 0600); err != nil {
		return nil, err
	}
	assistance, err := ReserveAssistanceRelay("127.0.0.1", "127.0.0.1")
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, errors.Join(errors.New("console demo origin is not TCP"), listener.Close())
	}
	origin := fmt.Sprintf("https://localhost:%d", address.Port)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20)); err != nil {
			http.Error(w, "unreadable delivery", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}}
	f.demo = &consoleDemoOrigin{server: server, done: make(chan error, 1)}
	go func() { f.demo.done <- server.ServeTLS(listener, "", "") }()
	document.Proto.Assistance, document.Proto.TrustedCaFile = assistance, trusted
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return nil, err
	}
	if err := f.writeConfig(encoded); err != nil {
		return nil, err
	}
	if err := f.Restart(ctx); err != nil {
		return nil, err
	}
	if err := f.EnableAdvisories(ctx, advisories, cacheDir); err != nil {
		return nil, err
	}
	return &ConsoleDemo{WebhookURL: origin + "/webhook", CAPEM: string(authority)}, nil
}

// consoleDemoCertificate returns a fresh CA PEM and a localhost leaf signed by
// it. Both private keys exist only in this process.
func consoleDemoCertificate() ([]byte, tls.Certificate, error) {
	var leaf tls.Certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, leaf, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, leaf, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lindm console demo origin CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, leaf, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, leaf, err
	}
	leaf = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), leaf, nil
}
