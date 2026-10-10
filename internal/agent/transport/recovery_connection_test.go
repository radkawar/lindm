package transport

import (
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/gen/lindm/recovery/v1/recoveryv1connect"
)

func TestRecoveryConnectionPinsTLSWithoutOrdinaryIdentity(t *testing.T) {
	var seen atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seen.Store(true)
		if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) != 0 {
			t.Error("recovery transport supplied an ordinary client certificate or weakened TLS")
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.URL.Path != recoveryv1connect.RecoveryServiceAcquireRecoveryWorkProcedure {
			t.Error("recovery client escaped its proof-only service")
		}
		http.Error(w, "transport probe only", http.StatusTeapot)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, closeClient, err := NewRecoveryClient(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	if _, err := client.AcquireRecoveryWork(t.Context(), connect.NewRequest(new(recoveryv1.AcquireRecoveryWorkRequest))); err == nil {
		t.Fatal("non-RPC transport probe response was accepted")
	}
	if !seen.Load() {
		t.Fatal("pinned recovery transport never reached the server")
	}
	for _, origin := range []string{"http://example.test", "https://user@example.test", "https://example.test/path", "https://example.test?token=x"} {
		if _, _, err := NewRecoveryClient(origin, ca); err == nil {
			t.Fatalf("unsafe recovery origin accepted: %s", origin)
		}
	}
	if _, _, err := NewRecoveryClient(server.URL, []byte("not a CA")); err == nil {
		t.Fatal("invalid recovery trust was accepted")
	}
}
