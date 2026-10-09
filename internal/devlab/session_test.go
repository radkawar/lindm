package devlab

import (
	"crypto/tls"
	"crypto/x509"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestFixtureLoginRejectsCredentialDestinationSubstitution(t *testing.T) {
	base, err := url.Parse(issuer + "/protocol/openid-connect/auth")
	if err != nil {
		t.Fatal(err)
	}
	legitimate := "https://localhost:18443/realms/lindm/login-actions/authenticate?session_code=bound-session&client_id=lindm-console"
	form := func(action string) []byte {
		return []byte(`<form id="kc-form-login" method="post" action="` + html.EscapeString(action) + `"><input type="hidden" name="credentialId" value="bound-credential"></form>`)
	}
	action, values, err := fixtureLoginForm(form(legitimate), base)
	if err != nil || action.String() != legitimate || values.Get("credentialId") != "bound-credential" {
		t.Fatalf("valid fixture login form rejected: %v", err)
	}
	for _, test := range []struct{ name, action string }{
		{"remote origin", "https://attacker.invalid/realms/lindm/login-actions/authenticate?client_id=lindm-console"},
		{"plaintext origin", strings.Replace(legitimate, "https:", "http:", 1)},
		{"console origin", strings.Replace(legitimate, "18443", "18444", 1)},
		{"embedded credentials", strings.Replace(legitimate, "https://", "https://user:password@", 1)},
		{"another client", strings.Replace(legitimate, "client_id=lindm-console", "client_id=another-client", 1)},
		{"another endpoint", strings.Replace(legitimate, "/login-actions/authenticate", "/untrusted-receiver", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := fixtureLoginForm(form(test.action), base); err == nil {
				t.Fatal("fixture credential submission accepted a substituted destination")
			}
		})
	}
	if _, _, err := fixtureLoginForm(append(form(legitimate), form(legitimate)...), base); err == nil {
		t.Fatal("ambiguous credential form accepted")
	}
	if _, _, err := fixtureLoginForm([]byte(strings.Replace(string(form(legitimate)), `method="post"`, `method="get"`, 1)), base); err == nil {
		t.Fatal("credential-bearing GET form accepted")
	}
}

func TestPrivateOwnerRoutingRetainsLogicalOriginAndTLSVerification(t *testing.T) {
	files, err := certificateFiles()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(files["server.crt"], files["server.key"])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(files["transport-ca.crt"]) {
		t.Fatal("invalid fixture CA")
	}
	observed := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Host + "|" + r.TLS.ServerName + "|" + r.Header.Get("Origin")
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{
		DialContext:     ownerDialContext(server.Listener.Addr().String()),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, consoleOrigin+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", consoleOrigin)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent || <-observed != "localhost:18444|localhost|"+consoleOrigin {
		t.Fatal("private route changed TLS name, HTTP host or logical origin")
	}
	transport.CloseIdleConnections()
	rejected := transport.Clone()
	defer rejected.CloseIdleConnections()
	rejected.TLSClientConfig.ServerName = "substituted.invalid"
	client.Transport = rejected
	response, err = client.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		t.Fatal("private route bypassed TLS hostname verification")
	}
}
