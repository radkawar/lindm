// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSplitCertificateExactNamesAndTransportChain(t *testing.T) {
	files, err := certificateFiles()
	if err != nil {
		t.Fatal(err)
	}
	shared, run := t.TempDir(), t.TempDir()
	for name, data := range files {
		if err := writeSplitPrivateFile(filepath.Join(shared, name), data); err != nil {
			t.Fatal(err)
		}
	}
	device := netip.MustParseAddr("192.0.2.20")
	if err := writeSplitCertificate(shared, run, device); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(run, "split-server.crt"), filepath.Join(run, "split-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leaf.DNSNames, []string{"localhost"}) || len(leaf.IPAddresses) != 3 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || leaf.IsCA {
		t.Fatal("split TLS leaf has unexpected names or CA authority")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(files["transport-ca.crt"]) {
		t.Fatal("invalid transport CA")
	}
	for _, host := range []string{device.String(), "localhost", "127.0.0.1", "::1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("verify %s: %v", host, err)
		}
	}
	if leaf.VerifyHostname("192.0.2.21") == nil || leaf.VerifyHostname("127.0.0.2") == nil {
		t.Fatal("split leaf covers an unrequested address")
	}
	if leaf.NotAfter.After(time.Now().Add(24 * time.Hour)) {
		t.Fatal("run-scoped leaf outlives one day")
	}
	for _, name := range []string{"split-server.crt", "split-server.key"} {
		info, err := os.Stat(filepath.Join(run, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("run-scoped TLS file is not owner-only")
		}
	}
	if err := writeSplitCertificate(shared, run, device); err == nil {
		t.Fatal("split TLS custody was overwritten")
	}
	for name, expected := range files {
		actual, err := os.ReadFile(filepath.Join(shared, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, expected) {
			t.Fatal("shared certificate custody changed")
		}
	}
}

func TestOpenSplitAuthorityRejectsInvalidDeviceBeforeResources(t *testing.T) {
	for _, address := range []string{"", "0.0.0.0", "127.0.0.1", "127.0.0.2", "::", "::1", "2001:db8::1", "::ffff:192.0.2.20", "224.0.0.1", "255.255.255.255"} {
		t.Run(address, func(t *testing.T) {
			var device netip.Addr
			if address != "" {
				device = netip.MustParseAddr(address)
			}
			_, err := OpenSplitDeviceActionAuthorityFixture(t.Context(), "unused", "unused", device, LoadAuthorityOptions{})
			if err == nil || !strings.Contains(err.Error(), "IPv4 address") {
				t.Fatalf("invalid device must fail before resource setup: %v", err)
			}
		})
	}
}

func TestControlPlaneHandleJSONRoundTrip(t *testing.T) {
	handle := ControlPlaneHandle{
		ConsoleOrigin: "https://localhost:24444", AdminPort: 24444, DeviceOrigin: "https://192.0.2.20:24445",
		DatabaseName: "split-fixture", TransportCAPEM: []byte("public CA"), ExecutionRootJSON: []byte(`{"public":"root"}`),
		BootstrapEnvelope: []byte(`{"public":"bootstrap"}`), AccountID: "00000000-0000-4000-8000-000000000001",
		Username: "remote-owner", Password: []byte("test-only-password"),
		WebAuthnCredentialID: []byte("test-credential"), WebAuthnPrivateKey: []byte("test-key"), WebAuthnCounter: 1,
	}
	encoded, err := json.Marshal(handle)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ControlPlaneHandle
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(handle, decoded) {
		t.Fatal("control-plane handle changed during JSON round-trip")
	}
}

func TestConnectedAuthorityRefusesControllerOperations(t *testing.T) {
	owner, err := newLocalAccount("localhost", "remote-owner", "00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	// A connected fixture must not touch even accidentally populated controller
	// paths. Closing it only destroys its own in-memory credentials.
	directory := t.TempDir()
	fixture := &AuthorityFixture{connected: &connectedAuthority{}, local: &localAuthority{owner: owner}, directory: directory}
	checks := []struct {
		name string
		call func() error
	}{
		{"device actions", func() error { _, err := fixture.ConfigureDeviceActions(t.Context()); return err }},
		{"assistance", func() error { return fixture.ConfigureAssistance(t.Context(), nil, nil) }},
		{"restart", func() error { return fixture.Restart(t.Context()) }},
		{"reveal approval", func() error { return fixture.RequireConsoleRevealApproval(t.Context()) }},
		{"wait", func() error { return fixture.Wait(t.Context()) }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.call(); err == nil || !strings.Contains(err.Error(), "controller-owned") {
				t.Fatalf("controller-owned operation was not explicitly refused: %v", err)
			}
		})
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatal("connected close touched controller paths")
	}
	if len(owner.password) != 0 || owner.authenticator != nil {
		t.Fatal("connected close retained local credentials")
	}
	if _, err := fixture.OpenOwnerSession(t.Context()); err == nil {
		t.Fatal("closed fixture opened owner session")
	}
	if _, err := fixture.ReadAgentFixture(t.Context()); err == nil {
		t.Fatal("closed fixture returned provisioning material")
	}
}

func TestConnectAuthorityClearsRejectedCredentials(t *testing.T) {
	if _, err := ConnectAuthorityFixture(t.Context(), nil); err == nil {
		t.Fatal("nil handle accepted")
	}
	for _, origin := range []string{"https://attacker.invalid:24444", "https://localhost:24445", "http://localhost:24444", "https://localhost:24444/path"} {
		password, key, id := []byte("test-password"), []byte("test-key"), []byte("test-id")
		handle := &ControlPlaneHandle{ConsoleOrigin: origin, AdminPort: 24444, Password: password, WebAuthnPrivateKey: key, WebAuthnCredentialID: id, WebAuthnCounter: 1}
		if _, err := ConnectAuthorityFixture(t.Context(), handle); err == nil {
			t.Fatal("invalid admin origin accepted")
		}
		if len(handle.Password) != 0 || len(handle.WebAuthnPrivateKey) != 0 || len(handle.WebAuthnCredentialID) != 0 || handle.WebAuthnCounter != 0 {
			t.Fatal("failed connection retained transferred credentials")
		}
		for _, buffer := range [][]byte{password, key, id} {
			if !bytes.Equal(buffer, make([]byte, len(buffer))) {
				t.Fatal("failed connection did not erase credential backing buffers")
			}
		}
	}
}

func TestConnectedAuthorityUsesOnlyHandleTrustAndForward(t *testing.T) {
	files, err := certificateFiles()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(files["server.crt"], files["server.key"])
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Host + "|" + r.TLS.ServerName
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, err := trustClientPEM(files["transport-ca.crt"])
	if err != nil {
		t.Fatal(err)
	}
	fixture := &AuthorityFixture{ConsoleOrigin: "https://localhost:24444", AdminAddress: server.Listener.Addr().String(), connected: &connectedAuthority{tls: config}}
	transport := &http.Transport{TLSClientConfig: config, DialContext: fixture.connectedDialContext()}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fixture.ConsoleOrigin+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-observed; got != "localhost:24444|localhost" {
		t.Fatalf("connected transport changed HTTP/TLS origin: %s", got)
	}
	if conn, err := fixture.connectedDialContext()(t.Context(), "tcp", "attacker.invalid:24444"); err == nil {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("connected transport dialed outside forwarded admin origin")
	}
	other, err := certificateFiles()
	if err != nil {
		t.Fatal(err)
	}
	untrusted, err := trustClientPEM(other["transport-ca.crt"])
	if err != nil {
		t.Fatal(err)
	}
	rejected := transport.Clone()
	rejected.TLSClientConfig = untrusted
	defer rejected.CloseIdleConnections()
	client.Transport = rejected
	response, err = client.Do(req)
	if err == nil {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("connected transport accepted an untrusted server")
	}
}
