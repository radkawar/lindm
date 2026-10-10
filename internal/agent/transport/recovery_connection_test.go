package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/gen/lindm/recovery/v1/recoveryv1connect"
)

func TestRecoveryConnectionPinsTLSWithoutOrdinaryIdentity(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	start := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificate, ca := recoveryTestCertificates(t, start, nil)
	server, seen := recoveryTestServer(t, certificate, true)
	clock := new(recoveryTestClock)
	clock.set(start.Add(30*time.Minute), start.Add(31*time.Minute), nil)
	client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	for range 2 {
		if _, err := client.AcquireRecoveryWork(t.Context(), connect.NewRequest(new(recoveryv1.AcquireRecoveryWorkRequest))); err != nil {
			t.Fatal(err)
		}
	}
	if seen.Load() != 2 {
		t.Fatalf("pinned recovery transport reached server %d times, want 2", seen.Load())
	}
	for _, origin := range []string{"http://example.test", "https://user@example.test", "https://example.test/path", "https://example.test?token=x"} {
		if _, _, err := NewRecoveryClient(origin, ca, clock.bounds); err == nil {
			t.Fatalf("unsafe recovery origin accepted: %s", origin)
		}
	}
	for _, ca := range [][]byte{nil, []byte("not a CA"), make([]byte, 65537)} {
		if _, _, err := NewRecoveryClient(server.URL, ca, clock.bounds); err == nil {
			t.Fatal("invalid recovery trust was accepted")
		}
	}
	if _, _, err := NewRecoveryClient(server.URL, ca, nil); err == nil {
		t.Fatal("missing time bounds callback was accepted")
	}
}

func TestRecoveryConnectionOnlyPublicTimeBeforeBootstrap(t *testing.T) {
	start := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificate, ca := recoveryTestCertificates(t, start, nil)
	server, seen := recoveryTestServer(t, certificate, true)
	clock := new(recoveryTestClock)
	clock.set(time.Time{}, time.Time{}, errors.New("not bootstrapped"))
	client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	actions := []func() error{
		func() error {
			_, err := client.AcquireRecoveryWork(t.Context(), connect.NewRequest(new(recoveryv1.AcquireRecoveryWorkRequest)))
			return err
		},
		func() error {
			_, err := client.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(new(recoveryv1.AuthorizeRecoveryStartRequest)))
			return err
		},
		func() error {
			_, err := client.CheckpointRecoveryAction(t.Context(), connect.NewRequest(new(recoveryv1.CheckpointRecoveryActionRequest)))
			return err
		},
		func() error {
			_, err := client.ReportRecoveryResult(t.Context(), connect.NewRequest(new(recoveryv1.ReportRecoveryResultRequest)))
			return err
		},
	}
	for _, action := range actions {
		if err := action(); err == nil {
			t.Fatal("action RPC accepted before authenticated time")
		}
	}
	for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie", "authorization", "proxy-authorization", "cookie"} {
		request := connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))
		request.Header()[header] = []string{"", "secret"}
		if _, err := client.GetRecoveryTime(t.Context(), request); err == nil {
			t.Fatalf("provisional request accepted identity header %s", header)
		}
	}
	if seen.Load() != 0 {
		t.Fatal("credentials reached the provisional endpoint")
	}
	if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err != nil {
		t.Fatal(err)
	}
	clock.set(start.Add(30*time.Minute), start.Add(31*time.Minute), nil)
	if err := actions[0](); err != nil {
		t.Fatal(err)
	}
	clock.set(time.Time{}, time.Time{}, errors.New("authenticated clock lost"))
	if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err == nil {
		t.Fatal("authenticated client downgraded to provisional time")
	}
	if err := actions[0](); err == nil {
		t.Fatal("action accepted after losing authenticated bounds")
	}
	if seen.Load() != 2 {
		t.Fatalf("unexpected requests reached recovery endpoint: %d", seen.Load())
	}
}

func TestRecoveryConnectionBootstrapIgnoresRTCSkew(t *testing.T) {
	// Move certificate validity, not the wall clock. Both chains are outside
	// the host's current time but valid at the independently authenticated date.
	now := time.Now()
	for _, test := range []struct {
		name  string
		start time.Time
	}{
		{name: "RTC ahead of server", start: now.AddDate(-20, 0, 0)},
		{name: "RTC behind server", start: now.AddDate(20, 0, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, ca := recoveryTestCertificates(t, test.start, nil)
			server, seen := recoveryTestServer(t, certificate, true)
			clock := new(recoveryTestClock)
			clock.set(time.Time{}, time.Time{}, errors.New("not bootstrapped"))
			client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient()
			if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err != nil {
				t.Fatalf("RTC skew blocked public time: %v", err)
			}
			clock.set(test.start.Add(30*time.Minute), test.start.Add(31*time.Minute), nil)
			if _, err := client.AcquireRecoveryWork(t.Context(), connect.NewRequest(new(recoveryv1.AcquireRecoveryWorkRequest))); err != nil {
				t.Fatalf("RTC skew blocked authenticated request: %v", err)
			}
			if seen.Load() != 2 {
				t.Fatalf("got %d requests, want 2", seen.Load())
			}
		})
	}
}

func TestRecoveryConnectionProvisionalVerificationPreservesPKI(t *testing.T) {
	start := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		edit    func(root, issuer, leaf *x509.Certificate)
		wrongCA bool
		corrupt bool
	}{
		{name: "wrong CA", wrongCA: true},
		{name: "wrong hostname", edit: func(_, _, leaf *x509.Certificate) {
			leaf.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
		}},
		{name: "wrong EKU", edit: func(_, _, leaf *x509.Certificate) {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}},
		{name: "non CA issuer", edit: func(_, issuer, _ *x509.Certificate) {
			issuer.IsCA = false
			issuer.MaxPathLenZero = false
		}},
		{name: "path constraint", edit: func(root, _, _ *x509.Certificate) {
			root.MaxPathLen = 0
			root.MaxPathLenZero = true
		}},
		{name: "name constraint", edit: func(root, _, _ *x509.Certificate) {
			root.PermittedDNSDomainsCritical = true
			root.PermittedIPRanges = []*net.IPNet{{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)}}
		}},
		{name: "no chain validity overlap", edit: func(root, _, _ *x509.Certificate) {
			root.NotBefore = start.Add(2 * time.Hour)
		}},
		{name: "invalid signature", corrupt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, ca := recoveryTestCertificates(t, start, test.edit)
			if test.wrongCA {
				_, ca = recoveryTestCertificates(t, start, nil)
			}
			if test.corrupt {
				der := certificate.Certificate[0]
				der[len(der)-1] ^= 1
			}
			server, seen := recoveryTestServer(t, certificate, true)
			clock := new(recoveryTestClock)
			clock.set(time.Time{}, time.Time{}, errors.New("not bootstrapped"))
			client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient()
			if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err == nil {
				t.Fatal("invalid provisional TLS peer was accepted")
			}
			if seen.Load() != 0 {
				t.Fatal("HTTP request reached an invalid provisional TLS peer")
			}
		})
	}
}

func TestRecoveryConnectionRevalidatesKeepaliveAtBothBounds(t *testing.T) {
	start := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, protocol := range []struct {
		name  string
		http2 bool
	}{{name: "HTTP1"}, {name: "HTTP2", http2: true}} {
		t.Run(protocol.name, func(t *testing.T) {
			for _, test := range []struct {
				name  string
				edit  func(root, issuer, leaf *x509.Certificate)
				lower time.Time
				upper time.Time
			}{
				{name: "leaf expiry upper", lower: start.Add(59 * time.Minute), upper: start.Add(61 * time.Minute)},
				{name: "leaf expiry lower", lower: start.Add(61 * time.Minute), upper: start.Add(62 * time.Minute)},
				{name: "issuer expiry", lower: start.Add(19 * time.Minute), upper: start.Add(21 * time.Minute), edit: func(_, issuer, _ *x509.Certificate) {
					issuer.NotAfter = start.Add(20 * time.Minute)
				}},
				{name: "root expiry", lower: start.Add(19 * time.Minute), upper: start.Add(21 * time.Minute), edit: func(root, _, _ *x509.Certificate) {
					root.NotAfter = start.Add(20 * time.Minute)
				}},
				{name: "leaf not yet valid", lower: start.Add(19 * time.Minute), upper: start.Add(21 * time.Minute), edit: func(_, _, leaf *x509.Certificate) {
					leaf.NotBefore = start.Add(20 * time.Minute)
				}},
				{name: "issuer not yet valid", lower: start.Add(19 * time.Minute), upper: start.Add(21 * time.Minute), edit: func(_, issuer, _ *x509.Certificate) {
					issuer.NotBefore = start.Add(20 * time.Minute)
				}},
				{name: "root not yet valid", lower: start.Add(19 * time.Minute), upper: start.Add(21 * time.Minute), edit: func(root, _, _ *x509.Certificate) {
					root.NotBefore = start.Add(20 * time.Minute)
				}},
			} {
				t.Run(test.name, func(t *testing.T) {
					certificate, ca := recoveryTestCertificates(t, start, test.edit)
					server, seen := recoveryTestServer(t, certificate, protocol.http2)
					clock := new(recoveryTestClock)
					clock.set(time.Time{}, time.Time{}, errors.New("not bootstrapped"))
					client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
					if err != nil {
						t.Fatal(err)
					}
					defer closeClient()
					if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err != nil {
						t.Fatal(err)
					}
					clock.set(test.lower, test.upper, nil)
					var reused atomic.Bool
					ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
						if info.Reused {
							reused.Store(true)
						}
					}})
					if _, err := client.AcquireRecoveryWork(ctx, connect.NewRequest(new(recoveryv1.AcquireRecoveryWorkRequest))); err == nil {
						t.Fatal("invalid authenticated interval accepted for an action")
					}
					if !reused.Load() {
						t.Fatal("did not exercise validation of an existing connection")
					}
					if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err == nil {
						t.Fatal("public time RPC bypassed authenticated certificate validity")
					}
					if seen.Load() != 1 {
						t.Fatalf("invalid authenticated requests reached endpoint: %d", seen.Load())
					}
				})
			}
		})
	}
}

func TestRecoveryConnectionAuthenticatedKeepaliveExpires(t *testing.T) {
	start := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificate, ca := recoveryTestCertificates(t, start, nil)
	server, seen := recoveryTestServer(t, certificate, true)
	clock := new(recoveryTestClock)
	clock.set(start.Add(30*time.Minute), start.Add(31*time.Minute), nil)
	client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	if _, err := client.AcquireRecoveryWork(t.Context(), connect.NewRequest(new(recoveryv1.AcquireRecoveryWorkRequest))); err != nil {
		t.Fatal(err)
	}
	clock.set(start.Add(59*time.Minute), start.Add(61*time.Minute), nil)
	var reused atomic.Bool
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		reused.Store(info.Reused)
	}})
	if _, err := client.AcquireRecoveryWork(ctx, connect.NewRequest(new(recoveryv1.AcquireRecoveryWorkRequest))); err == nil {
		t.Fatal("previously authenticated connection survived certificate expiry")
	}
	if !reused.Load() || seen.Load() != 1 {
		t.Fatalf("existing connection was not rejected before sending: reused=%t requests=%d", reused.Load(), seen.Load())
	}
}

func TestRecoveryConnectionRejectsInvalidAuthenticatedBounds(t *testing.T) {
	start := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificate, ca := recoveryTestCertificates(t, start, nil)
	server, seen := recoveryTestServer(t, certificate, true)
	for _, bounds := range [][2]time.Time{
		{},
		{start, time.Time{}},
		{time.Time{}, start},
		{start.Add(time.Minute), start},
	} {
		clock := new(recoveryTestClock)
		clock.set(bounds[0], bounds[1], nil)
		client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err == nil {
			t.Fatal("invalid authenticated bounds fell back to provisional TLS")
		}
		closeClient()
	}
	if seen.Load() != 0 {
		t.Fatal("invalid bounds allowed a request")
	}
}

func TestRecoveryConnectionRequiresTLS13(t *testing.T) {
	start := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificate, ca := recoveryTestCertificates(t, start, nil)
	var seen atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		seen.Store(true)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	clock := new(recoveryTestClock)
	clock.set(time.Time{}, time.Time{}, errors.New("not bootstrapped"))
	client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err == nil {
		t.Fatal("TLS 1.2 recovery server was accepted")
	}
	if seen.Load() {
		t.Fatal("request reached a TLS 1.2 endpoint")
	}
}

func TestRecoveryConnectionDoesNotFollowRedirects(t *testing.T) {
	start := time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificate, ca := recoveryTestCertificates(t, start, nil)
	var seen atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seen.Add(1)
		http.Redirect(w, request, recoveryv1connect.RecoveryServiceGetRecoveryTimeProcedure+"?redirected=yes", http.StatusTemporaryRedirect)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	clock := new(recoveryTestClock)
	clock.set(time.Time{}, time.Time{}, errors.New("not bootstrapped"))
	client, closeClient, err := NewRecoveryClient(server.URL, ca, clock.bounds)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	if _, err := client.GetRecoveryTime(t.Context(), connect.NewRequest(new(recoveryv1.GetRecoveryTimeRequest))); err == nil {
		t.Fatal("redirect accepted as a time response")
	}
	if seen.Load() != 1 {
		t.Fatalf("recovery transport followed a redirect: %d requests", seen.Load())
	}
}

type recoveryTestClock struct {
	mu    sync.RWMutex
	lower time.Time
	upper time.Time
	err   error
}

func (c *recoveryTestClock) bounds() (time.Time, time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lower, c.upper, c.err
}

func (c *recoveryTestClock) set(lower, upper time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lower, c.upper, c.err = lower, upper, err
}

type recoveryTransportTestService struct {
	recoveryv1connect.UnimplementedRecoveryServiceHandler
}

func (recoveryTransportTestService) GetRecoveryTime(context.Context, *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
	return connect.NewResponse(new(recoveryv1.GetRecoveryTimeResponse)), nil
}

func (recoveryTransportTestService) AcquireRecoveryWork(context.Context, *connect.Request[recoveryv1.AcquireRecoveryWorkRequest]) (*connect.Response[recoveryv1.AcquireRecoveryWorkResponse], error) {
	return connect.NewResponse(new(recoveryv1.AcquireRecoveryWorkResponse)), nil
}

func recoveryTestServer(t *testing.T, certificate tls.Certificate, http2 bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	_, handler := recoveryv1connect.NewRecoveryServiceHandler(recoveryTransportTestService{})
	seen := new(atomic.Int64)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seen.Add(1)
		if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) != 0 {
			t.Error("recovery transport supplied a client certificate or weakened TLS")
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("Proxy-Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("recovery transport sent ambient identity")
		}
		if (request.ProtoMajor == 2) != http2 {
			t.Errorf("unexpected HTTP protocol: %s", request.Proto)
		}
		// Repeated requests must not return this cookie.
		w.Header().Set("Set-Cookie", "ordinary-device-identity=forbidden; Path=/; Secure")
		handler.ServeHTTP(w, request)
	}))
	server.EnableHTTP2 = http2
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, seen
}

func recoveryTestCertificates(t *testing.T, start time.Time, edit func(root, issuer, leaf *x509.Certificate)) (tls.Certificate, []byte) {
	t.Helper()
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: start, NotAfter: start.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: start, NotAfter: start.Add(12 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(3), NotBefore: start, NotAfter: start.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if edit != nil {
		edit(root, issuer, leaf)
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, root, issuerPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, leafPublic, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, issuerDER}, PrivateKey: leafPrivate, Leaf: leaf}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}
