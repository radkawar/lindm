// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
	"lindm/internal/agent/enrollment"
	"lindm/internal/agent/executor"
	"lindm/internal/agent/testfixture"
)

// Every certificate has the SAME valid DNS name. A real executor verifies the
// quorum-signed two-root bootstrap, persists it, installs an Ed25519 credential,
// commits its session, and reloads before any network client is constructed.
// Device success uses RequireAndVerifyClientCert and the real executor TLS
// CertificateVerify signer; neither chain verification nor signer gates are mocked.
func TestOriginTLSHandshakesKeepConsoleAndDeviceRootsSeparate(t *testing.T) {
	for _, tc := range []struct {
		name          string
		client        string
		consoleSigner bool
		accepted      bool
	}{
		{name: "device rejects console signed same DNS", client: "device", consoleSigner: true},
		{name: "device accepts Ed25519 transport signed same DNS", client: "device", accepted: true},
		{name: "console accepts console signed same DNS", client: "console", consoleSigner: true, accepted: true},
		{name: "console rejects device transport signed same DNS", client: "console"},
		{name: "updates accept console signed same DNS", client: "update", consoleSigner: true, accepted: true},
		{name: "updates reject device transport signed same DNS", client: "update"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := new(atomic.Int32)
			mux := http.NewServeMux()
			devicePath, deviceHandler := devicev1connect.NewDeviceServiceHandler(originDeviceService{})
			enrollmentPath, enrollmentHandler := enrollmentv1connect.NewEnrollmentServiceHandler(originEnrollmentService{})
			mux.Handle(devicePath, deviceHandler)
			mux.Handle(enrollmentPath, enrollmentHandler)
			mux.HandleFunc("/targets/agent.deb", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "signed-package") })
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
					t.Error("request escaped TLS 1.3")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if tc.client == "device" && (len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1) {
					t.Error("device request escaped verified mTLS")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if tc.client != "device" && len(r.TLS.PeerCertificates) != 0 {
					t.Error("public console request disclosed a device credential")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				seen.Add(1)
				mux.ServeHTTP(w, r)
			}))
			defer server.Close()
			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			origin := "https://localhost:" + port
			now := time.Now().UTC()
			fixture := testfixture.NewBootstrap(t, now, origin, origin)
			certificate := fixture.ServerCertificate(t, tc.consoleSigner, "localhost")
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := leaf.VerifyHostname("localhost"); err != nil {
				t.Fatalf("negative handshake must not be a hostname failure: %v", err)
			}
			if !tc.consoleSigner {
				if _, ok := fixture.TransportCA.PublicKey.(ed25519.PublicKey); !ok {
					t.Fatal("device transport CA is not Ed25519")
				}
			}
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			if tc.client == "device" {
				roots := x509.NewCertPool()
				roots.AddCert(fixture.DeviceCA)
				server.TLS.ClientCAs = roots
				server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
			}
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			root, pins, connection := originExecutor(t, fixture, now)
			servers, err := connectServers(root, connection)
			if err != nil {
				t.Fatal(err)
			}
			defer servers.Close()
			switch tc.client {
			case "device":
				_, err := servers.device.GetSyncState(t.Context(), connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: connection.GetSessionEpoch()}))
				assertOriginHandshake(t, err, tc.accepted)
			case "console":
				_, err := servers.enrollment.RetrieveIssuance(t.Context(), connect.NewRequest(&enrollmentv1.RetrieveIssuanceRequest{AuthorityProof: []byte("protected retrieval proof")}))
				assertOriginHandshake(t, err, tc.accepted)
				_, err = enrollment.Enroll(t.Context(), pins)
				assertOriginHandshake(t, err, tc.accepted)
			case "update":
				client, err := newAgentUpdateClient(connection)
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseIdleConnections()
				answer := fetchAgentUpdateChunk(t.Context(), client, origin, &agentv1.AgentUpdateFetch{RequestId: uuid.NewString(), Path: "targets/agent.deb", Limit: 64})
				if answer.GetFailed() == tc.accepted || (tc.accepted && !bytes.Equal(answer.GetData(), []byte("signed-package"))) {
					t.Fatalf("public update origin handshake result: %v", answer)
				}
			}
			want := int32(0)
			if tc.accepted {
				want = 1
				if tc.client == "console" {
					want = 2
				}
			}
			if seen.Load() != want {
				t.Fatalf("requests reached same DNS peer: got %d want %d", seen.Load(), want)
			}
		})
	}
}

func assertOriginHandshake(t *testing.T, err error, accepted bool) {
	t.Helper()
	if accepted {
		if err != nil {
			t.Fatalf("authorized origin handshake refused: %v", err)
		}
		return
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("same DNS wrong-origin CA must fail chain verification: %v", err)
	}
}

func originExecutor(t *testing.T, fixture *testfixture.Bootstrap, now time.Time) (*executor.Service, *agentv1.PrepareBootstrapResponse, *agentv1.GetConnectionResponse) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	boot := uuid.NewString()
	options := []executor.Option{executor.WithClock(func() time.Time { return now }), executor.WithBootID(func() (string, error) { return boot, nil })}
	root, err := executor.New(t.Context(), directory, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	prepared, err := root.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{ExecutionRootJson: fixture.RootJSON, BootstrapEnvelope: fixture.Envelope, PendingGrant: "lg1_real-bootstrap-test-grant-over-32-characters"}))
	if err != nil {
		t.Fatal(err)
	}
	device, generation := uuid.New(), uuid.New()
	certificate := fixture.DeviceCertificate(t, prepared.Msg.GetCsrPem(), device, generation)
	if _, err := root.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: certificate})); err != nil {
		t.Fatal(err)
	}
	session, err := root.PrepareSession(t.Context(), connect.NewRequest(&agentv1.PrepareSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: session.Msg.GetPending().GetRequestId(), ServerEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	root, err = executor.New(t.Context(), directory, options...)
	if err != nil {
		t.Fatal(err)
	}
	response, err := root.GetConnection(t.Context(), connect.NewRequest(&agentv1.GetConnectionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(response.Msg)
	if err != nil {
		t.Fatal(err)
	}
	connection := new(agentv1.GetConnectionResponse)
	if err := proto.Unmarshal(encoded, connection); err != nil {
		t.Fatal(err)
	}
	bundle := fixture.Verified.Bundle
	if !connection.GetSessionEpochUsable() || connection.GetSessionEpoch() != 1 || !bytes.Equal(connection.GetConsoleCaPem(), bundle.GetConsoleCaPem()) || !bytes.Equal(connection.GetTransportCaPem(), bundle.GetTransportCaPem()) || !bytes.Equal(prepared.Msg.GetConsoleCaPem(), bundle.GetConsoleCaPem()) || !bytes.Equal(prepared.Msg.GetTransportCaPem(), bundle.GetTransportCaPem()) {
		t.Fatal("journal reload or serialized handoff lost signed origin roots/session fences")
	}
	return root, prepared.Msg, connection
}

func originConnectionPins(t *testing.T) *agentv1.GetConnectionResponse {
	t.Helper()
	connection := testfixture.NewBootstrap(t, time.Now().UTC(), "https://console.example.test", "https://device.example.test").Connection()
	connection.SessionEpoch, connection.SessionEpochUsable = 1, true
	connection.RenewAfter = timestamppb.New(time.Now().Add(time.Hour))
	return connection
}

type originDeviceService struct {
	devicev1connect.UnimplementedDeviceServiceHandler
}

func (originDeviceService) GetSyncState(_ context.Context, request *connect.Request[devicev1.GetSyncStateRequest]) (*connect.Response[devicev1.GetSyncStateResponse], error) {
	if request.Msg.GetSessionEpoch() != 1 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("session epoch fenced"))
	}
	return connect.NewResponse(&devicev1.GetSyncStateResponse{SessionEpoch: 1}), nil
}

type originEnrollmentService struct {
	enrollmentv1connect.UnimplementedEnrollmentServiceHandler
}

func (originEnrollmentService) RetrieveIssuance(context.Context, *connect.Request[enrollmentv1.RetrieveIssuanceRequest]) (*connect.Response[enrollmentv1.RetrieveIssuanceResponse], error) {
	return connect.NewResponse(&enrollmentv1.RetrieveIssuanceResponse{}), nil
}

func (originEnrollmentService) Enroll(context.Context, *connect.Request[enrollmentv1.EnrollRequest]) (*connect.Response[enrollmentv1.EnrollResponse], error) {
	return connect.NewResponse(&enrollmentv1.EnrollResponse{}), nil
}

func TestOriginTrustBoundsAndCacheInvalidation(t *testing.T) {
	connection := originConnectionPins(t)
	for _, root := range []string{"console", "device"} {
		for _, invalid := range [][]byte{nil, bytes.Repeat([]byte{'x'}, 63), bytes.Repeat([]byte{'x'}, 65537), bytes.Repeat([]byte{'x'}, 64)} {
			candidate := proto.CloneOf(connection)
			if root == "console" {
				candidate.ConsoleCaPem = invalid
			} else {
				candidate.TransportCaPem = invalid
			}
			if servers, err := connectServers(nil, candidate); err == nil {
				servers.Close()
				t.Fatalf("invalid %s roots admitted", root)
			}
			if root == "console" {
				if client, err := newAgentUpdateClient(candidate); err == nil {
					client.CloseIdleConnections()
					t.Fatal("update client admitted invalid console roots")
				}
				if _, err := enrollment.Enroll(t.Context(), &agentv1.PrepareBootstrapResponse{EnrollmentOrigin: candidate.GetEnrollmentOrigin(), ConsoleCaPem: invalid, TransportCaPem: candidate.GetTransportCaPem()}); err == nil || err.Error() != "invalid console transport trust" {
					t.Fatalf("enrollment client admitted invalid console roots: %v", err)
				}
			}
		}
	}
	var cache connectionCache
	defer cache.Close()
	first, err := cache.Get(nil, connection)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := cache.Get(nil, proto.CloneOf(connection))
	if err != nil || unchanged != first {
		t.Fatalf("unchanged signed pins retired transport: %v", err)
	}
	other := originConnectionPins(t)
	consoleChanged := proto.CloneOf(connection)
	consoleChanged.ConsoleCaPem = other.GetConsoleCaPem()
	second, err := cache.Get(nil, consoleChanged)
	if err != nil || second == first {
		t.Fatalf("console root change reused cached trust: %v", err)
	}
	deviceChanged := proto.CloneOf(consoleChanged)
	deviceChanged.TransportCaPem = other.GetTransportCaPem()
	third, err := cache.Get(nil, deviceChanged)
	if err != nil || third == second {
		t.Fatalf("device root change reused cached trust: %v", err)
	}
}
