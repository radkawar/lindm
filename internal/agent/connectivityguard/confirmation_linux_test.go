// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connectivityguard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/trust"
)

// This is a real TLS/signature unit test, not a native packet/firewall claim.
func TestConfirmationFreshConnectionExporterPinAndPartition(t *testing.T) {
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "guard-test-device"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, clientPublic, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(clientLeaf)
	var connections atomic.Int32
	var mode atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() == 2 {
			http.Error(w, "partition", http.StatusServiceUnavailable)
			return
		}
		if r.TLS == nil || r.TLS.DidResume || len(r.TLS.VerifiedChains) == 0 || !r.Close {
			t.Error("confirmation reused unauthenticated/persistent connection")
			http.Error(w, "auth", 400)
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, 384<<10))
		if err != nil {
			t.Error(err)
			return
		}
		message := new(agentv1.ConnectivityConfirmation)
		if err := proto.Unmarshal(data, message); err != nil {
			t.Error(err)
			return
		}
		exporter, err := r.TLS.ExportKeyingMaterial(ExporterLabel, message.GetNonce(), 32)
		if err != nil || !bytes.Equal(exporter, message.GetTlsExporter()) {
			t.Error("exporter did not bind this actual TLS connection")
			return
		}
		if mode.Load() == 1 {
			message.Nonce = bytes.Repeat([]byte{3}, 32)
		}
		signed, err := authority.Sign(r.Context(), message, key)
		if err != nil {
			t.Error(err)
			return
		}
		encoded, err := proto.Marshal(&agentv1.ConnectivityConfirmationResponse{ReceiptEnvelope: signed})
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/protobuf")
		if _, err := w.Write(encoded); err != nil {
			t.Error(err)
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	rules, err := protovalidate.New(protovalidate.WithMessages(&agentv1.ConnectivityConfirmation{}, &agentv1.ConnectivityConfirmationResponse{}))
	if err != nil {
		t.Fatal(err)
	}
	guard := &Guard{store: &store{rules: rules}, authority: authority, config: Config{Origin: server.URL, Policy: &agentv1.ConnectivityGuardConfig{ConfirmationPublicKey: public}, TransportTLS: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: clientKey, Leaf: clientLeaf}}}}}
	message := &agentv1.ConnectivityConfirmation{DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(), ActionId: uuid.NewString(), Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, CanonicalKey: uuid.NewString()}, AppliedGeneration: uuid.NewString(), AppliedSha256: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{2}, 32), SessionEpoch: 1}
	for index := range 4 {
		target, packet, _ := probeFixture(t)
		target.Id = uuid.NewString()
		family := uint32(4)
		if index >= 2 {
			target.Address = "2001:db8::2"
			target.SourceAddress = "2001:db8::1"
			family = 6
		}
		evidence := &agentv1.ConnectivityProbeEvidence{Target: target, Nonce: packet.GetNonce(), AddressFamily: family, Table: "lindm_test", Chain: "output", RuleHandle: 1, TraceId: 1, TraceSha256: bytes.Repeat([]byte{4}, 32)}
		if index%2 == 0 {
			evidence.NativeVerdict = 1
			evidence.ReceiverReceipt = []byte("opaque packet proof checked separately by the server domain")
		} else {
			target.Expected = agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY
		}
		message.Probes = append(message.Probes, evidence)
	}
	for _, evidence := range message.Probes {
		evidence.ReceiverReadyReceipt = []byte("opaque readiness proof checked by separate witness signature tests")
	}
	var priorExporter []byte
	for range 2 {
		request := proto.CloneOf(message)
		receipt, err := guard.confirm(t.Context(), request)
		if err != nil || len(receipt) == 0 {
			t.Fatalf("fresh confirmation: %v", err)
		}
		if bytes.Equal(priorExporter, request.GetTlsExporter()) {
			t.Fatal("fresh confirmations reused exporter")
		}
		priorExporter = bytes.Clone(request.GetTlsExporter())
	}
	if connections.Load() != 2 {
		t.Fatal("confirmations did not open separate TCP connections")
	}
	mode.Store(1)
	if receipt, err := guard.confirm(t.Context(), proto.CloneOf(message)); err == nil || len(receipt) != 0 {
		t.Fatal("validly signed receipt for another nonce committed")
	}
	mode.Store(2)
	if receipt, err := guard.confirm(t.Context(), proto.CloneOf(message)); err == nil || len(receipt) != 0 {
		t.Fatal("control-plane partition became confirmation")
	}
	mode.Store(0)
	guard.config.Policy.ConfirmationPublicKey = bytes.Repeat([]byte{9}, 32)
	if receipt, err := guard.confirm(t.Context(), proto.CloneOf(message)); err == nil || len(receipt) != 0 {
		t.Fatal("unapproved confirmation signing key accepted")
	}
}
