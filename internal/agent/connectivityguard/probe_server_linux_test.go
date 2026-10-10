//go:build linux

package connectivityguard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestProbeServerRequiresActualTLSAndPinnedPacketPolicy(t *testing.T) {
	target, packet, key := probeFixture(t)
	server, err := NewProbeServer(t.Context(), target.GetReceiver().GetOrigin(), uuid.NewString(), []*agentv1.ConnectivityProbeTarget{target}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	}()
	command := &agentv1.ConnectivityProbeCommand{Target: target, Packet: packet, Operation: agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_PREPARE}
	encoded, err := proto.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, ProbePath, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/protobuf")
	request.Header.Set("X-Forwarded-Client-Cert", "claimed enrolled client")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("plaintext relay gained a native probe socket")
	}
	if len(server.jobs) != 0 {
		t.Fatal("unauthenticated probe created native work")
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	changed := proto.CloneOf(target)
	changed.Receiver.PublicKey = wrongPublic
	if bad, err := NewProbeServer(t.Context(), target.GetReceiver().GetOrigin(), uuid.NewString(), []*agentv1.ConnectivityProbeTarget{changed}, key); err == nil {
		_ = bad.Close()
		t.Fatal("external witness key did not match its approved identity")
	}
	if bad, err := NewProbeServer(t.Context(), "https://unapproved.invalid", uuid.NewString(), []*agentv1.ConnectivityProbeTarget{target}, key); err == nil {
		_ = bad.Close()
		t.Fatal("unapproved peer origin accepted")
	}
}
func TestProbeServerShutdownClosesAdmission(t *testing.T) {
	target, _, key := probeFixture(t)
	server, err := NewProbeServer(t.Context(), target.GetReceiver().GetOrigin(), uuid.NewString(), []*agentv1.ConnectivityProbeTarget{target}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if !server.closed || len(server.jobs) != 0 {
		t.Fatal("shutdown retained native socket reservations")
	}
	for _, value := range server.key {
		if value != 0 {
			t.Fatal("external witness signing key copy survived shutdown")
		}
	}
}
