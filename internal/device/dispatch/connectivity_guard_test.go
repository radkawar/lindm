// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func confirmationTargets(t *testing.T) []*agentv1.ConnectivityProbeTarget {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var targets []*agentv1.ConnectivityProbeTarget
	for _, v6 := range []bool{false, true} {
		for _, verdict := range []agentv1.ConnectivityProbeVerdict{agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW, agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY} {
			source, destination := "192.0.2.1", "192.0.2.2"
			if v6 {
				source, destination = "2001:db8::1", "2001:db8::2"
			}
			targets = append(targets, &agentv1.ConnectivityProbeTarget{Id: uuid.NewString(), SourceAddress: source, Address: destination, SourcePort: 42421, Port: 42422, Expected: verdict, Direction: agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT, Protocol: agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_UDP, Receiver: &agentv1.ConnectivityProbePeer{Origin: "https://probe.invalid", PublicKey: public}})
		}
	}
	return targets
}
func TestConnectivityConfirmationNeverTrustsRelayHeaders(t *testing.T) {
	service := new(Service)
	handler, err := service.ConnectivityConfirmationHandler(confirmationTargets(t))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, ConnectivityConfirmationPath, bytes.NewReader([]byte{1, 2, 3}))
	request.Header.Set("Content-Type", "application/protobuf")
	request.Header.Set("X-Forwarded-Client-Cert", "fake authenticated executor")
	request.Header.Set("X-Lindm-TLS-Exporter", "fake fresh connection")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("relay headers bypassed real TLS identity: %d", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("confirmation rejection became cacheable")
	}
}
func TestConnectivityConfirmationHasNoArbitraryRPCOrTargetPolicy(t *testing.T) {
	service := new(Service)
	targets := confirmationTargets(t)
	handler, err := service.ConnectivityConfirmationHandler(targets)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ConnectivityConfirmationPath + "?url=https://arbitrary.invalid", ConnectivityConfirmationPath + "/other"} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.Header.Set("Content-Type", "application/protobuf")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatal("unrecognized confirmation RPC shape accepted")
		}
	}
	targets[1].Id = targets[0].GetId()
	if _, err := service.ConnectivityConfirmationHandler(targets); err == nil {
		t.Fatal("duplicate approved probe identity accepted")
	}
}
