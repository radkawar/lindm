// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/testfixture"
	"lindm/internal/trust"
)

func TestSignedOriginRootsSurviveEnrollmentAndJournalReload(t *testing.T) {
	now := time.Date(2031, 9, 2, 3, 4, 5, 0, time.UTC)
	fixture := testfixture.NewBootstrap(t, now, "https://console.example.test", "https://device.example.test")
	fix := newFixture(t, now)
	fix.root, fix.bundle = fixture.RootJSON, fixture.Envelope
	service := openExecutor(t, now)
	const grant = "lg1_quorum-signed-origin-grant-over-32-characters"
	first := prepare(t, service, fix, grant, false)
	bundle := fixture.Verified.Bundle
	assertRoots := func(console, device []byte) {
		t.Helper()
		if !bytes.Equal(console, bundle.GetConsoleCaPem()) || !bytes.Equal(device, bundle.GetTransportCaPem()) || bytes.Equal(console, device) {
			t.Fatal("handoff did not preserve the exact independent quorum-signed origin roots")
		}
	}
	assertRoots(first.GetConsoleCaPem(), first.GetTransportCaPem())
	// Caller-owned response slices cannot replace durable enrollment trust.
	first.ConsoleCaPem[0] ^= 1
	first.TransportCaPem[0] ^= 1
	service = reopen(t, service, now.Add(time.Minute))
	resumed := prepare(t, service, fix, grant, true)
	assertRoots(resumed.GetConsoleCaPem(), resumed.GetTransportCaPem())
	if !bytes.Equal(durable(t, service).GetBootstrapEnvelope(), fixture.Envelope) {
		t.Fatal("response mutation rewrote the signed bootstrap envelope")
	}
	device, generation := uuid.New(), uuid.New()
	certificate := fixture.DeviceCertificate(t, resumed.GetCsrPem(), device, generation)
	if _, err := service.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: certificate})); err != nil {
		t.Fatal(err)
	}
	service = reopen(t, service, now.Add(2*time.Minute))
	connection, err := service.GetConnection(t.Context(), connect.NewRequest(&agentv1.GetConnectionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	assertRoots(connection.Msg.GetConsoleCaPem(), connection.Msg.GetTransportCaPem())
	serialized := new(agentv1.GetConnectionResponse)
	if err := proto.Unmarshal(mustProto(t, connection.Msg), serialized); err != nil {
		t.Fatal(err)
	}
	assertRoots(serialized.GetConsoleCaPem(), serialized.GetTransportCaPem())
	connection.Msg.ConsoleCaPem[0] ^= 1
	connection.Msg.TransportCaPem[0] ^= 1
	again, err := service.GetConnection(t.Context(), connect.NewRequest(&agentv1.GetConnectionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	assertRoots(again.Msg.GetConsoleCaPem(), again.Msg.GetTransportCaPem())
}

func TestUnsignedConsoleRootReplacementRejectedAtAdmissionAndReload(t *testing.T) {
	now := time.Date(2031, 9, 2, 3, 4, 5, 0, time.UTC)
	fixture := testfixture.NewBootstrap(t, now, "https://console.example.test", "https://device.example.test")
	other := testfixture.NewBootstrap(t, now, "https://console.example.test", "https://device.example.test")
	replaced := proto.CloneOf(fixture.Verified.Bundle)
	replaced.ConsoleCaPem = bytes.Clone(other.Verified.Bundle.GetConsoleCaPem())
	payload, err := proto.Marshal(replaced)
	if err != nil {
		t.Fatal(err)
	}
	var envelope dsse.Envelope
	if err := json.Unmarshal(fixture.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	// Keep both original execution-root signatures while changing only the root.
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	service := openExecutor(t, now)
	if _, err := service.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{ExecutionRootJson: fixture.RootJSON, BootstrapEnvelope: tampered, PendingGrant: "lg1_quorum-signed-origin-grant-over-32-characters"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unsigned console root initialized enrollment: %v", err)
	}
	status, err := service.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil || status.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED {
		t.Fatalf("unsigned console root created persistent state: %v", err)
	}
	fix := newFixture(t, now)
	fix.root, fix.bundle = fixture.RootJSON, fixture.Envelope
	prepare(t, service, fix, "lg1_quorum-signed-origin-grant-over-32-characters", false)
	state := proto.CloneOf(durable(t, service))
	state.BootstrapEnvelope = tampered
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bind(t.Context(), authority, state, now); !errors.Is(err, errKey) {
		t.Fatalf("journal reload accepted an unsigned console root: %v", err)
	}
}
