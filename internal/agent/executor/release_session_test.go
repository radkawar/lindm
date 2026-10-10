//go:build linux

package executor

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/buildinfo"
)

func TestBuildChangeReacquiresSessionOnSameBoot(t *testing.T) {
	now := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	fix := newFixture(t, now)
	boot := uuid.NewString()
	svc := openExecutor(t, now, WithBootID(func() (string, error) { return boot, nil }))
	prepare(t, svc, fix, "lg1_test-grant-secret-with-32-characters-minimum", false)
	device, generation := uuid.New(), uuid.New()
	cert := fix.leaf(t, publicOf(durable(t, svc).GetIdentityPrivateKey()), device, generation, now.Add(-time.Minute), now.Add(30*24*time.Hour))
	if _, err := svc.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: cert})); err != nil {
		t.Fatal(err)
	}
	pending := session(t, svc).GetPending()
	if _, err := svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: pending.GetRequestId(), ServerEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	if session(t, svc).GetAccepted().GetSessionEpoch() != 1 {
		t.Fatal("unchanged build reacquired session")
	}
	// Model a protected receipt persisted by the preceding release. Do not mutate
	// global linker stamps, which would race unrelated executor tests.
	loaded, err := svc.enrolled(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	next := cloneState(loaded.state)
	next.SessionReceipt.AgentRelease = "preceding-build"
	next.SessionReceipt.AgentProtocolVersion = 0
	if err := svc.commit(t.Context(), loaded.revision, next); err != nil {
		t.Fatal(err)
	}
	svc = reopen(t, svc, now)
	successor := session(t, svc).GetPending()
	if successor.GetPredecessorEpoch() != 1 || successor.GetBootId() != boot {
		t.Fatal("same-boot build change failed to stage successor")
	}
	claim := durable(t, svc).GetPendingSession()
	if claim.GetAgentRelease() != buildinfo.Current().Version || claim.GetAgentProtocolVersion() != buildinfo.ProtocolVersion {
		t.Fatal("acquisition fabricated build identity")
	}
	if _, err := svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: successor.GetRequestId(), ServerEpoch: 2})); err != nil {
		t.Fatal(err)
	}
	svc = reopen(t, svc, now)
	if session(t, svc).GetAccepted().GetSessionEpoch() != 2 {
		t.Fatal("committed build identity was not durable")
	}
}
