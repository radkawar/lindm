// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

// capabilityPolicyFake models the executor's protected record and the
// server's issuance at the existing transport seams.
type capabilityPolicyFake struct {
	observation  *agentv1.CapabilityPolicyObservation
	getErr       error
	issued       *devicev1.GetCapabilityPolicyResponse
	serverErr    error
	requests     []*devicev1.GetCapabilityPolicyRequest
	updates      [][]byte
	executorGets int
	publications []*agentv1.CapabilityPolicyObservation
	publishErr   error
}

func (e *refreshTransportExecutor) GetCapabilityPolicy(context.Context, *connect.Request[agentv1.GetCapabilityPolicyRequest]) (*connect.Response[agentv1.GetCapabilityPolicyResponse], error) {
	c := &e.f.capability
	c.executorGets++
	if c.getErr != nil {
		return nil, c.getErr
	}
	observation := proto.CloneOf(c.observation)
	if observation == nil {
		observation = &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_NONE}
	}
	return connect.NewResponse(&agentv1.GetCapabilityPolicyResponse{Observation: observation}), nil
}

func (e *refreshTransportExecutor) UpdateCapabilityPolicy(_ context.Context, req *connect.Request[agentv1.UpdateCapabilityPolicyRequest]) (*connect.Response[agentv1.UpdateCapabilityPolicyResponse], error) {
	c := &e.f.capability
	c.updates = append(c.updates, bytes.Clone(req.Msg.GetPolicyEnvelope()))
	digest := sha256.Sum256(req.Msg.GetPolicyEnvelope())
	c.observation = &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE, AppliedVersion: c.issued.GetVersion(), AppliedSha256: digest[:]}
	return connect.NewResponse(&agentv1.UpdateCapabilityPolicyResponse{Observation: proto.CloneOf(c.observation)}), nil
}

func (s *refreshTransportServer) GetCapabilityPolicy(_ context.Context, req *connect.Request[devicev1.GetCapabilityPolicyRequest]) (*connect.Response[devicev1.GetCapabilityPolicyResponse], error) {
	c := &s.f.capability
	c.requests = append(c.requests, proto.CloneOf(req.Msg))
	if c.serverErr != nil {
		return nil, c.serverErr
	}
	issued := proto.CloneOf(c.issued)
	if issued == nil {
		issued = &devicev1.GetCapabilityPolicyResponse{}
	}
	return connect.NewResponse(issued), nil
}

func capabilityLoop(f *refreshTransportFixture) *managementLoop {
	return &managementLoop{
		executor: f.r.executor, cache: f.r.cache, gate: make(authorityGate, 1),
		refreshCapabilities: func(_ context.Context, observation *agentv1.CapabilityPolicyObservation) error {
			f.capability.publications = append(f.capability.publications, proto.CloneOf(observation))
			return f.capability.publishErr
		},
	}
}

func TestCapabilityPolicySyncRelaysSignedEnvelopeToExecutor(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.capability.issued = &devicev1.GetCapabilityPolicyResponse{PolicyEnvelope: []byte("signed policy v3"), Version: 3}
	m := capabilityLoop(f)
	if err := m.synchronizeCapabilityPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.capability.updates) != 1 || !bytes.Equal(f.capability.updates[0], []byte("signed policy v3")) {
		t.Fatalf("executor updates = %q", f.capability.updates)
	}
	first := f.capability.requests[0]
	if first.GetSessionEpoch() != f.connection.GetSessionEpoch() || first.GetAppliedVersion() != 0 || len(first.GetAppliedSha256()) != 0 {
		t.Fatalf("first server request = %v", first)
	}
	// The next cycle reports the ACTIVE cursor; an empty envelope is a no-op.
	f.capability.issued = &devicev1.GetCapabilityPolicyResponse{Version: 3}
	if err := m.synchronizeCapabilityPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("signed policy v3"))
	second := f.capability.requests[1]
	if second.GetAppliedVersion() != 3 || !bytes.Equal(second.GetAppliedSha256(), digest[:]) || len(f.capability.updates) != 1 {
		t.Fatalf("second request = %v updates = %d", second, len(f.capability.updates))
	}
}

func TestCapabilityPolicySyncReissuesInertAndSkipsRefusedLocally(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.capability.observation = &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_INERT, AppliedVersion: 2, AppliedSha256: bytes.Repeat([]byte{1}, 32)}
	m := capabilityLoop(f)
	if err := m.synchronizeCapabilityPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := f.capability.requests[0]; got.GetAppliedVersion() != 0 || len(got.GetAppliedSha256()) != 0 {
		t.Fatalf("INERT policy reported an applied cursor: %v", got)
	}
	f.capability.observation = &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_REFUSED_LOCALLY}
	if err := m.synchronizeCapabilityPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.capability.requests) != 1 {
		t.Fatal("a locally refused executor still asked the server for a policy")
	}
}

func TestCapabilityPolicySyncRecordsUnavailableReasonOncePerChange(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.capability.issued = &devicev1.GetCapabilityPolicyResponse{UnavailableReason: "capability_policy_not_delegated"}
	m := capabilityLoop(f)
	for range 2 {
		if err := m.synchronizeCapabilityPolicy(t.Context()); err != nil {
			t.Fatal(err)
		}
		if m.capabilityUnavailable != "capability_policy_not_delegated" || len(f.capability.updates) != 0 {
			t.Fatalf("unavailable = %q updates = %d", m.capabilityUnavailable, len(f.capability.updates))
		}
	}
	f.capability.issued = &devicev1.GetCapabilityPolicyResponse{}
	if err := m.synchronizeCapabilityPolicy(t.Context()); err != nil || m.capabilityUnavailable != "" {
		t.Fatalf("cleared reason = %q err = %v", m.capabilityUnavailable, err)
	}
	f.capability.serverErr = errors.New("server down")
	if err := m.synchronizeCapabilityPolicy(t.Context()); err == nil {
		t.Fatal("server failure was not reported")
	}
}

func TestInventoryPublishesExecutorCapabilityPolicy(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.capability.observation = &agentv1.CapabilityPolicyObservation{
		State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE, AppliedVersion: 4, AppliedSha256: bytes.Repeat([]byte{7}, 32),
		Capabilities: []*agentv1.CapabilityObservation{{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, Status: agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED}},
	}
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if got := f.publishedHost.GetDetails().GetCapabilityPolicy(); !proto.Equal(got, f.capability.observation) {
		t.Fatalf("published capability policy = %v", got)
	}
	f2 := newRefreshTransportFixture(t)
	f2.capability.getErr = errors.New("executor unavailable")
	if err := f2.r.refreshInventory(t.Context(), proto.CloneOf(f2.status)); err != nil {
		t.Fatal(err)
	}
	if f2.publishedHost.GetDetails().GetCapabilityPolicy() != nil {
		t.Fatal("published a capability policy without an executor observation")
	}
}

// The dispatch fakes model an executor without a policy and a server with
// nothing to issue; capability sync is then a read-only no-op every cycle.
func (e *dispatchExecutor) GetCapabilityPolicy(context.Context, *connect.Request[agentv1.GetCapabilityPolicyRequest]) (*connect.Response[agentv1.GetCapabilityPolicyResponse], error) {
	return connect.NewResponse(&agentv1.GetCapabilityPolicyResponse{Observation: &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_NONE}}), nil
}

func (s *dispatchServer) GetCapabilityPolicy(context.Context, *connect.Request[devicev1.GetCapabilityPolicyRequest]) (*connect.Response[devicev1.GetCapabilityPolicyResponse], error) {
	return connect.NewResponse(&devicev1.GetCapabilityPolicyResponse{}), nil
}

// These fixtures leave other management work empty so the real production
// cycle, unbuffered owner handoff and ordinary durable publication all execute.
func (*refreshTransportExecutor) GetExecutionTrust(context.Context, *connect.Request[agentv1.GetExecutionTrustRequest]) (*connect.Response[agentv1.GetExecutionTrustResponse], error) {
	return connect.NewResponse(&agentv1.GetExecutionTrustResponse{RootVersion: 1, RootSha256: make([]byte, sha256.Size), RootExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}), nil
}

func (*refreshTransportServer) GetExecutionTrust(context.Context, *connect.Request[devicev1.GetExecutionTrustRequest]) (*connect.Response[devicev1.GetExecutionTrustResponse], error) {
	return connect.NewResponse(&devicev1.GetExecutionTrustResponse{}), nil
}

func (*refreshTransportServer) GetDeviceActionWork(context.Context, *connect.Request[devicev1.GetDeviceActionWorkRequest]) (*connect.Response[devicev1.GetDeviceActionWorkResponse], error) {
	return connect.NewResponse(&devicev1.GetDeviceActionWorkResponse{}), nil
}

func (*refreshTransportServer) GetResourceWork(context.Context, *connect.Request[devicev1.GetResourceWorkRequest]) (*connect.Response[devicev1.GetResourceWorkResponse], error) {
	return connect.NewResponse(&devicev1.GetResourceWorkResponse{}), nil
}

func capabilityOwnerLoop(t *testing.T, f *refreshTransportFixture) *managementLoop {
	t.Helper()
	f.routinePublication = true
	f.r.refreshes = make(chan inventoryRefreshJob)
	m := capabilityLoop(f)
	m.refreshCapabilities = f.r.requestCapabilityRefresh
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-f.r.refreshes:
				f.r.handleInventoryRefresh(job)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return m
}

func enabledPackagePolicy() *agentv1.CapabilityPolicyObservation {
	return &agentv1.CapabilityPolicyObservation{
		State:          agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE,
		AppliedVersion: 7, AppliedSha256: bytes.Repeat([]byte{7}, sha256.Size), AcceptedAt: timestamppb.Now(),
		Capabilities: []*agentv1.CapabilityObservation{{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, Status: agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED}},
	}
}

func TestManagementCyclePublishesEntitlementChangesWithoutPolicyRotation(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.capability.observation = enabledPackagePolicy()
	accepted := proto.CloneOf(f.capability.observation)
	m := capabilityOwnerLoop(t, f)
	for _, missing := range []bool{false, true, false} {
		f.capability.observation = proto.CloneOf(accepted)
		if missing {
			f.capability.observation.Capabilities[0].Status = agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE
			f.capability.observation.Capabilities[0].Detail = "rhsm_registration_required"
		}
		if err := m.cycle(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := f.publishedHost.GetDetails().GetCapabilityPolicy(); !proto.Equal(got, f.capability.observation) {
			t.Fatalf("published protected status = %v want %v", got, f.capability.observation)
		}
		collections, reports := f.collections, f.hostCalls
		// A stable observation must not trigger another full native collection.
		if err := m.cycle(t.Context()); err != nil {
			t.Fatal(err)
		}
		if f.collections != collections || f.hostCalls != reports {
			t.Fatalf("stable status collected/reported again: collections=%d reports=%d", f.collections, f.hostCalls)
		}
		if len(f.capability.updates) != 0 || f.confirmations != 0 || f.publicationRequests != 0 {
			t.Fatal("local availability issued a policy or consumed a signed refresh result fence")
		}
	}
	if f.collections != 3 || f.hostCalls != 3 {
		t.Fatalf("changed status collections=%d reports=%d", f.collections, f.hostCalls)
	}
}

func TestManagementCapabilityPublicationRetainsAdmissionRefusalAndCoalesces(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.capability.observation = enabledPackagePolicy()
	m := capabilityOwnerLoop(t, f)
	if err := m.cycle(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.capability.observation = proto.CloneOf(f.capability.observation)
	f.capability.observation.Capabilities[0].Status = agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE
	f.capability.observation.Capabilities[0].Detail = "rhsm_registration_required"
	f.hostErr = connect.NewError(connect.CodeResourceExhausted, errors.New("ordinary host admission cooldown"))
	for range 2 {
		if err := m.cycle(t.Context()); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("ordinary admission refusal lost: %v", err)
		}
		if f.collections != 2 || f.publishedHost.GetDetails().GetCapabilityPolicy().GetCapabilities()[0].GetStatus() != agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED {
			t.Fatal("failed publication recollected or fabricated reported availability")
		}
	}
	f.hostErr = nil
	if err := m.cycle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.collections != 2 || !proto.Equal(f.publishedHost.GetDetails().GetCapabilityPolicy(), f.capability.observation) {
		t.Fatal("durably queued changed status did not drain without recollection")
	}
	if f.confirmations != 0 || f.publicationRequests != 0 || f.status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING {
		t.Fatal("ordinary capability publication altered signed action audit or confirmation")
	}
}

func TestCapabilityPolicyPublicationRunsWhenIssuanceFails(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.capability.observation = enabledPackagePolicy()
	f.capability.serverErr = errors.New("issuance unavailable")
	m := capabilityLoop(f)
	if err := m.synchronizeCapabilityPolicy(t.Context()); !errors.Is(err, f.capability.serverErr) {
		t.Fatalf("issuance failure = %v", err)
	}
	if len(f.capability.publications) != 1 || !proto.Equal(f.capability.publications[0], f.capability.observation) {
		t.Fatal("server issuance failure withheld protected local status")
	}
}

func TestCapabilityRefreshCancellationBeforeOwnerHandoff(t *testing.T) {
	r := &runner{refreshes: make(chan inventoryRefreshJob)}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.requestCapabilityRefresh(ctx, enabledPackagePolicy()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled handoff = %v", err)
	}
}

func TestManagementCapabilityPublicationCoalescesBeforeSpoolSynchronization(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.capability.observation = enabledPackagePolicy()
	f.syncErr = connect.NewError(connect.CodeUnavailable, errors.New("sync temporarily unavailable"))
	m := capabilityOwnerLoop(t, f)
	for range 2 {
		if err := m.cycle(t.Context()); connect.CodeOf(err) != connect.CodeUnavailable {
			t.Fatalf("sync failure lost: %v", err)
		}
		if f.collections != 1 || f.publishedHost != nil {
			t.Fatal("unbound waiting observation was recollected or reported")
		}
	}
	f.syncErr = nil
	if err := m.cycle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.collections != 1 || !proto.Equal(f.publishedHost.GetDetails().GetCapabilityPolicy(), f.capability.observation) {
		t.Fatal("waiting protected status did not publish after synchronization")
	}
}
