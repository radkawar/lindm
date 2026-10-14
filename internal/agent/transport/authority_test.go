// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
)

func TestConcurrentEstablishmentDoesNotFenceInventory(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cancelWaiter bool
	}{{"renewal-exclusion", false}, {"canceled-waiter", true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				root := &establishmentRaceRoot{entered: make(chan struct{}), release: make(chan struct{}), renewAfter: time.Now().Add(time.Hour)}
				gate := make(authorityGate, 1)
				connection, err := root.GetConnection(t.Context(), connect.NewRequest(&agentv1.GetConnectionRequest{}))
				if err != nil {
					t.Fatal(err)
				}
				cache := func() *connectionCache {
					return &connectionCache{connection: proto.CloneOf(connection.Msg), servers: &connections{device: &establishmentRaceDevice{}, enrollment: &establishmentRaceIssuance{}}}
				}
				inventory := make(chan error, 1)
				go func() { _, err := synchronize(t.Context(), root, cache(), gate); inventory <- err }()
				<-root.entered
				// Renewal becomes due after inventory captured its connection. The
				// executor excludes PrepareSession while a renewal is pending.
				root.mu.Lock()
				root.renewAfter = time.Now().Add(-time.Minute)
				root.mu.Unlock()
				ctx, cancel := context.WithCancel(t.Context())
				management := make(chan error, 1)
				go func() { management <- synchronizeExecutionTrust(ctx, root, cache(), gate) }()
				synctest.Wait()
				if tc.cancelWaiter {
					cancel()
					if err := <-management; !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled establishment waiter: %v", err)
					}
				}
				close(root.release)
				inventoryErr := <-inventory
				cancel()
				if !tc.cancelWaiter {
					<-management
				}
				if inventoryErr != nil {
					t.Fatalf("healthy inventory establishment was fenced by concurrent renewal: %v", inventoryErr)
				}
			})
		})
	}
}

// Model the pending-renewal/session exclusion, not a successful RPC echo.
// Cached transports isolate this interleaving from sockets and cryptography.
type establishmentRaceRoot struct {
	agentv1connect.ExecutorServiceClient
	mu               sync.Mutex
	entered, release chan struct{}
	paused, pending  bool
	renewAfter       time.Time
}

func (r *establishmentRaceRoot) GetConnection(context.Context, *connect.Request[agentv1.GetConnectionRequest]) (*connect.Response[agentv1.GetConnectionResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return connect.NewResponse(&agentv1.GetConnectionResponse{SessionEpoch: 1, SessionEpochUsable: true, RenewalPending: r.pending, RenewAfter: timestamppb.New(r.renewAfter)}), nil
}

func (*establishmentRaceRoot) GetAgentUpdate(context.Context, *connect.Request[agentv1.GetAgentUpdateRequest]) (*connect.Response[agentv1.GetAgentUpdateResponse], error) {
	return connect.NewResponse(&agentv1.GetAgentUpdateResponse{}), nil
}

func (r *establishmentRaceRoot) PrepareSession(ctx context.Context, _ *connect.Request[agentv1.PrepareSessionRequest]) (*connect.Response[agentv1.PrepareSessionResponse], error) {
	r.mu.Lock()
	pause := !r.paused
	r.paused = true
	r.mu.Unlock()
	if pause {
		close(r.entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.release:
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("renewal_pending"))
	}
	return connect.NewResponse(&agentv1.PrepareSessionResponse{Result: &agentv1.PrepareSessionResponse_Accepted{Accepted: &agentv1.AcceptedSession{SessionEpoch: 1}}}), nil
}

func (r *establishmentRaceRoot) PrepareRenewal(context.Context, *connect.Request[agentv1.PrepareRenewalRequest]) (*connect.Response[agentv1.PrepareRenewalResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = true
	return connect.NewResponse(&agentv1.PrepareRenewalResponse{}), nil
}

type establishmentRaceDevice struct {
	devicev1connect.DeviceServiceClient
}

func (*establishmentRaceDevice) GetSyncState(context.Context, *connect.Request[devicev1.GetSyncStateRequest]) (*connect.Response[devicev1.GetSyncStateResponse], error) {
	return connect.NewResponse(&devicev1.GetSyncStateResponse{SessionEpoch: 1}), nil
}

type establishmentRaceIssuance struct {
	enrollmentv1connect.EnrollmentServiceClient
}

func (*establishmentRaceIssuance) RetrieveIssuance(ctx context.Context, _ *connect.Request[enrollmentv1.RetrieveIssuanceRequest]) (*connect.Response[enrollmentv1.RetrieveIssuanceResponse], error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
