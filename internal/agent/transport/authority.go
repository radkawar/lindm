package transport

import (
	"context"
	"errors"
	"math"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
)

var ErrIdentityExpired = errors.New("device identity expired without a recoverable pending issuance")

type authorized struct {
	connection *agentv1.GetConnectionResponse
	servers    *connections
	epoch      uint64
}

type synchronized struct {
	*authorized
	state *devicev1.GetSyncStateResponse
}

// A transition spans several executor/server RPCs. The executor serializes
// individual calls, not a caller's captured credential and subsequent session.
type authorityGate chan struct{}

func (g authorityGate) lock(ctx context.Context) error {
	select {
	case g <- struct{}{}:
		if err := ctx.Err(); err != nil {
			g.unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g authorityGate) unlock() { <-g }

// synchronize fetches inventory high-water marks only for the inventory loop.
// Management uses establish directly and never advances the inventory poll.
func synchronize(ctx context.Context, executor agentv1connect.ExecutorServiceClient, cache *connectionCache, gate authorityGate) (*synchronized, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := gate.lock(ctx); err != nil {
		return nil, err
	}
	defer gate.unlock()
	authority, err := establishLocked(ctx, executor, cache)
	if err != nil {
		return nil, err
	}
	update, err := rpc(ctx, executor.GetAgentUpdate, &agentv1.GetAgentUpdateRequest{})
	if err != nil {
		return nil, err
	}
	// Read the root's durable result on every heartbeat. There is no network
	// acknowledgement to lose across restart and no transport-invented health.
	state, err := rpc(ctx, authority.servers.device.GetSyncState, &devicev1.GetSyncStateRequest{SessionEpoch: authority.epoch, AgentUpdate: update.GetStatus()})
	if err != nil {
		return nil, err
	}
	if state.GetSessionEpoch() != authority.epoch || state.GetHostSequence() > math.MaxInt64 || state.GetPackageSequence() > math.MaxInt64 {
		return nil, errors.New("server sync state does not bind the protected session")
	}
	return &synchronized{authorized: authority, state: state}, nil
}

func establish(ctx context.Context, executor agentv1connect.ExecutorServiceClient, cache *connectionCache, gate authorityGate) (*authorized, error) {
	if err := gate.lock(ctx); err != nil {
		return nil, err
	}
	defer gate.unlock()
	return establishLocked(ctx, executor, cache)
}

// establishLocked resolves rotation before acquiring a boot successor. Callers
// hold the shared gate until establishment (and inventory GetSyncState) finishes.
// Collection, upload and execution-trust synchronization never hold this gate.
func establishLocked(ctx context.Context, executor agentv1connect.ExecutorServiceClient, cache *connectionCache) (*authorized, error) {
	// A pending old-boot acquisition may need exact replay and then a second
	// acquisition for this boot. These are state transitions, not blind retries.
	for range 8 {
		connection, err := rpc(ctx, executor.GetConnection, &agentv1.GetConnectionRequest{})
		if err != nil {
			return nil, err
		}
		servers, err := cache.Get(executor, connection)
		if err != nil {
			return nil, err
		}
		if connection.GetDeviceActionReportOnly() {
			// The root has consumed live-root authority and closed its journal.
			// Only its pinned, already committed session remains usable. Never
			// attempt renewal, acquisition or any other persistent transition.
			if servers.device == nil || !connection.GetSessionEpochUsable() || connection.GetSessionEpoch() == 0 || connection.GetSessionEpoch() > math.MaxInt64 || connection.GetRenewalPending() {
				return nil, errors.New("executor report-only connection has no usable pinned session")
			}
			return &authorized{connection: connection, servers: servers, epoch: connection.GetSessionEpoch()}, nil
		}
		if connection.GetRenewalPending() {
			err = finishRenewal(ctx, executor, servers)
			if err != nil {
				return nil, err
			}
			continue
		}
		if servers.device == nil {
			return nil, ErrIdentityExpired
		}
		session, err := rpc(ctx, executor.PrepareSession, &agentv1.PrepareSessionRequest{})
		if err != nil {
			return nil, err
		}
		if pending := session.GetPending(); pending != nil {
			acquired, err := rpc(ctx, servers.device.AcquireSession, &devicev1.AcquireSessionRequest{AuthorityProof: pending.GetAuthorityProof()})
			if err == nil {
				_, err = rpc(ctx, executor.CommitSession, &agentv1.CommitSessionRequest{RequestId: pending.GetRequestId(), ServerEpoch: acquired.GetSessionEpoch()})
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		accepted := session.GetAccepted()
		if accepted == nil || accepted.GetSessionEpoch() == 0 || accepted.GetSessionEpoch() > math.MaxInt64 {
			return nil, errors.New("executor returned an invalid committed session")
		}
		if !connection.GetSessionEpochUsable() || connection.GetSessionEpoch() != accepted.GetSessionEpoch() {
			// Connection material was read before the state transition. Ask the
			// executor again rather than infer that an uncommitted fence is usable.
			continue
		}
		renewAfter := connection.GetRenewAfter()
		if renewAfter == nil || !renewAfter.IsValid() {
			return nil, errors.New("executor renewal schedule is missing")
		}
		if !time.Now().Before(renewAfter.AsTime()) {
			_, err := rpc(ctx, executor.PrepareRenewal, &agentv1.PrepareRenewalRequest{})
			if err != nil {
				return nil, err
			}
			continue
		}
		return &authorized{connection: connection, servers: servers, epoch: accepted.GetSessionEpoch()}, nil
	}
	return nil, errors.New("executor authority did not converge within its transition bound")
}

func finishRenewal(ctx context.Context, executor agentv1connect.ExecutorServiceClient, servers *connections) error {
	pending, err := rpc(ctx, executor.PrepareRenewal, &agentv1.PrepareRenewalRequest{})
	if err != nil {
		return err
	}
	// Retrieval never mints. It works after ordinary prolonged power loss even
	// when the former certificate has fallen outside its overlap or expired.
	retrieved, err := rpc(ctx, servers.enrollment.RetrieveIssuance, &enrollmentv1.RetrieveIssuanceRequest{AuthorityProof: pending.GetRetrievalProof()})
	var certificate []byte
	if err == nil {
		certificate = retrieved.GetCertificatePem()
	} else {
		// Unknown issuance and ineligible identity are intentionally uniform.
		// Only a still-valid old credential can attempt the exact staged mint;
		// expired authority never falls back to fresh enrollment or another key.
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			return err
		}
		if servers.device == nil {
			return ErrIdentityExpired
		}
		renewed, err := rpc(ctx, servers.device.RenewIdentity, &devicev1.RenewIdentityRequest{CsrPem: pending.GetCsrPem(), AuthorityProof: pending.GetAuthorityProof()})
		if err != nil {
			return err
		}
		certificate = renewed.GetCertificatePem()
	}
	_, err = rpc(ctx, executor.CommitRenewal, &agentv1.CommitRenewalRequest{IssuanceRequestId: pending.GetIssuanceRequestId(), CertificatePem: certificate})
	return err
}

// The local Unix client and remote HTTP clients use the same per-call deadline.
// State-changing calls are never automatically retried with newly generated input.
func rpc[Request, Response any](ctx context.Context, call func(context.Context, *connect.Request[Request]) (*connect.Response[Response], error), message *Request) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	response, err := call(ctx, connect.NewRequest(message))
	if err != nil {
		return nil, err
	}
	if response == nil || response.Msg == nil {
		return nil, errors.New("RPC returned no response message")
	}
	return response.Msg, nil
}
