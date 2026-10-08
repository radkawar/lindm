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
	state      *devicev1.GetSyncStateResponse
}

// establish resolves a protected rotation before acquiring a boot successor.
// Every receipt is committed locally before an observation can use its fence.
func establish(ctx context.Context, executor agentv1connect.ExecutorServiceClient, cache *connectionCache) (*authorized, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
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
		state, err := rpc(ctx, servers.device.GetSyncState, &devicev1.GetSyncStateRequest{SessionEpoch: accepted.GetSessionEpoch()})
		if err != nil {
			return nil, err
		}
		if state.GetSessionEpoch() != accepted.GetSessionEpoch() || state.GetHostSequence() > math.MaxInt64 || state.GetPackageSequence() > math.MaxInt64 {
			return nil, errors.New("server sync state does not bind the protected session")
		}
		return &authorized{connection: connection, servers: servers, epoch: accepted.GetSessionEpoch(), state: state}, nil
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
