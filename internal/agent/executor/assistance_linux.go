//go:build linux

package executor

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	"lindm/internal/agent/localrpc"
	"lindm/internal/rpcreason"
)

// WithRemoteAssistance applies device remote-assistance policy. Absent or
// disabled policy ends every invitation with DISABLED.
func WithRemoteAssistance(config *agentv1.RemoteAssistanceConfig) Option {
	return func(s *Service) {
		s.assistanceEnabled = config.GetEnabled()
		s.assistanceCeiling = proto.CloneOf(config.GetPolicyCeiling())
	}
}

// SyncAssistance is the network process's relay of the server's complete
// assistance directives. Reports carry local identities only from logind.
func (s *Service) SyncAssistance(ctx context.Context, req *connect.Request[agentv1.SyncAssistanceRequest]) (*connect.Response[agentv1.SyncAssistanceResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	response, err := s.assistance.syncNetwork(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(response), nil
}

// sessionService is the SessionService handler for the session socket. The
// caller is identified solely by the SO_PEERCRED UID recorded on its connection.
type sessionService struct {
	broker        *assistanceBroker
	reboots       rebootSessionProvider
	rebootPrompts map[uint32]rebootPrompt
}

var _ agentv1connect.SessionServiceHandler = (*sessionService)(nil)

func (h *sessionService) SyncSession(ctx context.Context, req *connect.Request[agentv1.SyncSessionRequest]) (*connect.Response[agentv1.SyncSessionResponse], error) {
	uid, ok := localrpc.PeerUID(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := h.broker.syncSession(ctx, uid, req.Msg)
	switch {
	case errors.Is(err, errNoGraphicalSession):
		return nil, rpcreason.Error(connect.CodePermissionDenied, "no_graphical_session")
	case errors.Is(err, errAmbiguousGraphicalSession):
		return nil, rpcreason.Error(connect.CodePermissionDenied, "ambiguous_graphical_session")
	case errors.Is(err, errLogindUnavailable):
		return nil, rpcreason.Error(connect.CodeUnavailable, "logind_unavailable")
	case err != nil:
		return nil, mapError(err)
	}
	if h.reboots != nil {
		if err := h.syncReboot(ctx, uid, req.Msg, response); err != nil {
			return nil, mapError(err)
		}
	}
	return noStore(response), nil
}
