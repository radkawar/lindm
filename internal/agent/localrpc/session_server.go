// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localrpc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"connectrpc.com/validate"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
)

const (
	maxSessionMessageBytes = 256 << 10
	maxSessionInFlight     = 8
)

// SessionListenConfig is the frozen session-helper listener identity. The
// socket name is fixed; NetworkUID is refused like UID 0.
type SessionListenConfig struct {
	Directory  string
	NetworkUID uint32
}

// ServeSession serves only SessionService on <Directory>/session.sock (0666
// when root). It admits any local UID except 0 and the network account at the
// transport layer; the handler binds the caller to its logind session using
// PeerUID. It shares no slots or limits with the executor socket.
func ServeSession(ctx context.Context, cfg SessionListenConfig, handler agentv1connect.SessionServiceHandler) error {
	if handler == nil || cfg.NetworkUID == 0 || cfg.Directory == "" {
		return errors.New("invalid session listener")
	}
	compiled, err := protovalidate.New(protovalidate.WithMessages(&agentv1.SyncSessionRequest{}), protovalidate.WithDisableLazy())
	if err != nil {
		return err
	}
	path, rpc := agentv1connect.NewSessionServiceHandler(handler,
		connect.WithInterceptors(validate.NewInterceptor(validate.WithValidator(compiled))),
		connect.WithReadMaxBytes(maxSessionMessageBytes),
		connect.WithSendMaxBytes(maxSessionMessageBytes),
		connect.WithCodec(strictJSONCodec{name: "json"}),
		connect.WithCodec(strictJSONCodec{name: "json; charset=utf-8"}),
	)
	limited := http.MaxBytesHandler(rpc, maxSessionMessageBytes+maxMessageOverhead)
	mux := http.NewServeMux()
	mux.Handle(path, &sessionGate{networkUID: cfg.NetworkUID, next: limited, slots: make(chan struct{}, maxSessionInFlight)})
	return serveSocket(ctx, cfg.Directory, SessionSocketName, sessionAccess(), mux)
}

type sessionGate struct {
	networkUID uint32
	next       http.Handler
	slots      chan struct{}
}

func (g *sessionGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uid, ok := PeerUID(r.Context())
	if !ok {
		writeDenied(w, r, connect.CodeUnauthenticated, "unauthenticated")
		return
	}
	// Root, the network account and group-0 peers (refused by peerCredential)
	// never act as a desktop user. Session binding is the handler's job.
	if uid == 0 || uid == g.networkUID || r.URL.Path != agentv1connect.SessionServiceSyncSessionProcedure {
		slog.Warn("session rpc denied", "procedure", r.URL.Path, "uid", uid)
		writeDenied(w, r, connect.CodePermissionDenied, "permission_denied")
		return
	}
	admit(w, r, g.slots, g.next)
}
