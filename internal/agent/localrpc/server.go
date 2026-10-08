//go:build linux

package localrpc

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
)

const (
	maxMessageBytes    = 1 << 20
	maxMessageOverhead = 16 << 10
	maxInFlight        = 16
)

// ListenConfig is the frozen listener identity. NetworkUID is the numeric UID
// resolved once by configuration, not a value supplied per request.
type ListenConfig struct {
	Directory  string
	SocketName string
	NetworkUID uint32
	NetworkGID uint32
}

// Serve listens on a root-owned Unix socket, authorizes SO_PEERCRED, and
// unlinks only that socket on shutdown. It does not remove the runtime directory.
func Serve(ctx context.Context, cfg ListenConfig, handler agentv1connect.ExecutorServiceHandler) error {
	if handler == nil || cfg.NetworkUID == 0 || cfg.SocketName == "" {
		return errors.New("invalid executor listener")
	}
	dir, err := openRuntimeDirectory(cfg.Directory)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	owned, err := listenSocket(dir, cfg.SocketName, cfg.NetworkGID)
	if err != nil {
		return err
	}
	defer func() { _ = owned.close() }()
	compiled, err := protovalidate.New(protovalidate.WithMessages(
		&agentv1.PrepareBootstrapRequest{},
		&agentv1.InstallEnrollmentRequest{},
		&agentv1.GetConnectionRequest{},
		&agentv1.SignTLSClientMessageRequest{},
		&agentv1.PrepareSessionRequest{},
		&agentv1.CommitSessionRequest{},
		&agentv1.PrepareRenewalRequest{},
		&agentv1.CommitRenewalRequest{},
		&agentv1.UpdateExecutionTrustRequest{},
		&agentv1.PrepareServiceExecutionRequest{},
		&agentv1.StartServiceExecutionRequest{},
		&agentv1.GetServiceExecutionRequest{},
		&agentv1.StatusRequest{},
	), protovalidate.WithDisableLazy())
	if err != nil {
		return err
	}
	path, rpc := agentv1connect.NewExecutorServiceHandler(handler,
		connect.WithInterceptors(validate.NewInterceptor(validate.WithValidator(compiled))),
		connect.WithReadMaxBytes(maxMessageBytes),
		connect.WithSendMaxBytes(maxMessageBytes),
		connect.WithCodec(strictJSONCodec{name: "json"}),
		connect.WithCodec(strictJSONCodec{name: "json; charset=utf-8"}),
	)
	limited := http.MaxBytesHandler(rpc, maxMessageBytes+maxMessageOverhead)
	mux := http.NewServeMux()
	mux.Handle(path, &peerGate{networkUID: cfg.NetworkUID, next: limited, slots: make(chan struct{}, maxInFlight)})
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ConnContext:       connContext,
	}
	errc := make(chan error, 1)
	go func() { errc <- server.Serve(owned.listener) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		<-errc
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

type peerGate struct {
	networkUID uint32
	next       http.Handler
	slots      chan struct{}
}

func (g *peerGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uid, ok := peerUID(r.Context())
	if !ok {
		writeDenied(w, r, connect.CodeUnauthenticated, "unauthenticated")
		return
	}
	if err := authorize(r.URL.Path, uid, g.networkUID); err != nil {
		slog.Warn("local rpc denied", "procedure", r.URL.Path, "uid", uid)
		writeDenied(w, r, connect.CodePermissionDenied, "permission_denied")
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		writeDenied(w, r, connect.CodeResourceExhausted, "resource_exhausted")
		return
	}
	g.next.ServeHTTP(w, r)
}

func authorize(procedure string, uid, networkUID uint32) error {
	rootOnly := procedure == agentv1connect.ExecutorServicePrepareBootstrapProcedure || procedure == agentv1connect.ExecutorServiceInstallEnrollmentProcedure
	known := rootOnly ||
		procedure == agentv1connect.ExecutorServiceGetConnectionProcedure ||
		procedure == agentv1connect.ExecutorServiceSignTLSClientMessageProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareSessionProcedure ||
		procedure == agentv1connect.ExecutorServiceCommitSessionProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareRenewalProcedure ||
		procedure == agentv1connect.ExecutorServiceCommitRenewalProcedure ||
		procedure == agentv1connect.ExecutorServiceUpdateExecutionTrustProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareServiceExecutionProcedure ||
		procedure == agentv1connect.ExecutorServiceStartServiceExecutionProcedure ||
		procedure == agentv1connect.ExecutorServiceGetServiceExecutionProcedure ||
		procedure == agentv1connect.ExecutorServiceStatusProcedure
	if !known || uid != 0 && (uid != networkUID || rootOnly) {
		return errors.New("permission denied")
	}
	return nil
}

type peerKey struct{}

type peerCred struct {
	uid uint32
	ok  bool
}

func connContext(ctx context.Context, conn net.Conn) context.Context {
	uid, err := peerCredential(conn)
	if err != nil {
		return context.WithValue(ctx, peerKey{}, peerCred{})
	}
	return context.WithValue(ctx, peerKey{}, peerCred{uid: uid, ok: true})
}

func peerUID(ctx context.Context) (uint32, bool) {
	cred, _ := ctx.Value(peerKey{}).(peerCred)
	return cred.uid, cred.ok
}

func peerCredential(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok || unixConn == nil {
		return 0, errors.New("not a unix connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		uid = cred.Uid
	}); err != nil {
		return 0, err
	}
	return uid, controlErr
}

func writeDenied(w http.ResponseWriter, r *http.Request, code connect.Code, reason string) {
	err := connect.NewError(code, errors.New(reason))
	err.Meta().Set("Lindm-Reason", reason)
	if connect.NewErrorWriter().IsSupported(r) {
		_ = connect.NewErrorWriter().Write(w, r, err)
		return
	}
	http.Error(w, reason, http.StatusForbidden)
}
