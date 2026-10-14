// SPDX-License-Identifier: Apache-2.0

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
	"lindm/internal/rpcreason"
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
	if handler == nil || cfg.NetworkUID == 0 || cfg.NetworkGID == 0 || cfg.SocketName == "" {
		return errors.New("invalid executor listener")
	}
	compiled, err := executorValidator()
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
	return serveSocket(ctx, cfg.Directory, cfg.SocketName, executorAccess(cfg.NetworkGID), mux)
}

// executorValidator compiles every executor request eagerly. Lazy compilation
// is off, so a request missing here fails every call with "no evaluator
// available" (ExchangeAssistanceRecording did on Fedora 44,
// layers-fedora44-files-02).
func executorValidator() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(
		&agentv1.PrepareBootstrapRequest{},
		&agentv1.InstallEnrollmentRequest{},
		&agentv1.ImportOfflineEnrollmentRequest{},
		&agentv1.GetConnectionRequest{},
		&agentv1.SignTLSClientMessageRequest{},
		&agentv1.PrepareSessionRequest{},
		&agentv1.CommitSessionRequest{},
		&agentv1.PrepareRenewalRequest{},
		&agentv1.CommitRenewalRequest{},
		&agentv1.PrepareEncryptionKeyRequest{},
		&agentv1.AcknowledgeEncryptionKeyRequest{},
		&agentv1.UpdateExecutionTrustRequest{},
		&agentv1.GetExecutionTrustRequest{},
		&agentv1.UpdateCapabilityPolicyRequest{},
		&agentv1.GetCapabilityPolicyRequest{},
		&agentv1.GetRecoveryReadinessRequest{},
		&agentv1.GetPatchStatusRequest{},
		&agentv1.GetApprovedConfigurationRequest{},
		&agentv1.PrepareResourceExecutionRequest{},
		&agentv1.CancelResourcePreparationRequest{},
		&agentv1.StartResourceExecutionRequest{},
		&agentv1.GetResourceExecutionRequest{},
		&agentv1.AttestResourceExecutionRequest{},
		&agentv1.PrepareDeviceActionRequest{},
		&agentv1.StartDeviceActionRequest{},
		&agentv1.GetDeviceActionRequest{},
		&agentv1.AttestDeviceActionRequest{},
		&agentv1.ConfirmDeviceActionEscrowRequest{},
		&agentv1.ConfirmDeviceActionInventoryRequest{},
		&agentv1.SupplyDeviceActionCredentialRequest{},
		&agentv1.PrepareDeviceActionRecoveryRequest{},
		&agentv1.CommitDeviceActionRecoveryRequest{},
		&agentv1.ExchangeAgentUpdateRequest{},
		&agentv1.GetAgentUpdateRequest{},
		&agentv1.StatusRequest{},
		&agentv1.SyncAssistanceRequest{},
		&agentv1.ExchangeAssistanceRecordingRequest{},
	), protovalidate.WithDisableLazy())
}

func serveSocket(ctx context.Context, directory, name string, access socketAccess, handler http.Handler) error {
	dir, err := openRuntimeDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	owned, err := listenSocket(dir, name, access)
	if err != nil {
		return err
	}
	defer func() { _ = owned.close() }()
	server := &http.Server{
		Handler:           handler,
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
	uid, ok := PeerUID(r.Context())
	if !ok {
		writeDenied(w, r, connect.CodeUnauthenticated, "unauthenticated")
		return
	}
	if err := authorize(r.URL.Path, uid, g.networkUID); err != nil {
		slog.Warn("local rpc denied", "procedure", r.URL.Path, "uid", uid)
		writeDenied(w, r, connect.CodePermissionDenied, "permission_denied")
		return
	}
	admit(w, r, g.slots, g.next)
}

func admit(w http.ResponseWriter, r *http.Request, slots chan struct{}, next http.Handler) {
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		writeDenied(w, r, connect.CodeResourceExhausted, "resource_exhausted")
		return
	}
	next.ServeHTTP(w, r)
}

func authorize(procedure string, uid, networkUID uint32) error {
	rootOnly := procedure == agentv1connect.ExecutorServicePrepareBootstrapProcedure || procedure == agentv1connect.ExecutorServiceInstallEnrollmentProcedure || procedure == agentv1connect.ExecutorServiceImportOfflineEnrollmentProcedure || procedure == agentv1connect.ExecutorServiceSupplyDeviceActionCredentialProcedure
	known := rootOnly ||
		procedure == agentv1connect.ExecutorServiceGetConnectionProcedure ||
		procedure == agentv1connect.ExecutorServiceSignTLSClientMessageProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareSessionProcedure ||
		procedure == agentv1connect.ExecutorServiceCommitSessionProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareRenewalProcedure ||
		procedure == agentv1connect.ExecutorServiceCommitRenewalProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareEncryptionKeyProcedure ||
		procedure == agentv1connect.ExecutorServiceAcknowledgeEncryptionKeyProcedure ||
		procedure == agentv1connect.ExecutorServiceUpdateExecutionTrustProcedure ||
		procedure == agentv1connect.ExecutorServiceGetExecutionTrustProcedure ||
		procedure == agentv1connect.ExecutorServiceUpdateCapabilityPolicyProcedure ||
		procedure == agentv1connect.ExecutorServiceGetCapabilityPolicyProcedure ||
		procedure == agentv1connect.ExecutorServiceGetRecoveryReadinessProcedure ||
		procedure == agentv1connect.ExecutorServiceGetPatchStatusProcedure ||
		procedure == agentv1connect.ExecutorServiceGetApprovedConfigurationProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareResourceExecutionProcedure ||
		procedure == agentv1connect.ExecutorServiceCancelResourcePreparationProcedure ||
		procedure == agentv1connect.ExecutorServiceStartResourceExecutionProcedure ||
		procedure == agentv1connect.ExecutorServiceGetResourceExecutionProcedure ||
		procedure == agentv1connect.ExecutorServiceAttestResourceExecutionProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareDeviceActionProcedure ||
		procedure == agentv1connect.ExecutorServiceStartDeviceActionProcedure ||
		procedure == agentv1connect.ExecutorServiceGetDeviceActionProcedure ||
		procedure == agentv1connect.ExecutorServiceAttestDeviceActionProcedure ||
		procedure == agentv1connect.ExecutorServiceConfirmDeviceActionEscrowProcedure ||
		procedure == agentv1connect.ExecutorServiceConfirmDeviceActionInventoryProcedure ||
		procedure == agentv1connect.ExecutorServicePrepareDeviceActionRecoveryProcedure ||
		procedure == agentv1connect.ExecutorServiceCommitDeviceActionRecoveryProcedure ||
		procedure == agentv1connect.ExecutorServiceExchangeAgentUpdateProcedure ||
		procedure == agentv1connect.ExecutorServiceGetAgentUpdateProcedure ||
		procedure == agentv1connect.ExecutorServiceStatusProcedure ||
		procedure == agentv1connect.ExecutorServiceSyncAssistanceProcedure ||
		procedure == agentv1connect.ExecutorServiceExchangeAssistanceRecordingProcedure
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

// PeerUID returns the SO_PEERCRED UID the kernel recorded when the local
// connection serving ctx was established. ok is false for any other context.
func PeerUID(ctx context.Context) (uint32, bool) {
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
		if cred.Uid != 0 {
			if cred.Gid == 0 {
				controlErr = errors.New("unprivileged peer belongs to group zero")
				return
			}
			if err := rejectRootPeerGroup(int(fd)); err != nil {
				controlErr = err
				return
			}
		}
		uid = cred.Uid
	}); err != nil {
		return 0, err
	}
	return uid, controlErr
}

func writeDenied(w http.ResponseWriter, r *http.Request, code connect.Code, reason string) {
	err := rpcreason.Error(code, reason)
	if connect.NewErrorWriter().IsSupported(r) {
		_ = connect.NewErrorWriter().Write(w, r, err)
		return
	}
	http.Error(w, reason, http.StatusForbidden)
}
