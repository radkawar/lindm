//go:build linux

package localrpc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	"lindm/internal/agent/statefs"
)

type recordingHandler struct {
	agentv1connect.UnimplementedExecutorServiceHandler
	uid uint32
	ok  bool
}

func (h *recordingHandler) PrepareBootstrap(ctx context.Context, _ *connect.Request[agentv1.PrepareBootstrapRequest]) (*connect.Response[agentv1.PrepareBootstrapResponse], error) {
	h.capture(ctx)
	return connect.NewResponse(&agentv1.PrepareBootstrapResponse{}), nil
}
func (h *recordingHandler) InstallEnrollment(context.Context, *connect.Request[agentv1.InstallEnrollmentRequest]) (*connect.Response[agentv1.InstallEnrollmentResponse], error) {
	return connect.NewResponse(&agentv1.InstallEnrollmentResponse{}), nil
}
func (h *recordingHandler) GetConnection(context.Context, *connect.Request[agentv1.GetConnectionRequest]) (*connect.Response[agentv1.GetConnectionResponse], error) {
	return connect.NewResponse(&agentv1.GetConnectionResponse{}), nil
}
func (h *recordingHandler) SignTLSClientMessage(context.Context, *connect.Request[agentv1.SignTLSClientMessageRequest]) (*connect.Response[agentv1.SignTLSClientMessageResponse], error) {
	return connect.NewResponse(&agentv1.SignTLSClientMessageResponse{}), nil
}
func (h *recordingHandler) PrepareSession(context.Context, *connect.Request[agentv1.PrepareSessionRequest]) (*connect.Response[agentv1.PrepareSessionResponse], error) {
	return connect.NewResponse(&agentv1.PrepareSessionResponse{}), nil
}
func (h *recordingHandler) CommitSession(context.Context, *connect.Request[agentv1.CommitSessionRequest]) (*connect.Response[agentv1.CommitSessionResponse], error) {
	return connect.NewResponse(&agentv1.CommitSessionResponse{}), nil
}
func (h *recordingHandler) PrepareRenewal(context.Context, *connect.Request[agentv1.PrepareRenewalRequest]) (*connect.Response[agentv1.PrepareRenewalResponse], error) {
	return connect.NewResponse(&agentv1.PrepareRenewalResponse{}), nil
}
func (h *recordingHandler) CommitRenewal(context.Context, *connect.Request[agentv1.CommitRenewalRequest]) (*connect.Response[agentv1.CommitRenewalResponse], error) {
	return connect.NewResponse(&agentv1.CommitRenewalResponse{}), nil
}
func (h *recordingHandler) UpdateExecutionTrust(ctx context.Context, _ *connect.Request[agentv1.UpdateExecutionTrustRequest]) (*connect.Response[agentv1.UpdateExecutionTrustResponse], error) {
	h.capture(ctx)
	return connect.NewResponse(&agentv1.UpdateExecutionTrustResponse{RootVersion: 1, DelegationVersion: 1, ExpiresAt: timestamppb.New(time.Unix(1, 0).UTC())}), nil
}
func (h *recordingHandler) Status(ctx context.Context, _ *connect.Request[agentv1.StatusRequest]) (*connect.Response[agentv1.StatusResponse], error) {
	h.capture(ctx)
	return connect.NewResponse(&agentv1.StatusResponse{}), nil
}
func (h *recordingHandler) capture(ctx context.Context) { h.uid, h.ok = peerUID(ctx) }

func TestAuthorizeDeniesWrongUIDAndRootMethods(t *testing.T) {
	if err := authorize(agentv1connect.ExecutorServiceStatusProcedure, 50, 40); err == nil {
		t.Fatal("wrong local UID was authorized")
	}
	if err := authorize(agentv1connect.ExecutorServicePrepareBootstrapProcedure, 40, 40); err == nil {
		t.Fatal("network UID was authorized for a root method")
	}
	if err := authorize(agentv1connect.ExecutorServiceStatusProcedure, 40, 40); err != nil {
		t.Fatal(err)
	}
	if err := authorize(agentv1connect.ExecutorServicePrepareBootstrapProcedure, 0, 40); err != nil {
		t.Fatalf("root was denied: %v", err)
	}
	if err := authorize(agentv1connect.ExecutorServiceUpdateExecutionTrustProcedure, 40, 40); err != nil {
		t.Fatal(err)
	}
	if err := authorize(agentv1connect.ExecutorServiceUpdateExecutionTrustProcedure, 0, 40); err != nil {
		t.Fatalf("root was denied execution trust relay: %v", err)
	}
	if err := authorize(agentv1connect.ExecutorServiceUpdateExecutionTrustProcedure, 50, 40); err == nil {
		t.Fatal("wrong local UID was authorized to relay execution trust")
	}
	for _, procedure := range []string{
		agentv1connect.ExecutorServicePrepareServiceExecutionProcedure,
		agentv1connect.ExecutorServiceStartServiceExecutionProcedure,
		agentv1connect.ExecutorServiceGetServiceExecutionProcedure,
	} {
		for _, uid := range []uint32{0, 40} {
			if err := authorize(procedure, uid, 40); err != nil {
				t.Fatalf("authorized peer %d denied %s: %v", uid, procedure, err)
			}
		}
		if err := authorize(procedure, 50, 40); err == nil {
			t.Fatalf("wrong UID authorized %s", procedure)
		}
	}
	if err := authorize(agentv1connect.ExecutorServiceInstallEnrollmentProcedure, 40, 40); err == nil {
		t.Fatal("network UID was authorized for enrollment")
	}
	if err := authorize("/lindm.agent.v1.ExecutorService/NotAMethod", 0, 40); err == nil {
		t.Fatal("unknown procedure was authorized")
	}
}

func TestSocketUsesPeerCredentialsAndMethodACL(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := statefs.OpenDirectory(dir); err == nil {
		t.Fatal("statefs.OpenDirectory accepted a traversable runtime directory")
	}
	networkUID := uint32(os.Geteuid())
	if networkUID == 0 {
		networkUID = 1
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handler := &recordingHandler{}
	errc := make(chan error, 1)
	go func() {
		errc <- Serve(ctx, ListenConfig{Directory: dir, SocketName: "executor.sock", NetworkUID: networkUID, NetworkGID: uint32(os.Getegid())}, handler)
	}()
	// Fixture dial does not weaken production Dial, which still requires UID 0.
	client, cleanup, err := dial(waitSocket(t, filepath.Join(dir, "executor.sock")), func(net.Conn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	if _, err := client.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{})); err != nil {
		t.Fatal(err)
	}
	if !handler.ok || handler.uid != uint32(os.Getuid()) {
		t.Fatalf("SO_PEERCRED uid = %d ok=%v, want %d", handler.uid, handler.ok, os.Getuid())
	}
	if _, err := client.UpdateExecutionTrust(t.Context(), connect.NewRequest(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: []byte{1}})); err != nil {
		t.Fatalf("admitted UID was denied execution trust relay: %v", err)
	}
	if _, err := client.PrepareServiceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareServiceExecutionRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("service intent request bypassed eager schema: %v", err)
	}
	if _, err := client.StartServiceExecution(t.Context(), connect.NewRequest(&agentv1.StartServiceExecutionRequest{ActionId: "not-a-uuid", StartGrantEnvelope: []byte{1}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("service start request bypassed eager schema: %v", err)
	}
	if _, err := client.GetServiceExecution(t.Context(), connect.NewRequest(&agentv1.GetServiceExecutionRequest{ActionId: "not-a-uuid"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("service lookup request bypassed eager schema: %v", err)
	}
	if os.Geteuid() != 0 {
		if _, err := client.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{Resume: true})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("network UID called a root method: %v", err)
		}
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("executor listener did not exit")
	}
	if _, err := os.Lstat(filepath.Join(dir, "executor.sock")); !os.IsNotExist(err) {
		t.Fatalf("shutdown left the owned socket: %v", err)
	}
}

func TestProductionDialRejectsNonRootExecutor(t *testing.T) {
	if os.Geteuid() == 0 {
		return
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = Serve(ctx, ListenConfig{Directory: dir, SocketName: "executor.sock", NetworkUID: uint32(os.Geteuid()), NetworkGID: uint32(os.Getegid())}, &recordingHandler{})
	}()
	client, cleanup, err := Dial(waitSocket(t, filepath.Join(dir, "executor.sock")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	if _, err := client.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{})); err == nil {
		t.Fatal("production Dial sent a request to a non-root executor")
	}
}

func TestWrongUIDIsDeniedOnSocket(t *testing.T) {
	if os.Geteuid() == 0 {
		return
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = Serve(ctx, ListenConfig{Directory: dir, SocketName: "executor.sock", NetworkUID: uint32(os.Geteuid()) + 1, NetworkGID: uint32(os.Getegid())}, &recordingHandler{})
	}()
	client, cleanup, err := dial(waitSocket(t, filepath.Join(dir, "executor.sock")), func(net.Conn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	if _, err := client.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong local UID was accepted: %v", err)
	}
	if _, err := client.UpdateExecutionTrust(t.Context(), connect.NewRequest(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: []byte{1}})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong local UID relayed execution trust: %v", err)
	}
}

func TestTCPConnectionHasNoPeerCredential(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		_, err = peerCredential(conn)
		_ = conn.Close()
		done <- err
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-done; err == nil {
		t.Fatal("TCP connection produced a unix peer credential")
	}
}

func waitSocket(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("executor socket was not created")
	return ""
}

var _ agentv1connect.ExecutorServiceHandler = (*recordingHandler)(nil)
