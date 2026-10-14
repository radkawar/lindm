// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/localrpc"
	"lindm/internal/rpcreason"
)

// serveSessionSocket binds the real session listener in a temporary directory.
// Only logind is injected; the caller UID comes from the kernel.
func serveSessionSocket(t *testing.T, networkUID uint32, broker *assistanceBroker) agentv1connect.SessionServiceClient {
	t.Helper()
	dir := t.TempDir()
	// Like the packaged root:root 0755 directory: not group/world writable.
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- localrpc.ServeSession(ctx, localrpc.SessionListenConfig{Directory: dir, NetworkUID: networkUID}, &sessionService{broker: broker})
	}()
	stopped := false
	t.Cleanup(func() {
		cancel()
		if stopped {
			return
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("session listener: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("session listener did not stop")
		}
		if _, err := os.Lstat(filepath.Join(dir, localrpc.SessionSocketName)); !os.IsNotExist(err) {
			t.Errorf("shutdown left the session socket: %v", err)
		}
	})
	path := filepath.Join(dir, localrpc.SessionSocketName)
	deadline := time.Now().Add(5 * time.Second)
	for {
		// bind(2) publishes the socket inode before listen(2) accepts clients.
		// Observe a real connection, not just the pathname, before the first RPC.
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		if err == nil {
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			break
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("session listener stopped before binding: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("session socket did not accept connections")
		}
		time.Sleep(10 * time.Millisecond)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return agentv1connect.NewSessionServiceClient(&http.Client{Transport: transport}, localrpc.SessionBaseURL)
}

func TestSessionSocketBindsPeerCredentialToLogindSession(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		t.Skip("the session socket refuses UID 0; run as an unprivileged user")
	}
	f := newAssistanceFixture(t, true)
	f.logind = []actionprovider.LogindSession{{ID: "42", UID: uid, User: "tester", Class: "user", Type: "wayland", Active: true}}
	directive := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "")}
	id := directive.GetInvitation().GetSessionId()
	f.network(directive)
	client := serveSessionSocket(t, uid+1, f.broker)
	response, err := client.SyncSession(t.Context(), connect.NewRequest(&agentv1.SyncSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if local := response.Msg.GetLocalSession(); local.GetUid() != uid || local.GetLogindSessionId() != "42" {
		t.Fatalf("bound local session = %v, want kernel uid %d", local, uid)
	}
	if directives := response.Msg.GetDirectives(); len(directives) != 1 || directives[0].GetInvitation().GetSessionId() != id {
		t.Fatalf("directives = %v", directives)
	}
	if _, err := client.SyncSession(t.Context(), connect.NewRequest(&agentv1.SyncSessionRequest{Reports: []*agentv1.SessionAssistanceReport{{SessionId: id, Phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED}}})); err != nil {
		t.Fatal(err)
	}
	if got := f.network(directive)[id]; got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED || got.GetLocalSession().GetUid() != uid {
		t.Fatalf("report after socket consent = %v", got)
	}
	// Eager schema validation runs before the broker.
	if _, err := client.SyncSession(t.Context(), connect.NewRequest(&agentv1.SyncSessionRequest{Reports: []*agentv1.SessionAssistanceReport{{SessionId: "not-a-uuid", Phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED}}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid report: %v", err)
	}
	f.setLogind("42", func(s *actionprovider.LogindSession) { s.Locked = true })
	_, err = client.SyncSession(t.Context(), connect.NewRequest(&agentv1.SyncSessionRequest{}))
	var connectErr *connect.Error
	if connect.CodeOf(err) != connect.CodePermissionDenied || !errors.As(err, &connectErr) || rpcreason.Get(connectErr) != "no_graphical_session" {
		t.Fatalf("locked caller: %v", err)
	}
}

func TestSessionSocketRefusesNetworkAccount(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		t.Skip("the session socket refuses UID 0; run as an unprivileged user")
	}
	f := newAssistanceFixture(t, true)
	f.logind = []actionprovider.LogindSession{{ID: "42", UID: uid, User: "tester", Class: "user", Type: "wayland", Active: true}}
	client := serveSessionSocket(t, uid, f.broker)
	if _, err := client.SyncSession(t.Context(), connect.NewRequest(&agentv1.SyncSessionRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("network account reached SessionService: %v", err)
	}
}
