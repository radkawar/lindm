//go:build linux

package localrpc

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// TestDialSessionRefusesNonRootServer checks the client side of the session
// socket: a socket served by a non-root process is never sent a request.
func TestDialSessionRefusesNonRootServer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test server must be an unprivileged peer")
	}
	path := filepath.Join(t.TempDir(), SessionSocketName)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := &http.Server{
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requests.Add(1)
		}),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	client, cleanup, err := DialSession(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = client.SyncSession(ctx, connect.NewRequest(&agentv1.SyncSessionRequest{}))
	if err == nil || !strings.Contains(err.Error(), "not root") {
		t.Fatalf("SyncSession error = %v, want root peer refusal", err)
	}
	if requests.Load() != 0 {
		t.Fatal("request bytes reached a non-root server")
	}
	if _, _, err := DialSession(""); err == nil {
		t.Fatal("empty socket path accepted")
	}
}
