//go:build linux

package vmlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// This exercises encrypted SSH observation/reconnection, not a simulated native
// update. Native package and boot evidence still requires lab vm updates.
func updateSSHFixture(t *testing.T, changedHostKey bool, observe func(int) (string, uint32, bool)) (*guestVM, *atomic.Int32) {
	t.Helper()
	keys := make([]ssh.Signer, 2)
	for i := range keys {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i], err = ssh.NewSignerFromKey(private)
		if err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connections := new(atomic.Int32)
	calls := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			n := connections.Add(1)
			_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
			config := &ssh.ServerConfig{NoClientAuth: true}
			key := keys[0]
			if changedHostKey && n > 1 {
				key = keys[1]
			}
			config.AddHostKey(key)
			server, channels, requests, err := ssh.NewServerConn(conn, config)
			if err != nil {
				_ = conn.Close()
				continue
			}
			go ssh.DiscardRequests(requests)
			for channel := range channels {
				session, commands, err := channel.Accept()
				if err != nil {
					break
				}
				request := <-commands
				var command struct{ Command string }
				if request == nil || request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil {
					_ = session.Close()
					break
				}
				if err := request.Reply(true, nil); err != nil {
					_ = session.Close()
					break
				}
				var output string
				var exit uint32
				var disconnect bool
				if command.Command != "true" {
					output, exit, disconnect = observe(int(calls.Add(1)))
				}
				if disconnect {
					_ = server.Close()
					break
				}
				if _, err := io.WriteString(session, output); err != nil {
					_ = session.Close()
					break
				}
				if _, err := session.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{exit})); err != nil {
					_ = session.Close()
					break
				}
				_ = session.Close()
			}
			_ = server.Close()
		}
	}()
	vm := &guestVM{dir: t.TempDir(), address: listener.Addr().String(), done: make(chan struct{}), log: new(vmLog),
		config: &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.FixedHostKey(keys[0].PublicKey())}}
	t.Cleanup(func() {
		if vm.client != nil {
			_ = vm.client.Close()
		}
		_ = listener.Close()
		<-done
	})
	vm.client, err = ssh.Dial("tcp4", vm.address, vm.config)
	if err != nil {
		t.Fatal(err)
	}
	return vm, connections
}

func updateStatusJSON(t *testing.T, finished time.Time) string {
	t.Helper()
	data, err := protojson.Marshal(&agentv1.GetAgentUpdateResponse{Status: &agentv1.AgentUpdateStatus{
		Enabled: true, Phase: "idle", LastOutcome: "rejected", AttemptFinishedAt: timestamppb.New(finished),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestUpdateObservationReconnectsOnlyReadOnlyStatus(t *testing.T) {
	now := time.Now()
	response := updateStatusJSON(t, now)
	vm, connections := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		return response, 0, call == 1
	})
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	status, err := waitUpdateObservation(ctx, vm, nil, "rejected")
	if err != nil || status.GetLastOutcome() != "rejected" || connections.Load() != 2 {
		t.Fatalf("lost transport prevented fresh observation: status=%v connections=%d err=%v", status, connections.Load(), err)
	}
}

func TestUpdateObservationRejectsChangedHostKey(t *testing.T) {
	vm, connections := updateSSHFixture(t, true, func(int) (string, uint32, bool) { return "", 0, true })
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	_, err := waitUpdateObservation(ctx, vm, nil, "rejected")
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") || errors.Is(err, context.DeadlineExceeded) || connections.Load() != 2 {
		t.Fatalf("changed host identity was retried or accepted: connections=%d err=%v", connections.Load(), err)
	}
}

func TestUpdateObservationPreservesFreshnessAcrossServiceRestart(t *testing.T) {
	before := time.Now().Add(-time.Minute)
	old, next := updateStatusJSON(t, before), updateStatusJSON(t, before.Add(time.Second))
	vm, connections := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		switch call {
		case 1:
			return "", 1, false // executor socket absent during native service restart
		case 2:
			return old, 0, false
		default:
			return next, 0, false
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	status, err := waitUpdateObservation(ctx, vm, &agentv1.AgentUpdateStatus{AttemptFinishedAt: timestamppb.New(before)}, "rejected")
	if err != nil || !status.GetAttemptFinishedAt().AsTime().After(before) || connections.Load() != 1 {
		t.Fatalf("restart lost freshness boundary or replaced healthy transport: status=%v connections=%d err=%v", status, connections.Load(), err)
	}
}

func TestUpdateObservationRejectsMalformedStatusWithoutPolling(t *testing.T) {
	vm, _ := updateSSHFixture(t, false, func(int) (string, uint32, bool) { return "not JSON", 0, false })
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	_, err := waitUpdateObservation(ctx, vm, nil, "rejected")
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("malformed observation was hidden until timeout: %v", err)
	}
}

func TestUpdateUnpackReconnectsWithoutReplayingMutation(t *testing.T) {
	vm, connections := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		return "dpkg pid=123 unpack=/fixture.dpkg-new bytes=1", 0, call == 1
	})
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	witness, err := waitUpdateUnpack(ctx, vm)
	if err != nil || witness == "" || connections.Load() != 2 {
		t.Fatalf("unpack observer lost after transport failure: connections=%d err=%v", connections.Load(), err)
	}
}

func TestUpdateObservationDiscardsAlreadyClosedClient(t *testing.T) {
	response := updateStatusJSON(t, time.Now())
	vm, connections := updateSSHFixture(t, false, func(int) (string, uint32, bool) { return response, 0, false })
	// runResult closes this same client when a command deadline fires. The next
	// observation must not spend the entire five-minute window reusing it.
	if err := vm.client.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	status, err := waitUpdateObservation(ctx, vm, nil, "rejected")
	if err != nil || status.GetLastOutcome() != "rejected" || connections.Load() != 2 {
		t.Fatalf("closed SSH client was reused: status=%v connections=%d err=%v", status, connections.Load(), err)
	}
}

func TestUpdateObservationCancellationRetainsLastStatus(t *testing.T) {
	response := updateStatusJSON(t, time.Now())
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	vm, _ := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		switch call {
		case 2:
			return "", 0, true
		case 3:
			cancel()
			return "", 0, true
		}
		return response, 0, false
	})
	_, err := waitUpdateObservation(ctx, vm, nil, "installed")
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "phase=idle outcome=rejected") || !strings.Contains(err.Error(), "first update observation transport loss") {
		t.Fatalf("transport loss erased its first error or last observed product state: %v", err)
	}
}

func TestUpdateUnpackStopsOnTerminalProductState(t *testing.T) {
	for _, phase := range []string{"recovery_required", "rejected", "installed"} {
		status := &agentv1.AgentUpdateStatus{Phase: phase, Reason: "native_transaction_incomplete"}
		err := updateUnpackTerminal(status)
		if err == nil || !strings.Contains(err.Error(), phase) || !strings.Contains(err.Error(), status.GetReason()) {
			t.Fatalf("terminal %s hidden behind unpack deadline: %v", phase, err)
		}
	}
	for _, phase := range []string{"idle", "checking", "staged", "applying", "installing"} {
		if err := updateUnpackTerminal(&agentv1.AgentUpdateStatus{Phase: phase}); err != nil {
			t.Fatalf("pending %s treated as terminal: %v", phase, err)
		}
	}
}
