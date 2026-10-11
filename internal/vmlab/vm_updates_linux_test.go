//go:build linux

package vmlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
)

// An aarch64 guest cannot boot without pinned EFI firmware. The lane must refuse
// that selection before snapshotting source or building any package, and must
// refuse storage buses whose root disk is not the throttled /dev/vda.
func TestUpdateHardwareResolvedBeforePackageBuild(t *testing.T) {
	manifest, err := LoadManifest("../../lab/images/debian-12-arm64.json")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	result, err := UpdateVM(context.Background(), manifest, VMUpdateOptions{Repository: t.TempDir(), WorkDir: work})
	if result != nil || err == nil || !strings.Contains(err.Error(), "explicit pinned EFI firmware") {
		t.Fatalf("UpdateVM without firmware = %v, %v", result, err)
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatalf("refused lane created work state: %v, %v", entries, err)
	}
	firmware := &EncryptedFirmwareOptions{Code: "/usr/share/AAVMF/AAVMF_CODE.secboot.fd", Vars: "/usr/share/AAVMF/AAVMF_VARS.fd", Package: "qemu-efi-aarch64", Version: "2024.02-2ubuntu0.10"}
	if err := updateHardwareSupported(manifest, &VMHardwareOptions{Firmware: firmware}, "arm64"); err != nil {
		t.Fatalf("pinned AAVMF virtio-blk guest refused: %v", err)
	}
	if err := updateHardwareSupported(manifest, &VMHardwareOptions{Firmware: firmware, StorageBus: "nvme"}, "arm64"); err == nil || !strings.Contains(err.Error(), "/dev/vda") {
		t.Fatalf("nvme root disk admitted: %v", err)
	}
	if err := updateHardwareSupported(manifest, &VMHardwareOptions{Firmware: firmware, Accelerator: "kvm"}, "amd64"); err == nil {
		t.Fatal("cross-architecture KVM admitted")
	}
	x86 := &labv1.ImageManifest{Distribution: "ubuntu", Version: "24.04", Architecture: "amd64"}
	if err := updateHardwareSupported(x86, nil, "amd64"); err != nil {
		t.Fatalf("default x86_64 BIOS guest refused: %v", err)
	}
	// The registry admits only the natively qualified architecture.
	amd, err := LoadManifest("../../lab/images/debian-12-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateVM(context.Background(), amd, VMUpdateOptions{Repository: t.TempDir(), WorkDir: work}); err == nil || !strings.Contains(err.Error(), "no maintained vm updates lane") {
		t.Fatalf("unqualified Debian 12 x86_64 update lane admitted: %v", err)
	}
}

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
		Enabled: true, Phase: "idle", LastOutcome: "rejected", AttemptStartedAt: timestamppb.New(finished.Add(-time.Millisecond)), AttemptFinishedAt: timestamppb.New(finished),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestUpdateObservationReconnectsOnlyReadOnlyStatus(t *testing.T) {
	now := time.Now()
	vm, connections := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		return updateStatusJSON(t, now.Add(time.Duration(call)*time.Second)), 0, call == 1
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

func TestUpdateUnpackFaultInjectionNeverReplayedOnTransportLoss(t *testing.T) {
	var calls atomic.Int32
	vm, connections := updateSSHFixture(t, false, func(int) (string, uint32, bool) {
		calls.Add(1)
		return "", 0, true
	})
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	witness, err := waitUpdateUnpack(ctx, vm)
	if err == nil || witness != "" || connections.Load() != 1 || calls.Load() != 1 || !strings.Contains(err.Error(), "not replayed") {
		t.Fatalf("mutating unpack probe replayed after transport loss: calls=%d connections=%d err=%v", calls.Load(), connections.Load(), err)
	}
}

func TestUpdateObservationDiscardsAlreadyClosedClient(t *testing.T) {
	now := time.Now()
	vm, connections := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		return updateStatusJSON(t, now.Add(time.Duration(call)*time.Second)), 0, false
	})
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

func TestUpdateObservationFencesPreMutationAndInflightCycles(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	vm, _ := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		calls.Add(1)
		started, finished := now, now.Add(time.Second)
		if call == 2 {
			// Completion is newer than both the caller's sample and our first
			// observation, but this cycle already started before the mutation.
			finished = now.Add(2 * time.Second)
		}
		if call >= 3 {
			started, finished = now.Add(3*time.Second), now.Add(4*time.Second)
		}
		data, err := protojson.Marshal(&agentv1.GetAgentUpdateResponse{Status: &agentv1.AgentUpdateStatus{
			Enabled: true, Phase: "idle", LastOutcome: "no_update",
			AttemptStartedAt: timestamppb.New(started), AttemptFinishedAt: timestamppb.New(finished),
		}})
		if err != nil {
			t.Error(err)
		}
		return string(data), 0, false
	})
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	status, err := waitUpdateObservation(ctx, vm, &agentv1.AgentUpdateStatus{AttemptFinishedAt: timestamppb.New(now.Add(-time.Minute))}, "no_update")
	if err != nil || calls.Load() < 3 || !status.GetAttemptStartedAt().AsTime().Equal(now.Add(3*time.Second)) {
		t.Fatalf("pre-mutation/in-flight observation accepted: calls=%d status=%v err=%v", calls.Load(), status, err)
	}
}
