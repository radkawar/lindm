//go:build integration && linux

package devlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/testdb"
)

func TestPersistentFixtureResumePreservesOwnerSession(t *testing.T) {
	binary, repository := nativeServer(t)
	pool, _ := testdb.Open(t)
	var affinity unix.CPUSet
	if err := unix.SchedGetaffinity(0, &affinity); err != nil {
		t.Fatal(err)
	}
	if affinity.Count() == 0 {
		t.Fatal("integration process has no available CPU")
	}
	cpu := 0
	for !affinity.IsSet(cpu) {
		cpu++
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var routed netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && validateSplitDevice(prefix.Addr()) == nil {
			routed = prefix.Addr()
			break
		}
	}
	if !routed.IsValid() {
		t.Fatal("persistent split fixture test requires a routed host IPv4 address")
	}
	for _, device := range []netip.Addr{{}, routed} {
		name := "local"
		if device.IsValid() {
			name = "split"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
			defer cancel()
			// Native GPG agent sockets require a short, private parent path.
			root, err := os.MkdirTemp("", "pfx-")
			if err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "controller")
			var fixture *AuthorityFixture
			defer func() {
				if fixture != nil {
					if err := fixture.Close(); err != nil {
						t.Error(err)
					}
				}
				cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				if err := DestroyPersistentFixture(cleanup, repository, state); err != nil {
					t.Errorf("destroy failed; private state retained at %s: %v", state, err)
					return
				}
				if err := os.RemoveAll(root); err != nil {
					t.Error(err)
				}
			}()
			options := LoadAuthorityOptions{DatabaseStorage: "shared", ServerCPUs: strconv.Itoa(cpu)}
			if device.IsValid() {
				source, err := filepath.Abs("../..")
				if err != nil {
					t.Fatal(err)
				}
				options.NativeEnrollmentArchitectures = []string{runtime.GOARCH}
				options.NativeEnrollmentSourceRepository = source
			}
			open := func() (*AuthorityFixture, error) {
				if device.IsValid() {
					return OpenPersistentSplitFixture(ctx, repository, binary, state, device, options)
				}
				return OpenPersistentFixture(ctx, repository, binary, state, options)
			}
			fixture, err = open()
			if err != nil {
				t.Fatal(err)
			}
			creationCPUs := options.ServerCPUs
			options = LoadAuthorityOptions{} // Resume needs no repeated creation options.
			nativeMetadata, err := json.Marshal(fixture.NativeRepository)
			if err != nil {
				t.Fatal(err)
			}
			if device.IsValid() && (fixture.NativeRepository == nil || fixture.NativeRepository.SignerFingerprint == "") {
				t.Fatal("split creation did not publish its signed native repository")
			}
			if fixture.Resumed {
				t.Fatal("first open reported resume")
			}
			if duplicate, err := open(); err == nil {
				_ = duplicate.Close()
				t.Fatal("second writer acquired live fixture")
			}
			if err := DestroyPersistentFixture(ctx, repository, state); err == nil {
				t.Fatal("destroy admitted live controller")
			}
			owner, err := fixture.OpenOwnerSession(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.transport.CloseIdleConnections()
			accountID, database, admin, endpoint := owner.AccountID, fixture.DatabaseName, fixture.AdminAddress, fixture.DeviceAddress
			leaf, err := os.ReadFile(filepath.Join(state, "split-server.crt"))
			if err != nil {
				t.Fatal(err)
			}
			relay, err := ReserveAssistanceRelay("127.0.0.1", "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if err := fixture.ConfigureAssistance(ctx, relay); err != nil {
				t.Fatal(err)
			}
			delegation, err := fixture.ConfigureDeviceActions(ctx)
			if err != nil {
				t.Fatal(err)
			}
			policy := &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "demo-reader", Permissions: []string{"fleet.read"}}}}
			if err := fixture.ConfigureAuthorization(ctx, policy); err != nil {
				t.Fatal(err)
			}
			before := fixture.ProcessID()
			if err := fixture.ConfigureAuthorization(ctx, proto.CloneOf(policy)); err != nil {
				t.Fatal(err)
			}
			if before != fixture.ProcessID() {
				t.Fatal("unchanged authorization restarted lindmd")
			}
			if _, err := owner.Admin.GetExecutionAuthority(ctx, connect.NewRequest(&adminv1.GetExecutionAuthorityRequest{})); err != nil {
				t.Fatalf("existing cookie lost after config-only restart: %v", err)
			}
			var laneID, approverID string
			laneState := filepath.Join(t.TempDir(), "lane")
			for round := range 2 {
				handle, err := fixture.ExportControlPlane(ctx, "persistent-lane")
				if err != nil {
					t.Fatal(err)
				}
				lane, err := ConnectPersistentAuthorityFixture(ctx, handle, laneState)
				if err != nil {
					t.Fatal(err)
				}
				if round == 0 {
					laneID, approverID = lane.local.owner.id, lane.local.approver.id
				}
				if lane.local.owner.id != laneID || lane.local.approver.id != approverID {
					t.Fatal("resume replaced enrolled lane accounts")
				}
				session, err := lane.OpenOwnerSession(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := session.Close(ctx); err != nil {
					t.Fatal(err)
				}
				session.transport.CloseIdleConnections()
				if err := lane.Close(); err != nil {
					t.Fatal(err)
				}
				if round == 0 {
					if err := fixture.Close(); err != nil {
						t.Fatal(err)
					}
					var present bool
					if err := pool.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_database WHERE datname=$1)", database).Scan(&present); err != nil || !present {
						t.Fatalf("Close dropped named database: present=%t err=%v", present, err)
					}
					busy, err := net.Listen("tcp4", admin)
					if err != nil {
						t.Fatal(err)
					}
					blocked, openErr := open()
					if openErr == nil {
						_ = blocked.Close()
						t.Error("resume replaced busy persisted admin port")
					}
					if err := busy.Close(); err != nil {
						t.Fatal(err)
					}
					resumed, err := open()
					if err != nil {
						t.Fatal(err)
					}
					fixture = resumed
					if !fixture.Resumed || fixture.DatabaseName != database || fixture.AdminAddress != admin || fixture.DeviceAddress != endpoint || fixture.local.owner.id != accountID {
						t.Fatal("resume changed persistent identity or listener ports")
					}
					if fixture.serverCPUs != creationCPUs || fixture.environment.ServerCPUs != creationCPUs {
						t.Fatal("resume discarded persistent server CPU affinity")
					}
					var recordedOptions LoadAuthorityOptions
					if err := readPersistentJSON(filepath.Join(state, "options.json"), &recordedOptions); err != nil {
						t.Fatal(err)
					}
					if recordedOptions.DatabaseStorage != "shared" || recordedOptions.ServerCPUs != creationCPUs {
						t.Fatal("resume replaced original fixture creation options")
					}
					retainedMetadata, err := json.Marshal(fixture.NativeRepository)
					if err != nil || !bytes.Equal(nativeMetadata, retainedMetadata) {
						t.Fatal("resume changed native repository publication metadata")
					}
					if device.IsValid() {
						if len(recordedOptions.NativeEnrollmentArchitectures) != 1 || recordedOptions.NativeEnrollmentArchitectures[0] != runtime.GOARCH {
							t.Fatal("resume lost native repository architecture selection")
						}
						instructions, err := owner.Admin.GetEnrollmentInstructions(ctx, connect.NewRequest(&adminv1.GetEnrollmentInstructionsRequest{}))
						if err != nil {
							t.Fatal(err)
						}
						if !instructions.Msg.GetReadiness().GetReady() {
							t.Fatalf("resumed native repository is not ready: %v", instructions.Msg.GetReadiness())
						}
						t.Logf("resumed native enrollment repository ready with retained fingerprint %s", fixture.NativeRepository.SignerFingerprint)
					}
					retainedDelegation, err := fixture.ConfigureDeviceActions(ctx)
					if err != nil || !proto.Equal(delegation, retainedDelegation) {
						t.Fatal("resume replaced execution delegation or signing custody")
					}
					retained, err := os.ReadFile(filepath.Join(state, "split-server.crt"))
					if err != nil || !bytes.Equal(leaf, retained) {
						t.Fatal("resume replaced TLS leaf")
					}
					savedRelay, err := fixture.AssistanceConfiguration()
					if err != nil || !proto.Equal(savedRelay, relay) {
						t.Fatal("resume changed TURN contract")
					}
					if _, err := owner.Admin.GetExecutionAuthority(ctx, connect.NewRequest(&adminv1.GetExecutionAuthorityRequest{})); err != nil {
						t.Fatalf("existing owner cookie/session lost across close and resume: %v", err)
					}
				}
			}
			if err := owner.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if err := fixture.Close(); err != nil {
				t.Fatal(err)
			}
			if err := DestroyPersistentAuthorityFixture(laneState); err != nil {
				t.Fatal(err)
			}
			if device.IsValid() {
				// Simulate interruption after DROP committed but before directory
				// removal: explicit destroy must finish rather than fail forever.
				if err := fixture.database.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := DestroyPersistentFixture(ctx, repository, state); err != nil {
				t.Fatal(err)
			}
			var present bool
			if err := pool.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_database WHERE datname=$1)", database).Scan(&present); err != nil || present {
				t.Fatalf("destroy retained database: present=%t err=%v", present, err)
			}
			if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("destroy retained fixture directory: %v", err)
			}
			t.Logf("create/resume/destroy preserved owner=%s database=%s admin=%s device=%s and existing cookie; database and state removed", accountID, database, admin, endpoint)
		})
	}
}
