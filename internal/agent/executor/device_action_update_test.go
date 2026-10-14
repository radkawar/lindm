// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/update"
)

// Restore an actual durable update engine without starting a package manager,
// network fetch, or native update worker.
func installBusyUpdateFixture(t *testing.T, f *deviceActionFixture) {
	t.Helper()
	s := f.svc
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded, err := s.enrolled(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	store, err := journal.OpenUpdates(s.directory)
	if err != nil {
		t.Fatal(err)
	}
	state := &agentv1.AgentUpdateJournal{FormatVersion: 1, InstalledVersion: "0.1.0", Phase: "recovery_required", ObservedAt: protoTimestamp(f.now), Transaction: &agentv1.AgentUpdateTransaction{Id: uuid.NewString(), Version: "1.2.3", NativeVersion: "1.2.3-1", PreviousVersion: "0.1.0", PreviousNativeVersion: "0.1.0-1", Manager: agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, Architecture: "amd64", Sha256: strings.Repeat("a", 64), Length: 1024, AdmittedAt: protoTimestamp(f.now), VerifiedExpiresAt: protoTimestamp(f.now.Add(time.Hour))}}
	if err := store.Save(state); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	engine, err := update.New(s.workerContext, s.directory, loaded.state.GetDeviceId(), loaded.bootstrap.Bundle.GetReleaseRootJson(), &agentv1.AgentUpdateConfig{RepositoryUrl: "https://updates.example.test/stable/", Ring: "stable", PollIntervalSeconds: 60, Manager: agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT})
	if err != nil {
		t.Fatal(err)
	}
	s.updates = engine
	if !s.agentUpdateBusy() {
		t.Fatal("restored unresolved update was not busy")
	}
}

func TestDeviceActionsRejectBusyUpdateBeforeAdmissionAndEffects(t *testing.T) {
	for _, phase := range []string{"prepare", "start", "effect_gate"} {
		t.Run(phase, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			intent := f.actionIntent(t, 1, nil)
			var grant []byte
			if phase != "prepare" {
				f.actionPrepare(t, intent)
				grant = f.actionGrant(t, intent)
			}
			installBusyUpdateFixture(t, f)
			var err error
			switch phase {
			case "prepare":
				_, err = f.svc.PrepareDeviceAction(t.Context(), connect.NewRequest(&agentv1.PrepareDeviceActionRequest{IntentEnvelope: mustSign(t, f.svc.authority, intent, f.planKey)}))
			case "start":
				_, err = f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: grant}))
			case "effect_gate":
				record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
				_, err = f.svc.consumeDeviceAction(t.Context(), record, grant, false)
			}
			if err == nil {
				t.Fatal("busy update admitted a device action")
			}
			if f.actionNative.effects.Load() != 0 {
				t.Fatal("busy update allowed a native effect")
			}
			record, _, err := f.svc.store.LoadDeviceAction(t.Context(), intent.GetActionId())
			if phase == "prepare" {
				if !errors.Is(err, journal.ErrDeviceActionNotFound) {
					t.Fatal("rejected Prepare persisted an action")
				}
			} else if err != nil || record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED || len(record.GetStartGrantEnvelope()) != 0 {
				t.Fatal("busy update consumed action authority")
			}
		})
	}
}

func TestDeviceActionHistoricalReplayRemainsAvailableDuringUpdate(t *testing.T) {
	f := newDeviceActionFixture(t)
	intent := f.actionIntent(t, 1, nil)
	envelope := f.actionPrepare(t, intent)
	grant := f.actionGrant(t, intent)
	actionStart(t, f.svc, intent.GetActionId(), grant)
	terminal := awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
	f.svc.operations.Wait()
	installBusyUpdateFixture(t, f)
	if got := actionStart(t, f.svc, intent.GetActionId(), grant); !proto.Equal(got, terminal) {
		t.Fatal("busy update hid exact historical action result")
	}
	if _, err := f.svc.PrepareDeviceAction(t.Context(), connect.NewRequest(&agentv1.PrepareDeviceActionRequest{IntentEnvelope: envelope})); err != nil {
		t.Fatal(err)
	}
	if f.actionNative.effects.Load() != 1 {
		t.Fatal("historical replay repeated effects")
	}
}

func TestRecoveryBootRejectsUpdateAtCommitAndFinalGate(t *testing.T) {
	for _, phase := range []string{"commit", "final_gate"} {
		t.Run(phase, func(t *testing.T) {
			f, native, intent := newRecoveryBootFixture(t)
			credential, boot, _ := recoveryBootEnvelopes(t, f, intent)
			if phase == "commit" {
				installBusyUpdateFixture(t, f)
			} else {
				native.beforeFinalGate = func() { installBusyUpdateFixture(t, f) }
			}
			_, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot}))
			if phase == "commit" {
				if err == nil {
					t.Fatal("busy update consumed BOOT")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				f.svc.operations.Wait()
				awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
			}
			if native.arms.Load() != 0 || native.reboots.Load() != 0 {
				t.Fatal("busy update allowed recovery boot")
			}
		})
	}
}

func TestRecoveryBootConsumedUnknownBlocksAgentUpdate(t *testing.T) {
	f, native, intent := newRecoveryBootFixture(t)
	credential, boot, _ := recoveryBootEnvelopes(t, f, intent)
	native.beforeArm = func() { f.bootClock.Add(uint64(31 * time.Second)) }
	if _, err := f.svc.CommitDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.CommitDeviceActionRecoveryRequest{ActionId: intent.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: boot})); err != nil {
		t.Fatal(err)
	}
	f.svc.operations.Wait()
	awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
	if !bytes.Equal(record.GetRecoveryBootGrantEnvelope(), boot) {
		t.Fatal("unknown BOOT lost consumption evidence")
	}
	blocked, err := f.svc.store.DeviceActionsBlockUpdate(t.Context())
	if err != nil || !blocked {
		t.Fatalf("consumed unknown BOOT did not exclude update: blocked=%v err=%v", blocked, err)
	}
}

func TestRecoveryPreparationRejectsBusyUpdateButRetainsHistory(t *testing.T) {
	f, native, intent := newRecoveryBootFixture(t)
	record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
	installBusyUpdateFixture(t, f)
	next := proto.CloneOf(intent)
	next.ActionId = uuid.NewString()
	next.ActionSequence++
	if _, err := f.svc.PrepareDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.PrepareDeviceActionRecoveryRequest{IntentEnvelope: mustSign(t, f.svc.authority, next, f.planKey)})); err == nil {
		t.Fatal("busy update admitted recovery preparation")
	}
	if _, _, err := f.svc.store.LoadDeviceAction(t.Context(), next.GetActionId()); !errors.Is(err, journal.ErrDeviceActionNotFound) {
		t.Fatal("blocked recovery preparation persisted authority")
	}
	response, err := f.svc.PrepareDeviceActionRecovery(t.Context(), connect.NewRequest(&agentv1.PrepareDeviceActionRecoveryRequest{IntentEnvelope: record.GetIntentEnvelope()}))
	if err != nil || !bytes.Equal(response.Msg.GetHandoffProof(), record.GetHandoffProof()) {
		t.Fatal("busy update hid historical recovery preparation")
	}
	if native.provisions.Load() != 1 {
		t.Fatal("blocked recovery preparation provisioned another key")
	}
}
