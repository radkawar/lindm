package executor

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// A consumed native power call may disappear with the old boot before a return
// can be journaled. Recovery observes boot identity; it never repeats the call.
func TestRestartActionConfirmsChangedBootWithoutReplay(t *testing.T) {
	for _, completedCall := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost-native-return", true: "accepted-native-return"}[completedCall], func(t *testing.T) {
			f := newDeviceActionFixture(t)
			i := f.actionIntent(t, 1, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}})
			f.actionPrepare(t, i)
			grant := f.actionGrant(t, i)
			r, _ := deviceActionRow(t, f.svc, i.GetActionId())
			if _, err := f.svc.consumeDeviceAction(t.Context(), r, grant, false); err != nil {
				t.Fatal(err)
			}
			if completedCall {
				f.svc.finishDeviceAction(i.GetActionId(), &agentv1.DeviceActionVerification{Verified: true, After: r.GetNativePlan().GetBefore(), PowerRequestAccepted: true}, nil, false)
				awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
			}
			// Executor restart in the SAME boot is not device restart success.
			f.reopenActions(t)
			awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
			f.reopenActions(t)
			awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
			f.boot = uuid.NewString()
			f.reopenActions(t)
			status := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
			if status.GetVerification().GetBootId() != f.boot || status.GetVerification().GetAfter().GetBootId() != f.boot || status.GetVerification().GetBootId() == r.GetChallenge().GetBootId() {
				t.Fatalf("restart lacks changed boot evidence: %v", status)
			}
			actionStart(t, f.svc, i.GetActionId(), grant)
			if f.actionNative.applies.Load() != 0 || f.actionNative.effects.Load() != 0 {
				t.Fatal("recovery or exact retry replayed power request")
			}
		})
	}
}

func TestShutdownActionNeverClaimsPowerOffFromContact(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}})
	f.actionPrepare(t, i)
	grant := f.actionGrant(t, i)
	r, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if _, err := f.svc.consumeDeviceAction(t.Context(), r, grant, false); err != nil {
		t.Fatal(err)
	}
	// Even a faulty native provider cannot turn request acceptance into success.
	f.svc.finishDeviceAction(i.GetActionId(), &agentv1.DeviceActionVerification{Verified: true, After: r.GetNativePlan().GetBefore(), PowerRequestAccepted: true, Evidence: "outcome_unknown_until_contact"}, nil, false)
	status := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	if status.GetVerification().GetVerified() || !status.GetVerification().GetPowerRequestAccepted() {
		t.Fatalf("shutdown lost honest acceptance: %v", status)
	}
	f.boot = uuid.NewString()
	f.reopenActions(t)
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	actionStart(t, f.svc, i.GetActionId(), grant)
	if f.actionNative.applies.Load() != 0 {
		t.Fatal("shutdown replayed after contact")
	}
}

func TestRestartActionUnconsumedGrantCannotConfirmLaterBoot(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}})
	f.actionPrepare(t, i)
	grant := f.actionGrant(t, i)
	f.boot = uuid.NewString()
	f.reopenActions(t)
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED)
	if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: grant})); err == nil {
		t.Fatal("unconsumed old boot grant was revived")
	}
}

func TestPowerActionWallDeliveryCannotExtendStartAuthority(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}})
	f.actionPrepare(t, i)
	grant := f.actionGrant(t, i)
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if _, err := f.svc.consumeDeviceAction(t.Context(), record, grant, false); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.recheckPowerActionStart(t.Context(), record, grant); err != nil {
		t.Fatal(err)
	}
	f.bootClock.Store(record.GetChallengeBoottimeNs())
	if err := f.svc.recheckPowerActionStart(t.Context(), record, grant); err == nil {
		t.Fatal("wall delivery extended the consumed grant deadline")
	}
	current, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if current.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || f.actionNative.effects.Load() != 0 {
		t.Fatal("deadline recheck altered consumption or issued an effect")
	}
}

func TestShutdownInterruptedBeforeNativeReplyRetainsUnknownEvidence(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}})
	f.actionPrepare(t, i)
	grant := f.actionGrant(t, i)
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if _, err := f.svc.consumeDeviceAction(t.Context(), record, grant, false); err != nil {
		t.Fatal(err)
	}
	f.boot = uuid.NewString()
	f.reopenActions(t)
	status := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	if status.GetVerification().GetEvidence() != "outcome_unknown_until_contact" || status.GetVerification().GetPowerRequestAccepted() || status.GetVerification().GetVerified() {
		t.Fatalf("interrupted shutdown invented native acceptance: %v", status)
	}
}
