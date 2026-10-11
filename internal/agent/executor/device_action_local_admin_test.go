//go:build linux

package executor

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func localAdminActionSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{AccountName: "lapsadmin", EscrowKeyId: strings.Repeat("c", 64), EscrowPublicKey: bytes.Repeat([]byte{6}, 256)}}}
}

// assertNoPlaintextAtRest scans every persisted executor byte, including the
// SQLite WAL, for the generated password.
func (f *deviceActionFixture) assertNoPlaintextAtRest(t *testing.T) {
	t.Helper()
	err := filepath.WalkDir(f.svc.directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, f.actionNative.localAdminCanary) {
			t.Errorf("plaintext local-admin password persisted in %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocalAdminRotationEscrowsBeforeNativeSet(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, localAdminActionSpec())
	f.actionPrepare(t, i)
	prepared, _ := deviceActionRow(t, f.svc, i.GetActionId())
	want := &agentv1.LocalAdminPasswordBinding{DeviceId: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration(), ActionId: i.GetActionId(), AccountName: "lapsadmin", AccountUid: 1001}
	if !proto.Equal(prepared.GetNativePlan().GetLocalAdminBinding(), want) {
		t.Fatalf("signed plan binding = %v", prepared.GetNativePlan().GetLocalAdminBinding())
	}
	actionStart(t, f.svc, i.GetActionId(), f.actionGrant(t, i))
	awaiting := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW)
	f.svc.operations.Wait()
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if f.actionNative.localAdminSets.Load() != 0 || record.GetLocalAdminPassword() == nil || !proto.Equal(awaiting.GetVerification().GetEscrow().GetLocalAdmin(), want) {
		t.Fatal("phase one changed the account or lost staged custody")
	}
	f.assertNoPlaintextAtRest(t)

	// A recovery-kind receipt for the same action is not escrow of this password.
	wrong := proto.CloneOf(record)
	wrong.Verification.Escrow.LocalAdmin = nil
	wrong.Verification.Escrow.LuksUuid = uuid.NewString()
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: f.escrowReceipt(t, wrong, 1)})); err == nil {
		t.Fatal("recovery-kind receipt authorized a password set")
	}
	if f.actionNative.localAdminSets.Load() != 0 {
		t.Fatal("rejected receipt set the password")
	}
	receipt := f.escrowReceipt(t, record, 1)
	f.actionNative.checkGate = func() error {
		r, _, err := f.svc.store.LoadDeviceAction(t.Context(), i.GetActionId())
		if err != nil {
			return err
		}
		if r.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW || !bytes.Equal(r.GetEscrowReceiptEnvelope(), receipt) || r.GetLocalAdminPassword() == nil {
			return errInternal
		}
		return nil
	}
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: receipt})); err != nil {
		t.Fatal(err)
	}
	terminal := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
	f.svc.operations.Wait()
	final, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if f.actionNative.localAdminSets.Load() != 1 || final.GetLocalAdminPassword() != nil || !terminal.GetVerification().GetVerified() {
		t.Fatal("verified set did not clear local custody")
	}
	f.reopenActions(t)
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: receipt})); err != nil {
		t.Fatal(err)
	}
	if f.actionNative.localAdminSets.Load() != 1 {
		t.Fatal("receipt replay repeated the native set")
	}
	f.assertNoPlaintextAtRest(t)
}

func TestLocalAdminInterruptedSetRemainsUnknown(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.actionNative.failLocalAdminSet = true
	i := f.actionIntent(t, 1, localAdminActionSpec())
	f.actionPrepare(t, i)
	actionStart(t, f.svc, i.GetActionId(), f.actionGrant(t, i))
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW)
	f.svc.operations.Wait()
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	receipt := f.escrowReceipt(t, record, 1)
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: receipt})); err != nil {
		t.Fatal(err)
	}
	status := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	f.svc.operations.Wait()
	final, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if final.GetLocalAdminPassword() != nil || !proto.Equal(status.GetVerification().GetEscrow(), record.GetVerification().GetEscrow()) {
		t.Fatal("unknown set lost escrow evidence or retained custody")
	}
	f.actionNative.failLocalAdminSet = false
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: receipt})); err != nil {
		t.Fatalf("consumed receipt lookup failed: %v", err)
	}
	if f.actionNative.localAdminSets.Load() != 1 {
		t.Fatal("interrupted set was retried")
	}
}

func TestLocalAdminRestartBeforeReceiptNeverSets(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, localAdminActionSpec())
	f.actionPrepare(t, i)
	actionStart(t, f.svc, i.GetActionId(), f.actionGrant(t, i))
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW)
	f.svc.operations.Wait()
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	f.reopenActions(t)
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	if r, _ := deviceActionRow(t, f.svc, i.GetActionId()); r.GetLocalAdminPassword() != nil {
		t.Fatal("restart retained custody of an unreceipted password")
	}
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: f.escrowReceipt(t, record, 1)})); err == nil {
		t.Fatal("receipt after restart revived the rotation")
	}
	if f.actionNative.localAdminSets.Load() != 0 {
		t.Fatal("restart set the password")
	}
	f.assertNoPlaintextAtRest(t)
}
