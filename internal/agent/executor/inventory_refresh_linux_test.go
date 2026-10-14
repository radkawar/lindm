// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func refreshActionSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}
}

func refreshReceipt(record *agentv1.DeviceActionRecord, at time.Time, version uint64) *agentv1.DeviceActionInventoryReceipt {
	i := record.GetIntent()
	return &agentv1.DeviceActionInventoryReceipt{DeploymentId: i.GetDeploymentId(), DeviceId: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration(), ActionId: i.GetActionId(), IntentSha256: bytes.Clone(record.GetIntentSha256()), StartGrantSha256: bytes.Clone(record.GetStartGrantSha256()), PackageSequence: 42, HostSequence: 57, SnapshotId: uuid.NewString(), PublishedAt: protoTimestamp(at), RootVersion: 1, DelegationVersion: version}
}

func TestInventoryRefreshRequiresSignedPublicationAndRetainsReplay(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, refreshActionSpec())
	f.actionPrepare(t, i)
	grant := f.actionGrant(t, i)
	actionStart(t, f.svc, i.GetActionId(), grant)
	f.svc.operations.Wait()
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || record.GetVerification() != nil || f.actionNative.applies.Load() != 0 {
		t.Fatal("queued refresh or generic provider result became completion")
	}
	confirm := func(envelope []byte) error {
		_, err := f.svc.ConfirmDeviceActionInventory(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionInventoryRequest{ActionId: i.GetActionId(), ReceiptEnvelope: envelope}))
		return err
	}
	if err := confirm([]byte("unsigned COMMITTED sequence 42")); err == nil {
		t.Fatal("unsigned relay confirmation accepted")
	}
	for _, mutate := range []func(*agentv1.DeviceActionInventoryReceipt){
		func(r *agentv1.DeviceActionInventoryReceipt) { r.ActionId = uuid.NewString() },
		func(r *agentv1.DeviceActionInventoryReceipt) { r.EnrollmentGeneration = uuid.NewString() },
		func(r *agentv1.DeviceActionInventoryReceipt) { r.IntentSha256[0] ^= 1 },
		func(r *agentv1.DeviceActionInventoryReceipt) { r.StartGrantSha256[0] ^= 1 },
		func(r *agentv1.DeviceActionInventoryReceipt) { r.PublishedAt = protoTimestamp(f.now.Add(-time.Second)) },
		func(r *agentv1.DeviceActionInventoryReceipt) { r.PublishedAt = protoTimestamp(f.now.Add(time.Second)) },
	} {
		r := refreshReceipt(record, f.now, 1)
		mutate(r)
		if err := confirm(mustSign(t, f.svc.authority, r, f.startKey)); err == nil {
			t.Fatal("substituted or stale publication receipt accepted")
		}
	}
	r := refreshReceipt(record, f.now, 1)
	if err := confirm(mustSign(t, f.svc.authority, r, f.planKey)); err == nil {
		t.Fatal("plan signer substituted for publication authority")
	}
	envelope := mustSign(t, f.svc.authority, r, f.startKey)
	if err := confirm(envelope); err != nil {
		t.Fatal(err)
	}
	completed, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if completed.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || completed.GetVerification().GetInventorySequence() != 42 || !bytes.Equal(completed.GetInventoryReceiptEnvelope(), envelope) || completed.GetInventoryReceiptRoot() == nil {
		t.Fatal("publication proof was not durably bound to successful result")
	}
	f.actionDelegation(t, 2)
	f.reopenActions(t)
	if err := confirm(envelope); err != nil {
		t.Fatalf("historical receipt failed after restart and delegation change: %v", err)
	}
	actionStart(t, f.svc, i.GetActionId(), grant)
	if f.actionNative.applies.Load() != 0 {
		t.Fatal("refresh grant replay invoked a native provider")
	}
	r.PackageSequence++
	if err := confirm(mustSign(t, f.svc.authority, r, f.startKey)); err == nil {
		t.Fatal("completed publication was replaced")
	}
}

func TestInventoryRefreshReceiptResolvesCrashWithoutRestartingCollection(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, refreshActionSpec())
	f.actionPrepare(t, i)
	actionStart(t, f.svc, i.GetActionId(), f.actionGrant(t, i))
	f.svc.operations.Wait()
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	envelope := mustSign(t, f.svc.authority, refreshReceipt(record, f.now, 1), f.startKey)
	f.reopenActions(t)
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	response, err := f.svc.ConfirmDeviceActionInventory(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionInventoryRequest{ActionId: i.GetActionId(), ReceiptEnvelope: envelope}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || f.actionNative.applies.Load() != 0 {
		t.Fatal("publication recovery replayed collection or lost successful publication")
	}
	after, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if !proto.Equal(after.GetStartedAt(), record.GetStartedAt()) || !bytes.Equal(after.GetStartGrantEnvelope(), record.GetStartGrantEnvelope()) {
		t.Fatal("publication recovery rewrote consumed authority")
	}
}
