//go:build integration && consolelab

package loadlab

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/devlab"
	"lindm/internal/trust"
)

// Exercise Populate's actual preparation/enrollment path while retaining its
// simulated device transports for fresh contact and signed work verification.
// No native action is executed or reported successful by this regression.
func TestConsoleDefaultDelegationAdmitsDeviceActions(t *testing.T) {
	repository, binary := os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD")
	if repository == "" || binary == "" {
		t.Fatal("set LINDM_CONSOLE_REPOSITORY and LINDM_CONSOLE_LINDMD for the real console lab regression")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	})
	r := &runner{fixture: fixture, metrics: &measurements{}, options: Options{Packages: 1, AssignmentPercent: 100}}
	if err := r.prepare(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		r.enrollmentTransport.CloseIdleConnections()
		if err := r.owner.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	restricted, err := fixture.OpenRestrictedRecoverySession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := errors.Join(restricted.Close(cleanup), fixture.RestoreAccount(cleanup, restricted.AccountID)); err != nil {
			t.Error(err)
		}
	})
	for index, test := range []struct {
		name string
		spec *agentv1.DeviceActionSpec
	}{
		{"refresh", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}},
		{"restart", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}},
		{"lock", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, err := r.enroll(ctx, index)
			if err != nil {
				t.Fatal(err)
			}
			defer d.close()
			// enroll -> syncTrust cryptographically verifies the published DSSE
			// delegation against the signed bootstrap, not the Admin API's echo.
			assertConsoleDelegation(t, d.delegation)
			// The existing simulated service protocol verifies both intent and
			// start signatures, binding these two delegates to the online keys
			// actually configured in lindmd. This is not native systemd evidence.
			if err := r.completePopulationAssignment(ctx, d); err != nil {
				t.Fatal(err)
			}
			current, err := r.owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: d.id}))
			if err != nil {
				t.Fatal(err)
			}
			observation := current.Msg.GetHost().GetObservation()
			details := observation.GetDetails()
			sessions := details.GetSessions().GetSessions()
			if observation.GetHardwareModel().GetValue() != "Synthetic, not native inventory" || sessions.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || sessions.GetValue() != 0 || details.GetStorage().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE || len(details.GetStorage().GetDevices()) != 0 {
				t.Fatal("initial population lost explicit synthetic sessions or invented storage")
			}
			// Seed recent contact through the authenticated heartbeat immediately
			// before admission. Never relax the production one-minute fence.
			if _, err := d.client.GetSyncState(ctx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: d.epoch})); err != nil {
				t.Fatal(err)
			}
			request := &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: d.id, EnrollmentGeneration: d.generation, Spec: test.spec, ExpiresAt: timestamppb.New(time.Now().Add(5 * time.Minute)), Reason: "disposable console action admission regression"}
			if _, err := restricted.Admin.CreateDeviceAction(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("operator bypassed action permission: %v", err)
			}
			if test.name == "lock" {
				approval := &adminv1.CreateApprovalRequest{LifetimeSeconds: 300, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}}
				if _, err := restricted.Admin.CreateApproval(ctx, connect.NewRequest(approval)); connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Fatalf("operator bypassed action approval permission: %v", err)
				}
				created, err := r.owner.Admin.CreateApproval(ctx, connect.NewRequest(approval))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := r.owner.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "must reject approval by the requester"})); connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Fatalf("requester approved own lock action: %v", err)
				}
			}
			created, err := r.owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
			if err != nil {
				t.Fatalf("default console delegation cannot admit %s: %v", test.name, err)
			}
			action := created.Msg.GetAction()
			if action.GetActionId() == "" || action.GetDeviceId() != d.id || action.GetEnrollmentGeneration() != d.generation || !proto.Equal(action.GetSpec(), test.spec) || action.GetStatus().GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
				t.Fatal("admission lost exact action identity or fabricated native success")
			}
			work, err := d.client.GetDeviceActionWork(ctx, connect.NewRequest(&devicev1.GetDeviceActionWorkRequest{SessionEpoch: d.epoch}))
			if err != nil {
				t.Fatal(err)
			}
			intent, err := r.verifier.VerifyDeviceActionIntent(ctx, d.root, d.delegation, work.Msg.GetWork().GetIntentEnvelope(), time.Now())
			if err != nil {
				t.Fatalf("verify server's signed action: %v", err)
			}
			if intent.GetActionId() != action.GetActionId() || intent.GetDeviceId() != d.id || intent.GetEnrollmentGeneration() != d.generation || !proto.Equal(intent.GetSpec(), test.spec) {
				t.Fatal("signed action does not bind the accepted request")
			}
		})
	}
}

func assertConsoleDelegation(t *testing.T, delegation *agentv1.ExecutionDelegation) {
	t.Helper()
	want := []string{"systemd.service.v1"}
	fields := (&agentv1.DeviceActionSpec{}).ProtoReflect().Descriptor().Oneofs().ByName("action").Fields()
	for i := range fields.Len() {
		spec := new(agentv1.DeviceActionSpec)
		message := spec.ProtoReflect()
		field := fields.Get(i)
		message.Set(field, message.NewField(field))
		capability, err := trust.DeviceActionCapability(spec)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, capability)
	}
	slices.Sort(want)
	if len(delegation.GetDelegates()) != 2 {
		t.Fatal("default console must delegate only distinct PLAN and START online keys")
	}
	roles := make(map[agentv1.ExecutionSignerRole]bool)
	keys := make(map[string]bool)
	for _, delegate := range delegation.GetDelegates() {
		role := delegate.GetRole()
		if (role != agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN && role != agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START) || roles[role] || keys[delegate.GetKey().GetKeyId()] {
			t.Fatal("default console delegation reused a role/key or granted an unexpected role")
		}
		roles[role], keys[delegate.GetKey().GetKeyId()] = true, true
		got := slices.Clone(delegate.GetCapabilities())
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("signed %s delegation capabilities = %v, want %v", role, got, want)
		}
	}
}
