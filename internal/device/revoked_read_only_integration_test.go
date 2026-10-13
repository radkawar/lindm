//go:build integration

package device

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/assistrelay"
)

// A revoked device is read-only: every operator mutation targeting it is
// refused with device_revoked, while its record stays readable.
func TestRevokedDeviceRefusesMutations(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newLAPSFixture(t, false)
	// Configured relay only: the refusal precedes any relay use.
	relay, err := assistrelay.New(&configv1.AssistanceConfig{MaxConcurrentSessions: 1, Relay: &configv1.AssistanceRelayConfig{
		Listener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 3478}, RelayAddress: "127.0.0.1",
		RelayPortMin: 40000, RelayPortMax: 40100, Urls: []string{"turn:relay.example:3478?transport=udp"}, Realm: "relay.example",
	}}, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Assistance = relay
	f.setPolicy(t, f.ownerCtx)
	if _, err := f.svc.RevokeDevice(f.ownerCtx, approvedRevocation(t, f.svc, f.ownerCtx, &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "retire stolen laptop"})); err != nil {
		t.Fatal(err)
	}
	restart := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}
	for name, call := range map[string]func(context.Context) error{
		"CreateDeviceAction restart": func(ctx context.Context) error {
			_, err := f.svc.CreateDeviceAction(ctx, connect.NewRequest(f.request(restart)))
			return err
		},
		"CreateDeviceAction lock": func(ctx context.Context) error {
			_, err := f.svc.CreateDeviceAction(ctx, connect.NewRequest(f.request(lockActionSpec())))
			return err
		},
		"CreateApproval device action": func(ctx context.Context) error {
			_, err := f.svc.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: f.request(lockActionSpec())}}))
			return err
		},
		"CreateApproval resource assignment": func(ctx context.Context) error {
			_, err := f.svc.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_SetResourceAssignment{SetResourceAssignment: &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Clear: true, Reason: "assign profile"}}}))
			return err
		},
		"SetResourceAssignment": func(ctx context.Context) error {
			_, err := f.svc.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Clear: true, Reason: "assign profile"}))
			return err
		},
		"SetDeviceMetadata": func(ctx context.Context) error {
			_, err := f.svc.SetDeviceMetadata(ctx, connect.NewRequest(&adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Metadata: &adminv1.DeviceMetadata{Owner: &adminv1.DeviceMetadata_OwnerText{OwnerText: "new owner"}}, Reason: "edit owner"}))
			return err
		},
		"CreateAssistanceSession": func(ctx context.Context) error {
			_, err := f.svc.CreateAssistanceSession(ctx, connect.NewRequest(&adminv1.CreateAssistanceSessionRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, Reason: "help user"}))
			return err
		},
		"UpdateAssistancePolicy": func(ctx context.Context) error {
			_, err := f.svc.UpdateAssistancePolicy(ctx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: &agentv1.AssistancePolicy{}}))
			return err
		},
		"SetLocalAdminPasswordPolicy": func(ctx context.Context) error {
			_, err := f.svc.SetLocalAdminPasswordPolicy(ctx, connect.NewRequest(&adminv1.SetLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: lapsPolicy(), Reason: "manage admin"}))
			return err
		},
		"RemoveLocalAdminPasswordPolicy": func(ctx context.Context) error {
			_, err := f.svc.RemoveLocalAdminPasswordPolicy(ctx, connect.NewRequest(&adminv1.RemoveLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "stop managing admin"}))
			return err
		},
		"RequestLocalAdminPasswordRotation": func(ctx context.Context) error {
			_, err := f.svc.RequestLocalAdminPasswordRotation(ctx, connect.NewRequest(&adminv1.RequestLocalAdminPasswordRotationRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "rotate admin"}))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := call(f.ownerCtx)
			if connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "device_revoked" {
				t.Fatalf("revoked device mutation: %v (reason %q)", err, rpcReason(err))
			}
		})
	}
	device, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if device.Msg.GetDevice().GetRevokedAt() == nil || device.Msg.GetDevice().GetRevokedByDisplayName() == "" {
		t.Fatalf("revocation provenance missing: %v", device.Msg.GetDevice())
	}
}
