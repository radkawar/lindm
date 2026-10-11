package identity

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestDeviceActionApprovalPermissions(t *testing.T) {
	cases := []struct {
		name       string
		spec       *agentv1.DeviceActionSpec
		permission Permission
	}{
		{"escrow", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{}}}, PermissionManageEncryption},
		{"tpm", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{}}}, PermissionManageEncryption},
		{"lock", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}, PermissionLockDevice},
		{"release lock", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: uuid.NewString()}}}, PermissionReleaseLockDevice},
		{"quarantine", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{}}}, PermissionQuarantineDevice},
		{"release", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseQuarantine{ReleaseQuarantine: &agentv1.ReleaseQuarantineAction{}}}, PermissionQuarantineDevice},
		{"crypto erase", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{}}}, PermissionExecuteDestructive},
		{"sanitize", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{}}}, PermissionExecuteDestructive},
		{"restart", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}, PermissionRunRemoteExecution},
		{"shutdown", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}}, PermissionRunRemoteExecution},
		{"refresh inventory", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}, PermissionManageInventory},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: uuid.NewString(), Spec: tc.spec}
			binding, err := bindApproval(request)
			if err != nil || binding.permission != tc.permission {
				t.Fatalf("permission = %q, error = %v", binding.permission, err)
			}
		})
	}
	if _, err := bindApproval(&adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: uuid.NewString(), Spec: &agentv1.DeviceActionSpec{}}); !errors.Is(err, ErrApprovalInvalid) {
		t.Fatalf("unknown action granted approval authority: %v", err)
	}
}

func TestResourceAssignmentApprovalBinding(t *testing.T) {
	device := uuid.New()
	request := &adminv1.SetResourceAssignmentRequest{
		RequestId: uuid.NewString(), DeviceId: device.String(), Clear: true,
		Reason: "release generic resource assignment",
	}
	payload := approvalPayload(&adminv1.CreateApprovalRequest{
		Payload: &adminv1.CreateApprovalRequest_SetResourceAssignment{SetResourceAssignment: request},
	})
	if payload != request {
		t.Fatal("generic assignment approval arm lost its request")
	}
	binding, err := bindApproval(payload)
	if err != nil {
		t.Fatal(err)
	}
	if binding.action != "resources.assign" || binding.permission != PermissionAssignResources || binding.target != device || binding.mutation != request.GetRequestId() {
		t.Fatalf("incorrect generic assignment authority: %+v", binding)
	}
	request.ApprovalId = uuid.NewString()
	replay, err := bindApproval(request)
	if err != nil || replay.digest != binding.digest {
		t.Fatalf("approval identifier changed bound action: %v", err)
	}
	request.Reason = "different release request"
	changed, err := bindApproval(request)
	if err != nil || changed.digest == binding.digest {
		t.Fatalf("changed assignment retained approval binding: %v", err)
	}
}

func TestTargetPreviewApprovalCannotSubstitutePayload(t *testing.T) {
	device := uuid.New()
	request := &adminv1.ActivateTargetPreviewRequest{
		RequestId: uuid.NewString(), DeviceId: device.String(),
		PreviewId: uuid.NewString(), PreviewSha256: make([]byte, 32),
		Reason: "activate reviewed target preview",
	}
	payload := approvalPayload(&adminv1.CreateApprovalRequest{
		Payload: &adminv1.CreateApprovalRequest_ActivateTargetPreview{ActivateTargetPreview: request},
	})
	if payload != request {
		t.Fatal("activation approval arm lost typed payload")
	}
	binding, err := bindApproval(payload)
	if err != nil {
		t.Fatal(err)
	}
	if binding.action != "resources.activate_preview" || binding.permission != PermissionAssignResources || binding.target != device || binding.mutation != request.GetRequestId() {
		t.Fatalf("incorrect preview approval authority: %+v", binding)
	}
	withApproval := proto.CloneOf(request)
	withApproval.ApprovalId = proto.String(uuid.NewString())
	replay, err := bindApproval(withApproval)
	if err != nil || replay.digest != binding.digest {
		t.Fatalf("approval ID changed reviewed activation: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*adminv1.ActivateTargetPreviewRequest)
	}{
		{"device", func(r *adminv1.ActivateTargetPreviewRequest) { r.DeviceId = uuid.NewString() }},
		{"request", func(r *adminv1.ActivateTargetPreviewRequest) { r.RequestId = uuid.NewString() }},
		{"preview", func(r *adminv1.ActivateTargetPreviewRequest) { r.PreviewId = uuid.NewString() }},
		{"digest", func(r *adminv1.ActivateTargetPreviewRequest) { r.PreviewSha256[0] = 1 }},
		{"reason", func(r *adminv1.ActivateTargetPreviewRequest) { r.Reason = "substituted activation" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := proto.CloneOf(request)
			test.change(changed)
			got, err := bindApproval(changed)
			if err != nil || got.digest == binding.digest {
				t.Fatalf("substituted activation retained approval binding: %v", err)
			}
		})
	}
	request.DeviceId = ""
	if _, err := bindApproval(request); !errors.Is(err, ErrApprovalInvalid) {
		t.Fatalf("unscoped preview activation accepted: %v", err)
	}
}

func TestRevealApprovalBindings(t *testing.T) {
	secret := &adminv1.RevealSecretRequest{RequestId: uuid.NewString(), SecretId: uuid.NewString(), Version: 1, Reason: "audit", ApprovalId: uuid.NewString()}
	binding, err := bindApproval(secret)
	if err != nil || binding.action != "secret.reveal" || binding.permission != PermissionRevealSecrets || binding.target != uuid.Nil || binding.mutation != secret.GetRequestId() {
		t.Fatalf("secret reveal binding=%+v err=%v", binding, err)
	}
	device := uuid.New()
	password := &adminv1.RevealLocalAdminPasswordRequest{RequestId: uuid.NewString(), DeviceId: device.String(), ActionId: uuid.NewString(), Reason: "audit", ApprovalId: uuid.NewString()}
	binding, err = bindApproval(password)
	if err != nil || binding.action != "local_admin.reveal" || binding.permission != PermissionRevealSecrets || binding.target != device || binding.mutation != password.GetRequestId() {
		t.Fatalf("local admin reveal binding=%+v err=%v", binding, err)
	}
	password.DeviceId = "not-a-uuid"
	if _, err := bindApproval(password); !errors.Is(err, ErrApprovalInvalid) {
		t.Fatal("local admin reveal accepted an untargeted payload")
	}
	rotate := &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: device.String(), Spec: &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{}}}}
	if _, err := bindApproval(rotate); !errors.Is(err, ErrApprovalInvalid) {
		t.Fatal("server-minted local-admin rotation accepted a manual approval")
	}
	for _, request := range []*adminv1.CreateApprovalRequest{
		{Payload: &adminv1.CreateApprovalRequest_RevealSecret{RevealSecret: secret}},
		{Payload: &adminv1.CreateApprovalRequest_RevealLocalAdminPassword{RevealLocalAdminPassword: password}},
	} {
		if approvalPayload(request) == nil {
			t.Fatalf("approval payload arm missing: %v", request)
		}
	}
}
