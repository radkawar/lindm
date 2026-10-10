package identity

import (
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func TestRecoveryApprovalPinsGenerationAndRevocation(t *testing.T) {
	request := &adminv1.CreateRecoveryEnrollmentGrantRequest{RequestId: uuid.NewString(), DeviceId: uuid.NewString(), ExpectedGenerationId: uuid.NewString(), LifetimeSeconds: 120, Reason: "replace selected installation"}
	bound, err := bindRecoveryApproval(request)
	if err != nil {
		t.Fatal(err)
	}
	if bound.action != "device.recover" || bound.permission != PermissionRevokeDevice || bound.target.String() != request.GetDeviceId() || bound.mutation != request.GetRequestId() {
		t.Fatal("recovery approval did not bind exact scoped operation")
	}
	withID := proto.CloneOf(request)
	withID.ApprovalId = uuid.NewString()
	same, err := bindRecoveryApproval(withID)
	if err != nil || same.digest != bound.digest {
		t.Fatal("server-issued approval identifier changed approved payload")
	}
	for _, mutate := range []func(*adminv1.CreateRecoveryEnrollmentGrantRequest){
		func(r *adminv1.CreateRecoveryEnrollmentGrantRequest) { r.DeviceId = uuid.NewString() },
		func(r *adminv1.CreateRecoveryEnrollmentGrantRequest) { r.ExpectedGenerationId = uuid.NewString() },
		func(r *adminv1.CreateRecoveryEnrollmentGrantRequest) { r.ExpectedRevoked = true },
		func(r *adminv1.CreateRecoveryEnrollmentGrantRequest) { r.RequestId = uuid.NewString() },
		func(r *adminv1.CreateRecoveryEnrollmentGrantRequest) { r.LifetimeSeconds++ },
		func(r *adminv1.CreateRecoveryEnrollmentGrantRequest) { r.Reason = "different authorization" },
	} {
		changed := proto.CloneOf(request)
		mutate(changed)
		binding, err := bindRecoveryApproval(changed)
		if err != nil || binding.digest == bound.digest {
			t.Fatalf("recovery mutation escaped immutable approval digest: %v", err)
		}
	}
}
