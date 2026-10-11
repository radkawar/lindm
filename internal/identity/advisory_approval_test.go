package identity

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func TestAdvisoryApprovalBindsEveryAcceptanceField(t *testing.T) {
	request := &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: uuid.NewString(), FindingId: uuid.NewString(), Reason: "Reviewed temporary exception", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}
	binding, err := bindApproval(request)
	if err != nil {
		t.Fatal(err)
	}
	if binding.action != "advisory_exception.accept" || binding.permission != PermissionManageAdvisoryExceptions || binding.target.String() != request.GetDeviceId() {
		t.Fatal("incorrect advisory approval authority")
	}
	request.ApprovalId = uuid.NewString()
	replay, err := bindApproval(request)
	if err != nil || replay.digest != binding.digest {
		t.Fatal("approval identifier changed exact payload")
	}
	for _, change := range []struct {
		name   string
		mutate func(*adminv1.AcceptAdvisoryFindingRequest)
	}{
		{"request", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.RequestId = uuid.NewString() }},
		{"device", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.DeviceId = uuid.NewString() }},
		{"finding", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.FindingId = uuid.NewString() }},
		{"reason", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.Reason += " changed" }},
		{"expiry", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.ExpiresAt.Nanos++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := proto.CloneOf(request)
			change.mutate(changed)
			actual, err := bindApproval(changed)
			if err != nil || actual.digest == binding.digest {
				t.Fatalf("changed field retained approval: %v", err)
			}
		})
	}
}
