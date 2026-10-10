package identity

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func bindRecoveryApproval(request *adminv1.CreateRecoveryEnrollmentGrantRequest) (approvalBinding, error) {
	var binding approvalBinding
	if request == nil {
		return binding, ErrApprovalInvalid
	}
	deviceID, err := uuid.Parse(request.GetDeviceId())
	if err != nil || deviceID == uuid.Nil {
		return binding, ErrApprovalInvalid
	}
	generation, err := uuid.Parse(request.GetExpectedGenerationId())
	if err != nil || generation == uuid.Nil {
		return binding, ErrApprovalInvalid
	}
	payload := proto.CloneOf(request)
	payload.ApprovalId = ""
	binding.action, binding.permission = "device.recover", PermissionRevokeDevice
	binding.target, binding.mutation = deviceID, request.GetRequestId()
	binding.payload, err = (proto.MarshalOptions{Deterministic: true}).Marshal(payload)
	if err != nil {
		return binding, fmt.Errorf("encode recovery approval: %w", err)
	}
	binding.digest = sha256.Sum256(binding.payload)
	return binding, nil
}
