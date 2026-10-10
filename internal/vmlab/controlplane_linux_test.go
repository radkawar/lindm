//go:build linux

package vmlab

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/devlab"
)

func TestRevocationAuthenticatesApproverOnlyWhenNeeded(t *testing.T) {
	const deviceID = "00000000-0000-4000-8000-000000000001"
	calls := 0
	control := &vmControlPlane{
		devices: make(map[string]*vmTrackedDevice),
		openApprover: func(context.Context) (*devlab.ApprovalSession, error) {
			calls++
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("session unavailable"))
		},
	}
	if err := control.RevokeDevice(t.Context(), deviceID); err == nil || calls != 0 {
		t.Fatal("untracked device caused approval authentication")
	}
	if err := control.TrackDevice(deviceID); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || control.approver != nil {
		t.Fatal("tracking a device consumed the approver idle-session lifetime")
	}
	if err := control.RevokeDevice(t.Context(), deviceID); connect.CodeOf(err) != connect.CodeUnauthenticated || calls != 1 {
		t.Fatalf("revocation did not fail at fresh approver authentication: calls=%d err=%v", calls, err)
	}
	device := control.devices[deviceID]
	if control.approver != nil || device.revoked || device.approval != nil || device.request.GetApprovalId() != "" {
		t.Fatal("failed authentication retained approval authority or claimed revocation")
	}
	device.revoked = true
	if err := control.RevokeDevice(t.Context(), deviceID); err != nil || calls != 1 {
		t.Fatal("already revoked device caused another authentication")
	}
	control.closed = true
	if err := control.RevokeDevice(t.Context(), deviceID); err == nil || calls != 1 {
		t.Fatal("closed control plane caused approval authentication")
	}
}

func TestRevocationRetainsOpenedApproverAfterApprovalFailure(t *testing.T) {
	const deviceID = "00000000-0000-4000-8000-000000000001"
	calls := 0
	// An uninitialized real session rejects approval before any mutation. This
	// tests session ownership, not a successful authentication or native lane.
	approver := new(devlab.ApprovalSession)
	control := &vmControlPlane{
		devices: map[string]*vmTrackedDevice{deviceID: {request: &adminv1.RevokeDeviceRequest{DeviceId: deviceID}}},
		openApprover: func(context.Context) (*devlab.ApprovalSession, error) {
			calls++
			return approver, nil
		},
	}
	for range 2 {
		if err := control.RevokeDevice(t.Context(), deviceID); err == nil {
			t.Fatal("approval accepted an unauthenticated session")
		}
	}
	if calls != 1 || control.approver != approver {
		t.Fatal("approval failure silently replaced or lost the owned session")
	}
}
