// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/admin/v1/adminv1connect"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/devlab"
)

type blockingDeviceAdmin struct {
	adminv1connect.AdminServiceClient
	calls int
}

func (a *blockingDeviceAdmin) GetDevice(ctx context.Context, request *connect.Request[adminv1.GetDeviceRequest]) (*connect.Response[adminv1.GetDeviceResponse], error) {
	a.calls++
	if a.calls == 1 {
		return connect.NewResponse(&adminv1.GetDeviceResponse{Device: &adminv1.Device{Id: request.Msg.GetDeviceId()}}), nil
	}
	<-ctx.Done()
	return nil, connect.NewError(connect.CodeDeadlineExceeded, ctx.Err())
}

// The Arch x86_64 lifecycle reported only "deadline_exceeded: get device
// failed" after 18 minutes: the poll that the wait's own deadline interrupted
// replaced the device mismatch that explained the failure.
func TestInventoryWaitKeepsMismatchAtDeadline(t *testing.T) {
	admin := &blockingDeviceAdmin{}
	control := &vmControlPlane{session: &devlab.OwnerSession{Admin: admin}}
	_, err := control.waitInventory(t.Context(), "0b5b3f5e-7f3c-4c4e-9d1e-2f6a1b0c9d8e", 1500*time.Millisecond, func(context.Context, *adminv1.GetDeviceResponse) (*vmInventoryEvidence, error) {
		return nil, errors.New("new successful package publication has not arrived")
	})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "publication has not arrived") || strings.Contains(err.Error(), "get device") || admin.calls != 2 {
		t.Fatalf("wait diagnosis = %v after %d calls", err, admin.calls)
	}
}

// Arch x86_64 packaged lifecycle then never matched: inspection already
// accepted Arch's absent VERSION_ID as UNAVAILABLE, but the control-plane
// publication comparison demanded SUCCESS for every host field.
func TestPublishedHostComparisonMatchesInspection(t *testing.T) {
	observed := func(status inventoryv1.CollectionStatus, value string) *inventoryv1.ObservedString {
		return &inventoryv1.ObservedString{Status: status, Value: value}
	}
	host := func(id string, version *inventoryv1.ObservedString) *inventoryv1.HostObservation {
		ok := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
		return &inventoryv1.HostObservation{OsId: observed(ok, id), OsVersion: version, Architecture: observed(ok, "x86_64"),
			KernelRelease: observed(ok, "6.17.1-arch1-1"), Hostname: observed(ok, "archlinux"), BootId: observed(ok, "71b44ad1-6894-451e-8b48-b1efb5b1c0f2")}
	}
	arch := &vmTruth{host: [6]string{"arch", "", "x86_64", "6.17.1-arch1-1", "archlinux", "71b44ad1-6894-451e-8b48-b1efb5b1c0f2"}}
	unavailable := observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, "")
	if err := vmCompareHost(arch, host("arch", unavailable)); err != nil {
		t.Fatalf("published Arch host rejected: %v", err)
	}
	for _, version := range []*inventoryv1.ObservedString{observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "rolling"), observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED, ""), nil} {
		if vmCompareHost(arch, host("arch", version)) == nil {
			t.Fatalf("accepted fabricated or failed Arch version %v", version)
		}
	}
	debian := &vmTruth{host: arch.host}
	debian.host[0] = "debian"
	if vmCompareHost(debian, host("debian", unavailable)) == nil {
		t.Fatal("non-Arch absent version accepted")
	}
}
