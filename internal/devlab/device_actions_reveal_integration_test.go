// SPDX-License-Identifier: Apache-2.0

//go:build integration

package devlab

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func TestNativeRevealReasonAuthorization(t *testing.T) {
	binary, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	fixture, err := OpenDeviceActionAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := fixture.ConfigureDeviceActions(ctx); err != nil {
		t.Fatal(err)
	}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	_, err = owner.Admin.RevealRecoveryKey(ctx, connect.NewRequest(&adminv1.RevealRecoveryKeyRequest{RequestId: uuid.NewString(), DeviceId: uuid.NewString(), ActionId: uuid.NewString()}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("missing reason denial: %v", err)
	}
	restricted, err := fixture.OpenRestrictedRecoverySession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, denied := restricted.Admin.RevealRecoveryKey(ctx, connect.NewRequest(&adminv1.RevealRecoveryKeyRequest{RequestId: uuid.NewString(), DeviceId: uuid.NewString(), ActionId: uuid.NewString(), Reason: "test dedicated permission"}))
	if err := restricted.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fixture.RestoreAccount(ctx, restricted.AccountID); err != nil {
		t.Fatal(err)
	}
	if connect.CodeOf(denied) != connect.CodePermissionDenied {
		t.Fatalf("restricted reader: %v", denied)
	}
	if err := owner.StepUp(ctx); err != nil {
		t.Fatal(err)
	}
}
