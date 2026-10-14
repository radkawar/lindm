// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"testing"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

func TestResourceAuthenticatedContactPreservesNativeFreshness(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(f.assignmentRequest(nil))); err != nil {
		t.Fatal(err)
	}
	contact := func(call func()) {
		t.Helper()
		var before, after time.Time
		if err := f.pool.QueryRow(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp()-interval '1 hour' WHERE id=$1 RETURNING last_seen_at", f.principal.DeviceID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		call()
		if err := f.pool.QueryRow(t.Context(), "SELECT last_seen_at FROM devices WHERE id=$1", f.principal.DeviceID).Scan(&after); err != nil || !after.After(before) {
			t.Fatalf("authenticated contact not recorded: %v", err)
		}
	}
	var work *devicev1.ResourceWork
	contact(func() { work = f.work(t) })
	contact(func() { f.start(t, work) })
	result := f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, true)
	contact(func() {
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(result)); err != nil {
			t.Fatal(err)
		}
	})
	// Complete the dependent resource so every native proof can then expire.
	work = f.work(t)
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, false))); err != nil {
		t.Fatal(err)
	}
	ageCompliance(t, f, 31*time.Minute)
	contact(func() {
		if _, err := f.service.GetSyncState(f.deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1})); err != nil {
			t.Fatal(err)
		}
	})
	contact(func() {
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(result)); err != nil {
			t.Fatal(err)
		}
	})
	for _, resource := range complianceState(t, f).GetResources() {
		if resource.GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_STALE {
			t.Fatal("authenticated heartbeat or retained result rejuvenated native proof")
		}
	}
}
