//go:build integration

package device

import (
	"slices"
	"testing"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// The release-quarantine picker asks for quarantines only: every one is listed
// across pages however many other actions came after it, and a page token
// continues only the kind set it was issued for.
func TestGetDeviceActionsFiltersByKindAcrossPages(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	quarantine := func() *agentv1.DeviceActionSpec {
		return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{ManagementEndpoints: []string{"192.0.2.1"}}}}
	}
	var quarantines []string
	for _, spec := range []*agentv1.DeviceActionSpec{quarantine(), lockActionSpec(), quarantine(), lockActionSpec(), lockActionSpec()} {
		action := f.create(t, f.request(spec))
		if spec.GetQuarantine() != nil {
			quarantines = append(quarantines, action.GetActionId())
		}
		// One open action at a time: close each before requesting the next.
		if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE device_actions SET closed_at=clock_timestamp(), closed_reason='test_closed' WHERE id=$1", action.GetActionId()); err != nil {
			t.Fatal(err)
		}
	}
	slices.Reverse(quarantines)

	kinds := []adminv1.DeviceActionKind{adminv1.DeviceActionKind_DEVICE_ACTION_KIND_QUARANTINE}
	var got []string
	token := ""
	for {
		response, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID, PageSize: 1, PageToken: token, Kinds: kinds}))
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range response.Msg.GetActions() {
			if action.GetSpec().GetQuarantine() == nil {
				t.Fatalf("kind filter listed %T", action.GetSpec().GetAction())
			}
			got = append(got, action.GetActionId())
		}
		if token = response.Msg.GetNextPageToken(); token == "" {
			break
		}
	}
	if !slices.Equal(got, quarantines) {
		t.Fatalf("quarantines = %v, want newest first %v", got, quarantines)
	}

	all, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID}))
	if err != nil || len(all.Msg.GetActions()) != 5 {
		t.Fatalf("unfiltered list = %d actions, %v", len(all.Msg.GetActions()), err)
	}

	filtered, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID, PageSize: 1, Kinds: kinds}))
	if err != nil {
		t.Fatal(err)
	}
	unfiltered, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID, PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	lock := adminv1.DeviceActionKind_DEVICE_ACTION_KIND_LOCK_SESSIONS
	for name, request := range map[string]*adminv1.GetDeviceActionsRequest{
		"filtered token, other kinds": {DeviceId: f.deviceID, PageToken: filtered.Msg.GetNextPageToken(), Kinds: []adminv1.DeviceActionKind{lock}},
		"filtered token, no kinds":    {DeviceId: f.deviceID, PageToken: filtered.Msg.GetNextPageToken()},
		"unfiltered token with kinds": {DeviceId: f.deviceID, PageToken: unfiltered.Msg.GetNextPageToken(), Kinds: kinds},
		"unspecified kind":            {DeviceId: f.deviceID, Kinds: []adminv1.DeviceActionKind{adminv1.DeviceActionKind_DEVICE_ACTION_KIND_UNSPECIFIED}},
		"undefined kind":              {DeviceId: f.deviceID, Kinds: []adminv1.DeviceActionKind{99}},
		"repeated kind":               {DeviceId: f.deviceID, Kinds: []adminv1.DeviceActionKind{lock, lock}},
	} {
		if _, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%s admitted: %v", name, err)
		}
	}
	// The same kinds in another order are the same filter.
	both := []adminv1.DeviceActionKind{lock, adminv1.DeviceActionKind_DEVICE_ACTION_KIND_QUARANTINE}
	first, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID, PageSize: 1, Kinds: both}))
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(both)
	if _, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID, PageSize: 1, PageToken: first.Msg.GetNextPageToken(), Kinds: both})); err != nil {
		t.Fatalf("reordered kinds refused their own token: %v", err)
	}
}
