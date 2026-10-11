//go:build integration

package device

import (
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	auditv1 "lindm/gen/lindm/audit/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

func TestAuditFiltersComposeHalfOpenEdgesEqualTimestampsAndSnapshot(t *testing.T) {
	f := newEnrolled(t, 0)
	actor, _ := identity.PrincipalFromContext(f.ownerCtx)
	other := insertPrincipal(t, f.ctx, f.conn, identity.RoleAuditor)
	start := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	end := start.Add(7 * 24 * time.Hour)
	target := uuid.MustParse(f.deviceID)
	insert := func(id, principal uuid.UUID, device uuid.UUID, action string, stamp time.Time) {
		t.Helper()
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO audit_events(id,actor_id,target_device_id,action,resource_id,occurred_at) VALUES($1,$2,$3,$4,'filter-contract',$5)`, id, principal, device, action, stamp); err != nil {
			t.Fatal(err)
		}
	}
	low := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	high := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	insert(low, actor.ID, target, "recovery_key.reveal", start)
	insert(high, actor.ID, target, "recovery_key.reveal", start)
	insert(uuid.New(), actor.ID, target, "recovery_key.reveal", start.Add(-time.Microsecond))
	insert(uuid.New(), actor.ID, target, "recovery_key.reveal", end)
	insert(uuid.New(), other.ID, target, "recovery_key.reveal", start)
	insert(uuid.New(), actor.ID, uuid.New(), "recovery_key.reveal", start)
	insert(uuid.New(), actor.ID, target, "local_admin.reveal", start)
	if _, err := f.conn.Exec(f.ctx, `UPDATE principals SET display_name='Audit operator' WHERE id=$1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	filter := &auditv1.AuditFilter{ActorId: new(actor.ID.String()), TargetDeviceId: &f.deviceID,
		ActionCategory: auditv1.AuditActionCategory_AUDIT_ACTION_CATEGORY_RECOVERY_KEY_REVEALS,
		OccurredFrom:   timestamppb.New(start), OccurredUntil: timestamppb.New(end)}
	request := &adminv1.ListAuditEventsRequest{PageSize: 1, Filter: filter}
	first, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Msg.Events) != 1 || first.Msg.Events[0].Id != high.String() || first.Msg.NextPageToken == "" || first.Msg.Events[0].GetActorDisplayName() != "Audit operator" {
		t.Fatalf("wrong first filtered page: %v", first.Msg)
	}
	request.PageToken = first.Msg.NextPageToken
	// A later commit with a backdated occurrence must not enter the saved page.
	insert(uuid.New(), actor.ID, target, "recovery_key.reveal", start.Add(time.Hour))
	insert(uuid.MustParse("00000000-0000-4000-8000-000000000000"), actor.ID, target, "recovery_key.reveal", start)
	second, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.Events) != 1 || second.Msg.Events[0].Id != low.String() || second.Msg.NextPageToken != "" {
		t.Fatalf("snapshot changed or timestamp tie lost: %v", second.Msg)
	}
	replay, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(replay.Msg, second.Msg) {
		t.Fatalf("same continuation changed: %v", err)
	}
	for name, change := range map[string]func(*auditv1.AuditFilter){
		"actor":  func(v *auditv1.AuditFilter) { v.ActorId = new(other.ID.String()) },
		"target": func(v *auditv1.AuditFilter) { v.TargetDeviceId = new(uuid.NewString()) },
		"category": func(v *auditv1.AuditFilter) {
			v.ActionCategory = auditv1.AuditActionCategory_AUDIT_ACTION_CATEGORY_REMOTE_SESSIONS
		},
		"from":  func(v *auditv1.AuditFilter) { v.OccurredFrom = timestamppb.New(start.Add(time.Microsecond)) },
		"until": func(v *auditv1.AuditFilter) { v.OccurredUntil = timestamppb.New(end.Add(time.Second)) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(request)
			change(changed.Filter)
			if _, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("cursor accepted changed selection: %v", err)
			}
		})
	}
	if _, err := f.svc.ListAuditEvents(identity.WithPrincipal(f.ctx, other), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("cursor accepted another caller: %v", err)
	}
	bad := proto.CloneOf(request)
	bad.PageToken = "not-a-cursor"
	if _, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(bad)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed cursor accepted: %v", err)
	}
	// Nanosecond boundaries compare exactly against PostgreSQL microseconds.
	narrow := proto.CloneOf(filter)
	narrow.OccurredFrom = timestamppb.New(start.Add(time.Nanosecond))
	narrow.OccurredUntil = timestamppb.New(start.Add(time.Microsecond))
	page, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(&adminv1.ListAuditEventsRequest{Filter: narrow}))
	if err != nil || len(page.Msg.GetEvents()) != 0 {
		t.Fatalf("submicrosecond lower bound rounded down: %v", err)
	}
}

func TestAuditFiltersRejectScopedAndMalformedRequests(t *testing.T) {
	f := newEnrolled(t, 0)
	actor, _ := identity.PrincipalFromContext(f.ownerCtx)
	actor.Role = identity.RoleAuditor
	actor.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionReadAudit)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{f.deviceID}}}}}
	request := &adminv1.ListAuditEventsRequest{Filter: &auditv1.AuditFilter{TargetDeviceId: &f.deviceID}}
	if _, err := f.svc.ListAuditEvents(identity.WithPrincipal(f.ctx, actor), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("matching target widened scoped audit authority: %v", err)
	}
	for _, filter := range []*auditv1.AuditFilter{
		{ActorId: new("broken")},
		{TargetDeviceId: new("")},
		{ActionCategory: 99},
		{OccurredFrom: timestamppb.New(f.now), OccurredUntil: timestamppb.New(f.now)},
		{OccurredFrom: &timestamppb.Timestamp{Nanos: -1}},
		{OccurredUntil: &timestamppb.Timestamp{Nanos: 1000000000}},
	} {
		if _, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(&adminv1.ListAuditEventsRequest{Filter: filter})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("malformed filter accepted: %v", err)
		}
	}
	if _, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(&adminv1.ListAuditEventsRequest{PageSize: 201})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unbounded page accepted: %v", err)
	}
}

func TestAuditCategoriesUseActualActionsAndDestructiveCapabilities(t *testing.T) {
	f := newDeviceActionFixture(t)
	request := f.request(wipeActionSpec())
	f.observeStorageTargets(t, request.GetSpec().GetCryptoErase().GetTarget())
	f.approval(t, request)
	wipe := f.create(t, request)
	page, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(&adminv1.ListAuditEventsRequest{Filter: &auditv1.AuditFilter{TargetDeviceId: &f.deviceID, ActionCategory: auditv1.AuditActionCategory_AUDIT_ACTION_CATEGORY_DESTRUCTIVE_ACTIONS}}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range page.Msg.Events {
		if event.GetResourceId() == wipe.GetActionId() && event.GetAction() == "device_action.create" && event.GetTargetDeviceId() == f.deviceID {
			found = true
		}
	}
	if !found {
		t.Fatal("actual destructive admission missing target/category projection")
	}
	for _, tc := range []struct {
		action, capability string
		want               int16
	}{
		{"recovery_key.reveal", "device.escrow-rotate.v1", 1},
		{"local_admin.reveal", "device.local-admin-rotate.v1", 0},
		{"device_action.create", "device.crypto-erase.v1", 2},
		{"device_action.start", "device.sanitize.v1", 2},
		{"device_action.result", "device.sanitize.v1", 2},
		{"device_action.recovery_handoff", "device.sanitize.v1", 2},
		{"device_action.recovery_start", "device.sanitize.v1", 2},
		{"device_action.recovery_checkpoint", "device.sanitize.v1", 2},
		{"device_action.recovery_result", "device.sanitize.v1", 2},
		{"device_action.create", "device.restart.v1", 0},
		{"device_action.result", "device.lock-sessions.v1", 0},
		{"device_action.escrow_store", "device.escrow-rotate.v1", 0},
	} {
		var got int16
		if err := f.conn.QueryRow(f.ctx, `SELECT audit_action_category($1,$2)`, tc.action, tc.capability).Scan(&got); err != nil || got != tc.want {
			t.Fatalf("category %s/%s = %d, want %d: %v", tc.action, tc.capability, got, tc.want, err)
		}
	}
	actions := []string{"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start", "assistance.stop", "assistance.end"}
	for _, action := range actions {
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO audit_events(action,resource_id,target_device_id) VALUES($1,'remote-filter',$2)`, action, f.deviceID); err != nil {
			t.Fatal(err)
		}
	}
	remote, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(&adminv1.ListAuditEventsRequest{Filter: &auditv1.AuditFilter{ActionCategory: auditv1.AuditActionCategory_AUDIT_ACTION_CATEGORY_REMOTE_SESSIONS, TargetDeviceId: &f.deviceID}}))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, event := range remote.Msg.Events {
		got = append(got, event.Action)
	}
	slices.Sort(actions)
	slices.Sort(got)
	if !slices.Equal(got, actions) {
		t.Fatalf("remote lifecycle selection = %v", got)
	}
}

func TestAuditTargetListAndPickerIncludeActualEnrollment(t *testing.T) {
	f := newEnrolled(t, 0)
	page, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(&adminv1.ListAuditEventsRequest{Filter: &auditv1.AuditFilter{TargetDeviceId: &f.deviceID}}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range page.Msg.Events {
		if event.GetAction() == "device.enroll" && event.GetResourceId() == f.deviceID && event.GetTargetDeviceId() == f.deviceID {
			found = true
		}
	}
	if !found {
		t.Fatal("target-filtered audit omitted the actual enrollment event")
	}
	options, err := f.svc.ListAuditDevices(f.ownerCtx, connect.NewRequest(&adminv1.ListAuditDevicesRequest{Id: &f.deviceID, PageSize: 1}))
	if err != nil || len(options.Msg.GetDevices()) != 1 || options.Msg.Devices[0].Id != f.deviceID {
		t.Fatalf("enrolled device missing from audit-only picker: %v", err)
	}
	var originalTarget *uuid.UUID
	if err := f.conn.QueryRow(f.ctx, `SELECT target_device_id FROM audit_events WHERE action=$1 AND resource_id=$2`, "device.enroll", f.deviceID).Scan(&originalTarget); err != nil {
		t.Fatal(err)
	}
	if originalTarget != nil {
		t.Fatal("projection rewrote original enrollment evidence")
	}
}
