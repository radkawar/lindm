//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

func TestAuditOnlyLookupsAreBoundedLiteralAndResolveSavedIDs(t *testing.T) {
	f := newEnrolled(t, 0)
	reader, _ := identity.PrincipalFromContext(f.ownerCtx)
	reader.Role = identity.RoleAuditor
	reader.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionReadAudit)}}}
	ctx := identity.WithPrincipal(f.ctx, reader)
	ids := []uuid.UUID{uuid.MustParse("00000000-0000-4000-8000-000000000001"), uuid.MustParse("00000000-0000-4000-8000-000000000002")}
	for _, id := range ids {
		for _, statement := range []string{
			`INSERT INTO principals(id,issuer,subject,display_name) VALUES($1::uuid,'audit-picker',($1::uuid)::text,'Audit%_ operator')`,
			`INSERT INTO devices(id,state,hostname,enrolled_at) VALUES($1,'pending','Audit%_ device',now())`,
			`INSERT INTO audit_events(actor_id,target_device_id,action,resource_id) VALUES($1,$1,'recovery_key.reveal','audit-picker')`,
		} {
			if _, err := f.conn.Exec(f.ctx, statement, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Keep inactive actors searchable; names are current context, not authority.
	if _, err := f.conn.Exec(f.ctx, `UPDATE principals SET deactivated_at=now(),deactivation_source='scim' WHERE id=$1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	first, err := f.svc.ListAuditActors(ctx, connect.NewRequest(&adminv1.ListAuditActorsRequest{NamePrefix: "audit%_", PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Msg.Actors) != 1 || first.Msg.Actors[0].Id != ids[0].String() || first.Msg.NextAfterId != ids[0].String() {
		t.Fatalf("actor first page: %v", first.Msg)
	}
	second, err := f.svc.ListAuditActors(ctx, connect.NewRequest(&adminv1.ListAuditActorsRequest{NamePrefix: "audit%_", PageSize: 1, AfterId: first.Msg.NextAfterId}))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.Actors) != 1 || second.Msg.Actors[0].Id != ids[1].String() || second.Msg.NextAfterId != "" {
		t.Fatalf("actor continuation: %v", second.Msg)
	}
	selected, err := f.svc.ListAuditActors(ctx, connect.NewRequest(&adminv1.ListAuditActorsRequest{Id: new(ids[1].String()), PageSize: 1}))
	if err != nil || len(selected.Msg.GetActors()) != 1 {
		t.Fatalf("saved inactive actor lookup: %v", err)
	}
	devices, err := f.svc.ListAuditDevices(ctx, connect.NewRequest(&adminv1.ListAuditDevicesRequest{NamePrefix: "AUDIT%_", PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if len(devices.Msg.Devices) != 1 || devices.Msg.Devices[0].Id != ids[0].String() || devices.Msg.NextAfterId != ids[0].String() {
		t.Fatalf("device first page: %v", devices.Msg)
	}
	device, err := f.svc.ListAuditDevices(ctx, connect.NewRequest(&adminv1.ListAuditDevicesRequest{Id: new(ids[1].String()), PageSize: 1}))
	if err != nil || len(device.Msg.GetDevices()) != 1 {
		t.Fatalf("saved device lookup: %v", err)
	}
	unknown := uuid.NewString()
	for _, statement := range []string{
		`INSERT INTO principals(id,issuer,subject,display_name) VALUES($1::uuid,'audit-picker',($1::uuid)::text,'AuditXY decoy')`,
		`INSERT INTO devices(id,state,hostname,enrolled_at) VALUES($1,'pending','AuditXY decoy',now())`,
	} {
		if _, err := f.conn.Exec(f.ctx, statement, unknown); err != nil {
			t.Fatal(err)
		}
	}
	missingActor, err := f.svc.ListAuditActors(ctx, connect.NewRequest(&adminv1.ListAuditActorsRequest{Id: &unknown}))
	if err != nil || len(missingActor.Msg.GetActors()) != 0 {
		t.Fatalf("unreferenced actor exposed: %v", err)
	}
	missingDevice, err := f.svc.ListAuditDevices(ctx, connect.NewRequest(&adminv1.ListAuditDevicesRequest{Id: &unknown}))
	if err != nil || len(missingDevice.Msg.GetDevices()) != 0 {
		t.Fatalf("unreferenced device exposed: %v", err)
	}
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO audit_events(actor_id,target_device_id,action,resource_id) VALUES($1,$1,'recovery_key.reveal','picker-decoy')`, unknown); err != nil {
		t.Fatal(err)
	}
	literalActors, err := f.svc.ListAuditActors(ctx, connect.NewRequest(&adminv1.ListAuditActorsRequest{NamePrefix: "Audit%_"}))
	if err != nil || len(literalActors.Msg.GetActors()) != 2 {
		t.Fatalf("actor prefix treated wildcard characters as a pattern: %v", err)
	}
	literalDevices, err := f.svc.ListAuditDevices(ctx, connect.NewRequest(&adminv1.ListAuditDevicesRequest{NamePrefix: "Audit%_"}))
	if err != nil || len(literalDevices.Msg.GetDevices()) != 2 {
		t.Fatalf("device prefix treated wildcard characters as a pattern: %v", err)
	}
	if _, err := f.conn.Exec(f.ctx, `DELETE FROM devices WHERE id=$1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	deleted, err := f.svc.ListAuditDevices(ctx, connect.NewRequest(&adminv1.ListAuditDevicesRequest{Id: new(ids[1].String())}))
	if err != nil || len(deleted.Msg.GetDevices()) != 0 {
		t.Fatalf("deleted device label fabricated: %v", err)
	}
	if _, err := f.svc.ListAuditActors(ctx, connect.NewRequest(&adminv1.ListAuditActorsRequest{PageSize: 101})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unbounded actor page: %v", err)
	}
	if _, err := f.svc.ListAuditDevices(ctx, connect.NewRequest(&adminv1.ListAuditDevicesRequest{Id: new("broken")})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed selected id: %v", err)
	}
	reader.Bindings[0].Scopes = []*authv1.DeviceScope{{DeviceIds: []string{ids[0].String()}}}
	scoped := identity.WithPrincipal(f.ctx, reader)
	if _, err := f.svc.ListAuditActors(scoped, connect.NewRequest(&adminv1.ListAuditActorsRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped actor lookup admitted: %v", err)
	}
	if _, err := f.svc.ListAuditDevices(scoped, connect.NewRequest(&adminv1.ListAuditDevicesRequest{Id: new(ids[0].String())})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped exact device lookup admitted: %v", err)
	}
}
