//go:build integration

package device

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

func defineInventoryAttribute(t *testing.T, f *enrolledFixture, key string, kind adminv1.AttributeType, values ...string) {
	t.Helper()
	_, err := f.svc.SetAttributeDefinition(f.ownerCtx, connect.NewRequest(&adminv1.SetAttributeDefinitionRequest{RequestId: uuid.NewString(), Definition: &adminv1.AttributeDefinition{Key: key, Type: kind, EnumValues: values}, Reason: "define test inventory attribute"}))
	if err != nil {
		t.Fatal(err)
	}
}

func setInventoryMetadata(t *testing.T, f *enrolledFixture, id string, metadata *adminv1.DeviceMetadata) *adminv1.SetDeviceMetadataRequest {
	t.Helper()
	request := &adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: id, Metadata: metadata, Reason: "assign test inventory metadata"}
	if _, err := f.svc.SetDeviceMetadata(f.ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestInventoryMetadataTypingOwnershipAuditAndReplay(t *testing.T) {
	f := newEnrolled(t, 0)
	defineInventoryAttribute(t, f, "desk", adminv1.AttributeType_ATTRIBUTE_TYPE_STRING)
	defineInventoryAttribute(t, f, "floor", adminv1.AttributeType_ATTRIBUTE_TYPE_INT)
	defineInventoryAttribute(t, f, "loaner", adminv1.AttributeType_ATTRIBUTE_TYPE_BOOL)
	defineInventoryAttribute(t, f, "site", adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM, "east", "west")
	metadata := &adminv1.DeviceMetadata{Labels: []string{"engineering", "site:east"}, Owner: &adminv1.DeviceMetadata_OwnerText{OwnerText: "Workplace team"}, Attributes: map[string]*adminv1.AttributeValue{
		"desk":   {Value: &adminv1.AttributeValue_StringValue{StringValue: "A-12"}},
		"floor":  {Value: &adminv1.AttributeValue_IntValue{IntValue: 0}},
		"loaner": {Value: &adminv1.AttributeValue_BoolValue{BoolValue: false}},
		"site":   {Value: &adminv1.AttributeValue_EnumValue{EnumValue: "east"}},
	}}
	request := setInventoryMetadata(t, f, f.deviceID, metadata)
	if _, err := f.svc.SetDeviceMetadata(f.ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	filtered, err := f.svc.ListDevices(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicesRequest{Filter: &adminv1.DeviceFilter{Labels: metadata.Labels, Attributes: metadata.Attributes}}))
	if err != nil || len(filtered.Msg.GetDevices()) != 1 || filtered.Msg.GetDevices()[0].GetId() != f.deviceID {
		t.Fatalf("typed zero/false/string/enum search mismatch: %v", err)
	}
	var audits int
	if err := f.conn.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE action='inventory.SetDeviceMetadata' AND resource_id=$1`, f.deviceID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("mutation audit count=%d: %v", audits, err)
	}
	detail, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil || !proto.Equal(detail.Msg.GetDevice().GetMetadata(), metadata) {
		t.Fatalf("metadata did not round-trip: %v", err)
	}
	changed := proto.CloneOf(request)
	changed.Metadata.Labels = []string{"changed"}
	if _, err := f.svc.SetDeviceMetadata(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed retry accepted: %v", err)
	}
	for _, bad := range []*adminv1.DeviceMetadata{
		{Attributes: map[string]*adminv1.AttributeValue{"missing": {Value: &adminv1.AttributeValue_BoolValue{BoolValue: true}}}},
		{Attributes: map[string]*adminv1.AttributeValue{"floor": {Value: &adminv1.AttributeValue_StringValue{StringValue: "0"}}}},
		{Attributes: map[string]*adminv1.AttributeValue{"site": {Value: &adminv1.AttributeValue_EnumValue{EnumValue: "north"}}}},
		{Owner: &adminv1.DeviceMetadata_OwnerPrincipalId{OwnerPrincipalId: uuid.NewString()}},
	} {
		_, err := f.svc.SetDeviceMetadata(f.ownerCtx, connect.NewRequest(&adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Metadata: bad, Reason: "reject invalid metadata"}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("invalid metadata accepted: %v", err)
		}
	}
	for _, definition := range []*adminv1.AttributeDefinition{
		{Key: "floor", Type: adminv1.AttributeType_ATTRIBUTE_TYPE_STRING},
		{Key: "site", Type: adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM, EnumValues: []string{"west"}},
	} {
		_, err := f.svc.SetAttributeDefinition(f.ownerCtx, connect.NewRequest(&adminv1.SetAttributeDefinitionRequest{RequestId: uuid.NewString(), Definition: definition, Reason: "reject incompatible schema change"}))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("stored values invalidated: %v", err)
		}
	}
	defineInventoryAttribute(t, f, "site", adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM, "east", "west", "north")
	actor, _ := identity.PrincipalFromContext(f.ownerCtx)
	setInventoryMetadata(t, f, f.deviceID, &adminv1.DeviceMetadata{Owner: &adminv1.DeviceMetadata_OwnerPrincipalId{OwnerPrincipalId: actor.ID.String()}})
	detail, err = f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil || detail.Msg.GetDevice().GetMetadata().GetOwnerPrincipalId() != actor.ID.String() || detail.Msg.GetDevice().GetMetadata().GetOwnerText() != "" {
		t.Fatalf("principal owner did not replace free text: %v", err)
	}
	// With all stored values removed, changing the key's type is safe.
	defineInventoryAttribute(t, f, "floor", adminv1.AttributeType_ATTRIBUTE_TYPE_BOOL)
	listed, err := f.svc.ListAttributeDefinitions(f.ownerCtx, connect.NewRequest(&adminv1.ListAttributeDefinitionsRequest{PageSize: 2}))
	if err != nil || len(listed.Msg.GetDefinitions()) != 2 || listed.Msg.GetNextAfterKey() == "" {
		t.Fatalf("definition pagination: %v", err)
	}
	next, err := f.svc.ListAttributeDefinitions(f.ownerCtx, connect.NewRequest(&adminv1.ListAttributeDefinitionsRequest{PageSize: 2, AfterKey: listed.Msg.GetNextAfterKey()}))
	if err != nil || len(next.Msg.GetDefinitions()) != 2 || next.Msg.GetNextAfterKey() != "" {
		t.Fatalf("definition continuation: %v", err)
	}
}

func TestInventoryMetadataAuditFailureRollsBack(t *testing.T) {
	f := newEnrolled(t, 0)
	if _, err := f.conn.Exec(f.ctx, `CREATE FUNCTION reject_inventory_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.SetDeviceMetadata' THEN RAISE EXCEPTION 'test audit unavailable'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_inventory_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_inventory_audit()`); err != nil {
		t.Fatal(err)
	}
	request := &adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Metadata: &adminv1.DeviceMetadata{Labels: []string{"must-rollback"}}, Reason: "audit must be atomic"}
	if _, err := f.svc.SetDeviceMetadata(f.ownerCtx, connect.NewRequest(request)); err == nil {
		t.Fatal("mutation committed without audit")
	}
	var labels, receipts int
	if err := f.conn.QueryRow(f.ctx, `SELECT count(*) FROM device_labels WHERE device_id=$1`, f.principal.DeviceID).Scan(&labels); err != nil {
		t.Fatal(err)
	}
	if err := f.conn.QueryRow(f.ctx, `SELECT count(*) FROM device_admin_requests WHERE request_id=$1`, request.RequestId).Scan(&receipts); err != nil || labels != 0 || receipts != 0 {
		t.Fatalf("partial mutation survived labels=%d receipts=%d: %v", labels, receipts, err)
	}
	if _, err := f.conn.Exec(f.ctx, `DROP TRIGGER reject_inventory_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetDeviceMetadata(f.ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatalf("rolled-back request could not retry: %v", err)
	}
}

func TestInventorySearchCursorBindingAndScopedExports(t *testing.T) {
	f := newEnrolled(t, 0)
	defineInventoryAttribute(t, f, "floor", adminv1.AttributeType_ATTRIBUTE_TYPE_INT)
	matching := map[string]bool{}
	for i := range 5 {
		id := uuid.New()
		host := "safe-host"
		if i == 0 {
			host = "\t=HYPERLINK(\"https://example.invalid\")"
		}
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices(id,state,enrolled_at,last_seen_at,hostname,os_id,os_version) VALUES($1,'pending',$2,$2,$3,'ubuntu','24.04')`, id, f.now, host); err != nil {
			t.Fatal(err)
		}
		label := "allowed"
		if i == 4 {
			label = "denied"
		} else {
			matching[id.String()] = true
		}
		setInventoryMetadata(t, f, id.String(), &adminv1.DeviceMetadata{Labels: []string{label}, Attributes: map[string]*adminv1.AttributeValue{"floor": {Value: &adminv1.AttributeValue_IntValue{IntValue: 0}}}})
	}
	actor, _ := identity.PrincipalFromContext(f.ownerCtx)
	actor.Role = identity.RoleAuditor
	actor.Bindings = []*authv1.RoleBinding{{Role: identity.RoleAuditor, Permissions: []string{string(identity.PermissionReadFleet)}, Scopes: []*authv1.DeviceScope{{Labels: []string{"allowed"}}}}}
	scopedCtx := identity.WithPrincipal(f.ctx, actor)
	filter := &adminv1.DeviceFilter{OsId: "ubuntu", OsVersion: "24.04", Labels: []string{"allowed"}, Attributes: map[string]*adminv1.AttributeValue{"floor": {Value: &adminv1.AttributeValue_IntValue{IntValue: 0}}}, LastSeenFrom: timestamppb.New(f.now.Add(-time.Hour)), LastSeenUntil: timestamppb.New(f.now)}
	request := &adminv1.ListDevicesRequest{PageSize: 2, Filter: filter}
	first, err := f.svc.ListDevices(scopedCtx, connect.NewRequest(request))
	if err != nil || len(first.Msg.GetDevices()) != 2 || first.Msg.GetNextPageToken() == "" {
		t.Fatalf("filtered first page: %v", err)
	}
	request.PageToken = first.Msg.GetNextPageToken()
	changed := proto.CloneOf(request)
	changed.Filter.OsVersion = "22.04"
	if _, err := f.svc.ListDevices(scopedCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("cursor allowed changed filter: %v", err)
	}
	if _, err := f.svc.ListDevices(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("cursor allowed changed scope: %v", err)
	}
	other := actor
	other.ID = uuid.New()
	if _, err := f.svc.ListDevices(identity.WithPrincipal(f.ctx, other), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("cursor allowed changed actor: %v", err)
	}
	second, err := f.svc.ListDevices(scopedCtx, connect.NewRequest(request))
	if err != nil || len(second.Msg.GetDevices()) != 2 || second.Msg.GetNextPageToken() != "" {
		t.Fatalf("filtered continuation: %v", err)
	}
	for _, page := range []*adminv1.ListDevicesResponse{first.Msg, second.Msg} {
		assertInventoryPageFits(t, page)
		for _, item := range page.GetDevices() {
			if !matching[item.GetId()] {
				t.Fatalf("scoped page duplicated or leaked %s", item.GetId())
			}
			delete(matching, item.GetId())
		}
	}
	if len(matching) != 0 {
		t.Fatalf("pagination lost %d devices", len(matching))
	}
	// A later enrollment cannot move the first-page boundary or enter a
	// continuation. Revisit the first page using its own returned token.
	laterID := uuid.New()
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices(id,state,enrolled_at,last_seen_at,hostname,os_id,os_version,metadata)
		SELECT $1,state,$2,last_seen_at,hostname,os_id,os_version,metadata FROM devices WHERE id=$3`, laterID, f.now.Add(time.Second), first.Msg.Devices[0].GetId()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO device_labels(device_id,label) VALUES($1,'allowed')`, laterID); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Second)
	revisited, err := f.svc.ListDevices(scopedCtx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 2, Filter: filter, PageToken: first.Msg.GetPageToken()}))
	if err != nil || !proto.Equal(revisited.Msg, first.Msg) || first.Msg.GetPageToken() == "" {
		t.Fatalf("first-page cursor changed cutoff or expiry: %v", err)
	}
	for _, format := range []adminv1.DeviceExportFormat{adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV, adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON} {
		export := &adminv1.ExportDevicesRequest{PageSize: 2, Filter: filter, Format: format}
		count := 0
		formulaProtected := false
		for page := 0; ; page++ {
			if page > 4 {
				t.Fatal("export failed to terminate")
			}
			response, err := f.svc.ExportDevices(scopedCtx, connect.NewRequest(export))
			if err != nil {
				t.Fatal(err)
			}
			assertInventoryPageFits(t, response.Msg)
			if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV {
				rows, err := csv.NewReader(bytes.NewReader(response.Msg.GetContent())).ReadAll()
				if err != nil || len(rows) < 2 || rows[0][0] != "id" {
					t.Fatalf("invalid CSV page: %v", err)
				}
				for _, row := range rows[1:] {
					if row[8] != "allowed" {
						t.Fatal("CSV leaked unauthorized metadata")
					}
					if strings.HasPrefix(row[1], "'\t=") {
						formulaProtected = true
					}
				}
				count += len(rows) - 1
			} else {
				var rows []json.RawMessage
				if err := json.Unmarshal(response.Msg.GetContent(), &rows); err != nil {
					t.Fatal(err)
				}
				count += len(rows)
			}
			if response.Msg.GetNextPageToken() == "" {
				break
			}
			export.PageToken = response.Msg.GetNextPageToken()
		}
		if count != 5 || (format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV && !formulaProtected) {
			t.Fatalf("export count=%d formulaProtected=%v", count, formulaProtected)
		}
	}
	if _, err := f.svc.ExportDevices(scopedCtx, connect.NewRequest(&adminv1.ExportDevicesRequest{Filter: filter, Format: adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON, PageToken: request.PageToken})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("list cursor accepted for export: %v", err)
	}
	f.now = f.now.Add(16 * time.Minute)
	if _, err := f.svc.ListDevices(scopedCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("expired cursor accepted: %v", err)
	}
}

func TestInventoryValidationAndAuthorization(t *testing.T) {
	f := newEnrolled(t, 0)
	for _, filter := range []*adminv1.DeviceFilter{
		{LastSeenFrom: timestamppb.New(f.now), LastSeenUntil: timestamppb.New(f.now.Add(-time.Second))},
		{Labels: []string{"invalid label"}},
		{Attributes: map[string]*adminv1.AttributeValue{"invalid key": {Value: &adminv1.AttributeValue_IntValue{IntValue: 1}}}},
	} {
		if _, err := f.svc.ListDevices(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicesRequest{Filter: filter})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("invalid filter accepted: %v", err)
		}
	}
	request := &adminv1.SetDeviceMetadataRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Metadata: &adminv1.DeviceMetadata{}, Reason: "deny unauthorized metadata change"}
	if _, err := f.svc.SetDeviceMetadata(context.Background(), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous mutation accepted: %v", err)
	}
	actor := insertPrincipal(t, f.ctx, f.conn, identity.RoleAuditor)
	denied := identity.WithPrincipal(f.ctx, actor)
	if _, err := f.svc.SetDeviceMetadata(denied, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("auditor mutation accepted: %v", err)
	}
	if _, err := f.svc.ExportDevices(context.Background(), connect.NewRequest(&adminv1.ExportDevicesRequest{Format: adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous export accepted: %v", err)
	}
}

func TestInventoryExportByteBudgetAndDefinitionReplay(t *testing.T) {
	f := newEnrolled(t, 0)
	definition := &adminv1.SetAttributeDefinitionRequest{RequestId: uuid.NewString(), Definition: &adminv1.AttributeDefinition{Key: "asset", Type: adminv1.AttributeType_ATTRIBUTE_TYPE_STRING}, Reason: "test definition receipt"}
	for range 2 {
		if _, err := f.svc.SetAttributeDefinition(f.ownerCtx, connect.NewRequest(definition)); err != nil {
			t.Fatal(err)
		}
	}
	changed := proto.CloneOf(definition)
	changed.Definition.Type = adminv1.AttributeType_ATTRIBUTE_TYPE_BOOL
	if _, err := f.svc.SetAttributeDefinition(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed definition retry accepted: %v", err)
	}
	var audits int
	if err := f.conn.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE action='inventory.SetAttributeDefinition' AND resource_id='asset'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("definition retry emitted %d audits: %v", audits, err)
	}
	// JSON escaping and CSV quoting each amplify these admitted field values.
	value := strings.Repeat("\"\n", 2048)
	for range 60 {
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id,os_version,architecture) VALUES($1,'pending',$2,$3,$3,$3,$3)`, uuid.New(), f.now, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, format := range []adminv1.DeviceExportFormat{adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV, adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON} {
		request := &adminv1.ExportDevicesRequest{Format: format, PageSize: 200}
		count, pages := 0, 0
		for {
			pages++
			if pages > 61 {
				t.Fatal("byte-bounded export did not terminate")
			}
			response, err := f.svc.ExportDevices(f.ownerCtx, connect.NewRequest(request))
			if err != nil {
				t.Fatal(err)
			}
			assertInventoryPageFits(t, response.Msg)
			if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV {
				rows, err := csv.NewReader(bytes.NewReader(response.Msg.GetContent())).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				count += len(rows) - 1
			} else {
				var rows []json.RawMessage
				if err := json.Unmarshal(response.Msg.GetContent(), &rows); err != nil {
					t.Fatal(err)
				}
				count += len(rows)
			}
			if response.Msg.GetNextPageToken() == "" {
				break
			}
			request.PageToken = response.Msg.GetNextPageToken()
		}
		if count != 61 || pages < 2 {
			t.Fatalf("byte budget skipped rows or failed to split: count=%d pages=%d", count, pages)
		}
	}
}

func TestInventoryNestedMetadataPageBudget(t *testing.T) {
	f := newEnrolled(t, 0)
	metadata := &adminv1.DeviceMetadata{Attributes: make(map[string]*adminv1.AttributeValue)}
	for i := range 32 {
		key := fmt.Sprintf("attribute_%02d", i)
		defineInventoryAttribute(t, f, key, adminv1.AttributeType_ATTRIBUTE_TYPE_STRING)
		metadata.Attributes[key] = &adminv1.AttributeValue{Value: &adminv1.AttributeValue_StringValue{StringValue: strings.Repeat("\x01", 1024)}}
		metadata.Labels = append(metadata.Labels, fmt.Sprintf("label-%02d", i))
	}
	setInventoryMetadata(t, f, f.deviceID, metadata)
	for range 15 {
		if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices(id,state,enrolled_at,metadata)
			SELECT $1,'pending',enrolled_at,metadata FROM devices WHERE id=$2`, uuid.New(), f.principal.DeviceID); err != nil {
			t.Fatal(err)
		}
	}
	for _, jsonEncoding := range []bool{false, true} {
		client := inventoryAdminClient(t, f, f.ownerCtx, jsonEncoding)
		request := &adminv1.ListDevicesRequest{PageSize: 200}
		count, pages := 0, 0
		for {
			pages++
			if pages > 16 {
				t.Fatal("nested metadata pagination did not terminate")
			}
			response, err := client.ListDevices(f.ctx, connect.NewRequest(request))
			if err != nil {
				t.Fatal(err)
			}
			assertInventoryPageFits(t, response.Msg)
			for _, item := range response.Msg.Devices {
				if !proto.Equal(item.GetMetadata(), metadata) {
					t.Fatal("nested metadata changed during pagination")
				}
			}
			count += len(response.Msg.Devices)
			if response.Msg.NextPageToken == "" {
				break
			}
			request.PageToken = response.Msg.NextPageToken
		}
		if count != 16 || pages < 2 {
			t.Fatalf("nested page count=%d rows=%d", pages, count)
		}
	}
}
