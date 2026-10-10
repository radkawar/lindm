//go:build integration

package device

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/admin/v1/adminv1connect"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/identity"
)

func inventoryAdminClient(t *testing.T, f *enrolledFixture, actor context.Context, json bool) adminv1connect.AdminServiceClient {
	t.Helper()
	principal, ok := identity.PrincipalFromContext(actor)
	if !ok {
		t.Fatal("missing admin test principal")
	}
	path, handler := f.svc.AdminHandler()
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), principal)))
	}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	var options []connect.ClientOption
	if json {
		options = append(options, connect.WithProtoJSON())
	}
	return adminv1connect.NewAdminServiceClient(server.Client(), server.URL, options...)
}

func assertInventoryPageFits(t *testing.T, message proto.Message) {
	t.Helper()
	encoded, err := protojson.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if binarySize := proto.Size(message); binarySize > maxMessageBytes || len(encoded) > maxMessageBytes {
		t.Fatalf("response exceeds handler limit: protobuf=%d JSON=%d limit=%d", binarySize, len(encoded), maxMessageBytes)
	}
}

func TestListDevicePackagesHandlerBoundsEncodedPages(t *testing.T) {
	for _, shape := range []struct {
		name  string
		value string
	}{
		{name: "unicode", value: strings.Repeat("\U0001f680", 2048)},
		{name: "json_escape", value: strings.Repeat("\x01", 2048)},
	} {
		for _, json := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", shape.name, json), func(t *testing.T) {
				f := newEnrolled(t, 0)
				client := inventoryAdminClient(t, f, f.ownerCtx, json)
				packages := make([]*inventoryv1.Package, 240)
				var expected []*adminv1.DevicePackage
				for i := range packages {
					manager := "apt"
					if i%6 == 0 {
						manager = "rpm"
					}
					packages[i] = &inventoryv1.Package{Name: fmt.Sprintf("package-%03d", i), Version: shape.value, Architecture: "amd64", Manager: manager}
					if manager == "apt" {
						expected = append(expected, &adminv1.DevicePackage{Position: uint32(i), Name: packages[i].Name, Version: shape.value, Architecture: "amd64", Manager: manager})
					}
				}
				var batches [][]byte
				for i := 0; i < len(packages); i += 40 {
					batches = append(batches, packageBatch(t, packages[i:i+40]...))
				}
				manifest := snapshotManifest(t, f.generation, 1, f.now, batches)
				if _, err := f.begin(t, manifest, 1); err != nil {
					t.Fatal(err)
				}
				for i, batch := range batches {
					if _, err := f.put(t, manifest.GetSnapshotId(), uint32(i), batch, 1); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := f.commit(t, manifest, 1); err != nil {
					t.Fatal(err)
				}
				request := &adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 200, Manager: "apt"}
				var first *adminv1.ListDevicePackagesResponse
				seen := 0
				for pages := 0; ; pages++ {
					if pages > len(expected) {
						t.Fatal("package pagination did not terminate")
					}
					response, err := client.ListDevicePackages(f.ctx, connect.NewRequest(request))
					if err != nil {
						t.Fatalf("handler rejected valid package page: %v", err)
					}
					page := response.Msg
					assertInventoryPageFits(t, page)
					if page.SnapshotId != manifest.GetSnapshotId() || page.Sequence != 1 || len(page.Packages) == 0 || len(page.Packages) > 200 {
						t.Fatalf("wrong snapshot or page length: snapshot=%s sequence=%d count=%d", page.SnapshotId, page.Sequence, len(page.Packages))
					}
					if first == nil {
						first = page
						if page.NextPageToken == "" {
							t.Fatal("oversized logical page has no continuation")
						}
						f.now = f.now.Add(snapshotAttemptInterval)
						f.publishPackages(t, 2, "replacement")
					}
					if !proto.Equal(page.CursorExpiresAt, first.CursorExpiresAt) {
						t.Fatal("continuation extended the cursor lifetime")
					}
					for _, item := range page.Packages {
						if seen >= len(expected) || !proto.Equal(item, expected[seen]) {
							t.Fatalf("package pagination skipped, duplicated, or changed row %d at position %d", seen, item.Position)
						}
						seen++
					}
					if page.NextPageToken == "" {
						break
					}
					_, position, err := decodePackagePage(page.NextPageToken)
					if err != nil || position != page.Packages[len(page.Packages)-1].Position+1 {
						t.Fatalf("continuation did not follow last returned position: %d (%v)", position, err)
					}
					request = &adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 200, PageToken: page.NextPageToken, Manager: "rpm", NamePrefix: "replacement"}
				}
				if seen != len(expected) {
					t.Fatalf("returned %d packages, want %d", seen, len(expected))
				}
				replayed, err := client.ListDevicePackages(f.ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 200, PageToken: first.PageToken}))
				if err != nil || !proto.Equal(replayed.Msg, first) {
					t.Fatalf("first-page replay changed after publication: %v", err)
				}
			})
		}
	}
}

func TestListDevicesHandlerBoundsEncodedPages(t *testing.T) {
	for _, shape := range []struct {
		name     string
		value    string
		pageSize uint32
	}{
		{name: "ascii_max_page", value: strings.Repeat("h", 4096), pageSize: 200},
		{name: "unicode_default_page", value: strings.Repeat("\U0001f680", 4096)},
		{name: "json_escape_default_page", value: strings.Repeat("\x01", 4096)},
	} {
		for _, json := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", shape.name, json), func(t *testing.T) {
				f := newEnrolled(t, 0)
				report := hostObservation(f.generation, 1, shape.value)
				report.Observation.OsId.Value = shape.value
				report.Observation.OsVersion.Value = shape.value
				report.Observation.Architecture.Value = shape.value
				if err := f.svc.rules.Validate(report); err != nil {
					t.Fatalf("host fixture is not admitted by the schema: %v", err)
				}
				if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
					t.Fatal(err)
				}
				// Copy an admitted projection to a larger fleet. Equal enrollment
				// timestamps exercise the UUID component of the keyset cursor.
				for range 200 {
					if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices (id, state, enrolled_at, hostname, os_id, os_version, architecture)
						SELECT $1, 'pending', enrolled_at, hostname, os_id, os_version, architecture FROM devices WHERE id = $2`, uuid.New(), f.principal.DeviceID); err != nil {
						t.Fatal(err)
					}
				}
				rows, err := f.conn.Query(f.ctx, `SELECT id::text FROM devices ORDER BY enrolled_at DESC, id DESC`)
				if err != nil {
					t.Fatal(err)
				}
				var expected []string
				for rows.Next() {
					var id string
					if err := rows.Scan(&id); err != nil {
						t.Fatal(err)
					}
					expected = append(expected, id)
				}
				rows.Close()
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				client := inventoryAdminClient(t, f, f.ownerCtx, json)
				request := &adminv1.ListDevicesRequest{PageSize: shape.pageSize}
				seen := 0
				var first *adminv1.ListDevicesResponse
				for pages := 0; ; pages++ {
					if pages > len(expected) {
						t.Fatal("fleet pagination did not terminate")
					}
					response, err := client.ListDevices(f.ctx, connect.NewRequest(request))
					if err != nil {
						t.Fatalf("handler rejected valid fleet page: %v", err)
					}
					page := response.Msg
					assertInventoryPageFits(t, page)
					if page.GetPageToken() == "" || page.GetCursorExpiresAt() == nil || (request.GetPageToken() != "" && page.GetPageToken() != request.GetPageToken()) {
						t.Fatal("fleet page did not preserve its opaque replay cursor")
					}
					if first == nil {
						first = page
					} else if !proto.Equal(page.GetCursorExpiresAt(), first.GetCursorExpiresAt()) {
						t.Fatal("fleet continuation extended the cursor lifetime")
					}
					if len(page.Devices) == 0 || int32(len(page.Devices)) > pageLimit(shape.pageSize) {
						t.Fatalf("invalid fleet page length %d", len(page.Devices))
					}
					for _, item := range page.Devices {
						if seen >= len(expected) || item.Id != expected[seen] {
							t.Fatalf("fleet pagination skipped or repeated device %d: %s", seen, item.Id)
						}
						if item.Hostname != shape.value || item.OsId != shape.value || item.OsVersion != shape.value || item.Architecture != shape.value {
							t.Fatal("fleet pagination truncated an admitted host field")
						}
						seen++
					}
					if page.NextPageToken == "" {
						break
					}
					if page.NextPageToken == page.GetPageToken() {
						t.Fatal("fleet continuation did not advance the opaque cursor")
					}
					request.PageToken = page.NextPageToken
				}
				if seen != len(expected) {
					t.Fatalf("returned %d devices, want %d", seen, len(expected))
				}
			})
		}
	}
}
