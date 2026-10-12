//go:build integration

package device

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

func deviceProjectionPage(t *testing.T, svc *Service, ctx context.Context, request *adminv1.ListDevicesRequest) *adminv1.ListDevicesResponse {
	t.Helper()
	response, err := svc.ListDevices(ctx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	assertInventoryPageFits(t, response.Msg)
	return response.Msg
}

func TestListDevicesCurrentHeadComplianceProjection(t *testing.T) {
	f := newDispatchFixture(t)
	assignment := f.assign(t, nil)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	var now time.Time
	if err := f.pool.QueryRow(t.Context(), "SELECT CURRENT_TIMESTAMP").Scan(&now); err != nil {
		t.Fatal(err)
	}
	recent, older, stale := now.Add(-time.Minute), now.Add(-2*time.Minute), now.Add(-time.Hour)
	deviceID := f.principal.DeviceID.String()
	exec("UPDATE devices SET hostname='projection-visible',enrolled_at=$2 WHERE id=$1", deviceID, now.Add(-time.Minute))
	unassigned, hidden := uuid.NewString(), uuid.NewString()
	exec(`INSERT INTO devices(id,state,enrolled_at,hostname) VALUES
($1,'active',$3,'projection-unassigned'),($2,'active',$4,'projection-hidden')`, unassigned, hidden, now.Add(-2*time.Minute), now.Add(-time.Second))

	// Retained assignments, including heads in an earlier enrollment generation,
	// must not contaminate either the worst compliance or its verification time.
	copyAssignment := func(device, generation string, head bool) {
		t.Helper()
		id := uuid.NewString()
		exec(`INSERT INTO resource_assignments(id,device_id,generation_id,request_id,request_digest,actor_id,authorization_version,revision_id,document,assigned_at)
SELECT $1,$2,$3,$4,request_digest,actor_id,authorization_version,revision_id,document,assigned_at
FROM resource_assignments WHERE id=$5`, id, device, generation, uuid.NewString(), assignment.GetAssignmentId())
		exec(`INSERT INTO resource_assignment_resources(assignment_id,resource_id,resource_kind,canonical_key,position,document,disposition,last_verified_at)
SELECT $1,resource_id,resource_kind,canonical_key,position,document,4,$3 FROM resource_assignment_resources WHERE assignment_id=$2`, id, assignment.GetAssignmentId(), stale.Add(-time.Hour))
		if head {
			exec("INSERT INTO resource_assignment_heads(generation_id,assignment_id) VALUES($1,$2)", generation, id)
		}
	}
	copyAssignment(deviceID, f.principal.GenerationID.String(), false)
	oldGeneration, hiddenGeneration := uuid.NewString(), uuid.NewString()
	exec(`INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES
($1,$2,'revoked',$5),($3,$4,'active',$5)`, oldGeneration, deviceID, hiddenGeneration, hidden, now)
	copyAssignment(deviceID, oldGeneration, true)
	exec("UPDATE devices SET current_generation_id=$2 WHERE id=$1", hidden, hiddenGeneration)
	copyAssignment(hidden, hiddenGeneration, true)

	principal := scopedReader(f.actor, &authv1.DeviceScope{DeviceIds: []string{deviceID, unassigned}})
	principal.Bindings = append(principal.Bindings, &authv1.RoleBinding{Permissions: []string{string(identity.PermissionReadAudit)}})
	ctx := identity.WithPrincipal(t.Context(), principal)
	request := &adminv1.ListDevicesRequest{PageSize: 2, Filter: &adminv1.DeviceFilter{NamePrefix: "projection-"}}
	assertProjection := func(t *testing.T, want adminv1.DeviceCompliance, verified *time.Time) {
		t.Helper()
		page := deviceProjectionPage(t, f.service, ctx, request)
		if len(page.GetDevices()) != 2 || page.GetNextPageToken() != "" {
			t.Fatalf("hidden device consumed scoped page capacity: %v", page)
		}
		got := page.GetDevices()[0]
		if got.GetId() != deviceID || got.GetCompliance() != want {
			t.Fatalf("current-head worst compliance: got=%v want=%v", got, want)
		}
		if verified == nil {
			if got.GetLastVerifiedAt() != nil {
				t.Fatalf("partially verified resources acquired an all-resource timestamp: %v", got)
			}
		} else if got.GetLastVerifiedAt() == nil || !got.GetLastVerifiedAt().AsTime().Equal(*verified) {
			t.Fatalf("verification time must be the oldest proof across current resources: got=%v want=%v", got.GetLastVerifiedAt(), verified)
		}
		other := page.GetDevices()[1]
		if other.GetId() != unassigned || other.GetCompliance() != adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNASSIGNED || other.GetLastVerifiedAt() != nil {
			t.Fatalf("device without a head acquired compliance evidence: %v", other)
		}
	}
	for _, test := range []struct {
		name     string
		update   string
		blocked  string
		want     adminv1.DeviceCompliance
		verified *time.Time
	}{
		{"unknown", "disposition=1,last_verified_at=NULL,drift_remediated=false", "", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNKNOWN, nil},
		{"compliant_oldest_proof", "disposition=3,last_verified_at=CASE WHEN position=0 THEN $2::timestamptz ELSE $3::timestamptz END,drift_remediated=false", "", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_COMPLIANT, &older},
		{"remediated_over_compliant", "disposition=3,last_verified_at=CASE WHEN position=0 THEN $2::timestamptz ELSE $3::timestamptz END,drift_remediated=(position=1)", "", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_DRIFT_REMEDIATED, &older},
		{"stale_over_remediated", "disposition=3,last_verified_at=CASE WHEN position=0 THEN $4::timestamptz ELSE $3::timestamptz END,drift_remediated=true", "", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_STALE, &stale},
		{"unknown_over_stale", "disposition=3,last_verified_at=CASE WHEN position=0 THEN $4::timestamptz ELSE NULL END,drift_remediated=false", "", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNKNOWN, nil},
		{"attention_over_unknown", "disposition=CASE WHEN position=0 THEN 3 ELSE 4 END,last_verified_at=CASE WHEN position=0 THEN NULL ELSE $3::timestamptz END,drift_remediated=false", "", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION, nil},
		{"blocked_assignment", "disposition=3,last_verified_at=CASE WHEN position=0 THEN $2::timestamptz ELSE $3::timestamptz END,drift_remediated=false", "authority_changed", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION, &older},
		{"blocked_disposition", "disposition=CASE WHEN position=0 THEN 3 ELSE 5 END,last_verified_at=CASE WHEN position=0 THEN $2::timestamptz ELSE $3::timestamptz END,drift_remediated=false", "", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION, &older},
		{"dependency_attention", "disposition=CASE WHEN position=0 THEN 4 ELSE 1 END,last_verified_at=NULL,drift_remediated=false", "", adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			exec("UPDATE resource_assignments SET blocked_reason=$2 WHERE id=$1", assignment.GetAssignmentId(), test.blocked)
			// The CTE types every time parameter, including those unused by a case.
			exec("WITH times AS (SELECT $2::timestamptz,$3::timestamptz,$4::timestamptz) UPDATE resource_assignment_resources SET "+test.update+" WHERE assignment_id=$1", assignment.GetAssignmentId(), recent, older, stale)
			assertProjection(t, test.want, test.verified)
		})
	}
	all := deviceProjectionPage(t, f.service, f.adminCtx, &adminv1.ListDevicesRequest{PageSize: 10, Filter: request.Filter})
	if len(all.GetDevices()) != 3 || all.GetDevices()[0].GetId() != hidden || all.GetDevices()[0].GetCompliance() != adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION {
		t.Fatalf("unrestricted list lost hidden current-head resources: %v", all)
	}

	exec("UPDATE resource_assignment_resources SET disposition=1,last_verified_at=NULL,drift_remediated=false WHERE assignment_id=$1", assignment.GetAssignmentId())
	work := f.work(t)
	f.start(t, work)
	assertProjection(t, adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION, nil)
	clear := f.assignmentRequest(proto.String(assignment.GetAssignmentId()))
	clear.Target, clear.Clear = nil, true
	if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clear)); err != nil {
		t.Fatal(err)
	}
	assertProjection(t, adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNASSIGNED, nil)
}

func TestListDevicesNamePrefixIsLiteralAndCaseSensitive(t *testing.T) {
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	var visible []string
	for _, hostname := range []string{"node%one", "node_one", `node\one`, "nodeXone", "Node%one", "équipe-one", "xnode%one", "node'one"} {
		id := uuid.NewString()
		visible = append(visible, id)
		fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id) VALUES($1,'active',$2,$3,'prefix-fixture')`, id, f.now.Add(-time.Minute), hostname)
	}
	hidden := uuid.NewString()
	fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id) VALUES($1,'active',$2,'node%hidden','prefix-fixture')`, hidden, f.now)
	ctx := identity.WithPrincipal(f.ctx, scopedReader(owner, &authv1.DeviceScope{DeviceIds: visible}))
	for _, test := range []struct {
		prefix string
		want   []string
	}{
		{"node%", []string{"node%one"}},
		{"node_", []string{"node_one"}},
		{`node\`, []string{`node\one`}},
		{"Node%", []string{"Node%one"}},
		{"équipe", []string{"équipe-one"}},
		{"node'", []string{"node'one"}},
		{"one", nil},
		{"node%hidden", nil},
		{"", []string{"node%one", "node_one", `node\one`, "nodeXone", "Node%one", "équipe-one", "xnode%one", "node'one"}},
	} {
		t.Run(test.prefix, func(t *testing.T) {
			page := deviceProjectionPage(t, f.svc, ctx, &adminv1.ListDevicesRequest{PageSize: 200, Filter: &adminv1.DeviceFilter{OsId: "prefix-fixture", NamePrefix: test.prefix}})
			var got []string
			for _, row := range page.GetDevices() {
				got = append(got, row.GetHostname())
				if row.GetCompliance() != adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNASSIGNED || row.GetLastVerifiedAt() != nil {
					t.Fatalf("unassigned name match acquired compliance evidence: %v", row)
				}
			}
			want := slices.Clone(test.want)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) || page.GetNextPageToken() != "" {
				t.Fatalf("literal prefix %q: got=%q want=%q next=%q", test.prefix, got, want, page.GetNextPageToken())
			}
		})
	}
	all := deviceProjectionPage(t, f.svc, f.ownerCtx, &adminv1.ListDevicesRequest{Filter: &adminv1.DeviceFilter{OsId: "prefix-fixture", NamePrefix: "node%"}})
	if len(all.GetDevices()) != 2 || all.GetDevices()[0].GetId() != hidden {
		t.Fatalf("unrestricted prefix did not include the otherwise hidden match: %v", all)
	}
	for _, prefix := range []string{"node\x00", strings.Repeat("n", 4097)} {
		if _, err := f.svc.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{Filter: &adminv1.DeviceFilter{NamePrefix: prefix}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("invalid name prefix admitted: %v", err)
		}
	}
}

func TestListDevicesPrefixCursorCutoffAndPreviousReplay(t *testing.T) {
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	prefix := `page%_\`
	var want []string
	for i := range 8 {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)
		fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id) VALUES($1,'active',$2,$3,'projection-pagination')`, id, f.now.Add(-time.Minute), fmt.Sprintf("%s%d", prefix, i))
		if i < 5 {
			want = append(want, id)
			fleetSummaryExec(t, f, "INSERT INTO device_labels(device_id,label) VALUES($1,'visible')", id)
		}
	}
	slices.Reverse(want)
	// This newer, authorized row matches a wildcard interpretation, not a literal
	// prefix. The three highest equal-time UUIDs above are unauthorized matches.
	decoy := uuid.NewString()
	fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id) VALUES($1,'active',$2,'pageXYZ','projection-pagination')`, decoy, f.now)
	fleetSummaryExec(t, f, "INSERT INTO device_labels(device_id,label) VALUES($1,'visible')", decoy)
	principal := scopedReader(owner, &authv1.DeviceScope{Labels: []string{"visible"}})
	principal.Bindings = append(principal.Bindings, &authv1.RoleBinding{Permissions: []string{string(identity.PermissionReadAudit)}})
	ctx := identity.WithPrincipal(f.ctx, principal)
	filter := &adminv1.DeviceFilter{OsId: "projection-pagination", NamePrefix: prefix}
	request := &adminv1.ListDevicesRequest{PageSize: 2, Filter: filter}
	first := deviceProjectionPage(t, f.svc, ctx, request)
	if len(first.GetDevices()) != 2 || first.GetNextPageToken() == "" || first.GetPageToken() == "" || first.GetCursorExpiresAt() == nil {
		t.Fatalf("scope/prefix filtering did not precede the page limit: %v", first)
	}

	// Both subsequent pages and Previous must retain the original enrollment
	// cutoff, even though a fresh search is allowed to show the later device.
	late := uuid.NewString()
	fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id) VALUES($1,'active',$2,$3,'projection-pagination')`, late, f.now.Add(time.Second), prefix+"later")
	fleetSummaryExec(t, f, "INSERT INTO device_labels(device_id,label) VALUES($1,'visible')", late)
	f.now = f.now.Add(2 * time.Second)
	pages := []*adminv1.ListDevicesResponse{first}
	for pages[len(pages)-1].GetNextPageToken() != "" {
		if len(pages) >= 3 {
			t.Fatal("prefix pagination failed to terminate within the authorized population")
		}
		request.PageToken = pages[len(pages)-1].GetNextPageToken()
		page := deviceProjectionPage(t, f.svc, ctx, request)
		if page.GetPageToken() != request.PageToken || !proto.Equal(page.GetCursorExpiresAt(), first.GetCursorExpiresAt()) {
			t.Fatalf("continuation changed its replay token or fixed expiry: %v", page)
		}
		pages = append(pages, page)
	}
	var got []string
	for i, page := range pages {
		count := 2
		if i == 2 {
			count = 1
		}
		if len(page.GetDevices()) != count {
			t.Fatalf("hidden/nonmatching rows consumed page %d capacity: %v", i, page)
		}
		for _, row := range page.GetDevices() {
			got = append(got, row.GetId())
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("prefix keyset skipped, repeated, or admitted a post-cutoff device: got=%v want=%v", got, want)
	}
	for i := len(pages) - 1; i >= 0; i-- {
		request.PageToken = pages[i].GetPageToken()
		replay := deviceProjectionPage(t, f.svc, ctx, request)
		if !proto.Equal(replay, pages[i]) {
			t.Fatalf("Previous replay changed page %d, cutoff, or expiry: got=%v want=%v", i, replay, pages[i])
		}
	}
	for _, token := range []string{first.GetPageToken(), first.GetNextPageToken()} {
		for _, changedPrefix := range []string{"", prefix + "changed"} {
			changed := &adminv1.ListDevicesRequest{PageSize: 2, PageToken: token, Filter: proto.CloneOf(filter)}
			changed.Filter.NamePrefix = changedPrefix
			if _, err := f.svc.ListDevices(ctx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("saved cursor accepted changed prefix %q: %v", changedPrefix, err)
			}
		}
	}
	request.PageToken = first.GetPageToken()
	if _, err := f.svc.ListDevices(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("saved prefix cursor accepted changed scope: %v", err)
	}
	revokedScope := scopedReader(owner, &authv1.DeviceScope{Labels: []string{"no-longer-visible"}})
	if _, err := f.svc.ListDevices(identity.WithPrincipal(f.ctx, revokedScope), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("Previous replay bypassed removed device scope: %v", err)
	}
	fresh := deviceProjectionPage(t, f.svc, ctx, &adminv1.ListDevicesRequest{PageSize: 2, Filter: filter})
	if len(fresh.GetDevices()) != 2 || fresh.GetDevices()[0].GetId() != late {
		t.Fatalf("fresh prefix search failed to include a later enrollment: %v", fresh)
	}
	f.now = first.GetCursorExpiresAt().AsTime()
	if _, err := f.svc.ListDevices(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("Previous replay extended the fixed cursor lifetime: %v", err)
	}
}

func TestListDevicesHostnameSearchIsCaseInsensitiveLiteralSubstring(t *testing.T) {
	f := newEnrolled(t, 0)
	for _, hostname := range []string{"ubuntu-ws-01", "UBUNTU-SRV", "fedora-ws-03", "node%x", "nodeyx"} {
		fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id) VALUES($1,'active',$2,$3,'search-fixture')`, uuid.NewString(), f.now.Add(-time.Minute), hostname)
	}
	for _, test := range []struct {
		search string
		want   []string
	}{
		{"ws", []string{"fedora-ws-03", "ubuntu-ws-01"}},
		{"UBUNTU", []string{"UBUNTU-SRV", "ubuntu-ws-01"}},
		{"Srv", []string{"UBUNTU-SRV"}},
		{"%", []string{"node%x"}},
		{"", []string{"UBUNTU-SRV", "fedora-ws-03", "node%x", "nodeyx", "ubuntu-ws-01"}},
	} {
		page := deviceProjectionPage(t, f.svc, f.ownerCtx, &adminv1.ListDevicesRequest{PageSize: 200, HostnameSearch: test.search, Filter: &adminv1.DeviceFilter{OsId: "search-fixture"}})
		var got []string
		for _, row := range page.GetDevices() {
			got = append(got, row.GetHostname())
		}
		slices.Sort(got)
		if !slices.Equal(got, test.want) {
			t.Fatalf("hostname search %q: got=%q want=%q", test.search, got, test.want)
		}
	}
	if _, err := f.svc.ListDevices(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicesRequest{HostnameSearch: strings.Repeat("a", 254)})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("oversized hostname search admitted: %v", err)
	}
}

func TestListDevicesSortsAcrossPagesWithMissingValuesLast(t *testing.T) {
	f := newEnrolled(t, 0)
	type fixture struct {
		hostname, osID, osVersion string
		seen                      time.Duration // 0: never seen
	}
	devices := []fixture{
		{"bravo", "ubuntu", "24.04", 3 * time.Minute},
		{"Alpha", "fedora", "44", 5 * time.Minute},
		{"charlie", "Debian", "12", 1 * time.Minute},
		{"", "", "", 0}, // pending: no hostname, OS or contact
		{"delta", "ubuntu", "22.04", 0},
		{"echo", "rhel", "9.4", 2 * time.Minute},
	}
	for i, d := range devices {
		var seen any
		if d.seen != 0 {
			seen = f.now.Add(-d.seen)
		}
		fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,hostname,os_id,os_version,last_seen_at) VALUES($1,'active',$2,$3,$4,$5,$6)`,
			uuid.NewString(), f.now.Add(-time.Hour+time.Duration(i)*time.Second), d.hostname, d.osID, d.osVersion, seen)
	}
	filter := &adminv1.DeviceFilter{}
	all := func(sort *adminv1.DeviceSort) []string {
		t.Helper()
		request := &adminv1.ListDevicesRequest{PageSize: 2, Sort: sort, Filter: filter}
		var got []string
		for pages := 0; ; pages++ {
			if pages > 6 {
				t.Fatal("sorted pagination did not terminate")
			}
			page := deviceProjectionPage(t, f.svc, f.ownerCtx, request)
			for _, row := range page.GetDevices() {
				if row.GetId() == f.deviceID {
					continue // the fixture's own enrolled device
				}
				got = append(got, row.GetHostname())
			}
			if page.GetNextPageToken() == "" {
				return got
			}
			request.PageToken = page.GetNextPageToken()
		}
	}
	field := func(field adminv1.DeviceSortField, descending bool) *adminv1.DeviceSort {
		return &adminv1.DeviceSort{Field: field, Descending: descending}
	}
	for _, test := range []struct {
		name string
		sort *adminv1.DeviceSort
		want []string
	}{
		{"hostname ascending", field(adminv1.DeviceSortField_DEVICE_SORT_FIELD_HOSTNAME, false), []string{"Alpha", "bravo", "charlie", "delta", "echo", ""}},
		{"hostname descending", field(adminv1.DeviceSortField_DEVICE_SORT_FIELD_HOSTNAME, true), []string{"echo", "delta", "charlie", "bravo", "Alpha", ""}},
		{"last contact ascending", field(adminv1.DeviceSortField_DEVICE_SORT_FIELD_LAST_SEEN, false), []string{"Alpha", "bravo", "echo", "charlie"}},
		{"last contact descending", field(adminv1.DeviceSortField_DEVICE_SORT_FIELD_LAST_SEEN, true), []string{"charlie", "echo", "bravo", "Alpha"}},
		{"operating system ascending", field(adminv1.DeviceSortField_DEVICE_SORT_FIELD_OPERATING_SYSTEM, false), []string{"charlie", "Alpha", "echo", "delta", "bravo", ""}},
		{"newest enrollment default", nil, []string{"echo", "delta", "", "charlie", "Alpha", "bravo"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := all(test.sort)
			if strings.HasPrefix(test.name, "last contact") {
				// Never-seen rows (pending and delta) follow, in id order.
				if len(got) != 6 || !slices.Equal(got[:4], test.want) || !slices.ContainsFunc(got[4:], func(h string) bool { return h == "" }) || !slices.Contains(got[4:], "delta") {
					t.Fatalf("got=%q want %q then never-seen", got, test.want)
				}
				return
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("got=%q want=%q", got, test.want)
			}
		})
	}
	first := deviceProjectionPage(t, f.svc, f.ownerCtx, &adminv1.ListDevicesRequest{PageSize: 2, Filter: filter, Sort: field(adminv1.DeviceSortField_DEVICE_SORT_FIELD_HOSTNAME, false)})
	for _, changed := range []*adminv1.ListDevicesRequest{
		{PageSize: 2, Filter: filter, PageToken: first.GetNextPageToken(), Sort: field(adminv1.DeviceSortField_DEVICE_SORT_FIELD_HOSTNAME, true)},
		{PageSize: 2, Filter: filter, PageToken: first.GetNextPageToken(), Sort: field(adminv1.DeviceSortField_DEVICE_SORT_FIELD_HOSTNAME, false), HostnameSearch: "a"},
	} {
		if _, err := f.svc.ListDevices(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("cursor accepted a changed order or search: %v", err)
		}
	}
}
