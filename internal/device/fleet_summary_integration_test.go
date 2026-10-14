// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"lindm/internal/device/directory"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/advisory"
	"lindm/internal/identity"
)

func fleetSummary(t *testing.T, svc *Service, ctx context.Context, limit uint32) *adminv1.GetFleetSummaryResponse {
	t.Helper()
	response, err := svc.GetFleetSummary(ctx, connect.NewRequest(&adminv1.GetFleetSummaryRequest{RecentActionLimit: limit}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetObservedAt() == nil || response.Msg.GetObservedAt().CheckValid() != nil {
		t.Fatal("summary did not identify its database observation time")
	}
	return response.Msg
}

func fleetSummaryExec(t *testing.T, f *enrolledFixture, query string, args ...any) {
	t.Helper()
	if _, err := f.conn.Exec(f.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestFleetSummaryCountsAllAuthorizedDevices(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	// The enrolled device is an explicitly unknown, pending device. More than
	// one ListDevices page of active devices must still contribute to totals.
	fleetSummaryExec(t, f, "UPDATE devices SET state='pending',os_id='',os_version='',last_seen_at=NULL WHERE id=$1", f.deviceID)
	visible := []string{f.deviceID}
	for range 205 {
		id := uuid.NewString()
		visible = append(visible, id)
		fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,os_id,os_version,last_seen_at)
 VALUES($1,'active',CURRENT_TIMESTAMP,'ubuntu','22.04',CURRENT_TIMESTAMP-interval '1 hour')`, id)
	}
	active, recovery, revoked := uuid.NewString(), uuid.NewString(), uuid.NewString()
	visible = append(visible, active, recovery, revoked)
	fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,os_id,os_version,last_seen_at)
 VALUES($1,'active',CURRENT_TIMESTAMP,'ubuntu','24.04',CURRENT_TIMESTAMP-interval '48 hours'),
 ($2,'recovery_hold',CURRENT_TIMESTAMP,'fedora','44',CURRENT_TIMESTAMP-interval '1 hour')`, active, recovery)
	fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,os_id,os_version,revoked_at,revoked_by,revoke_reason)
 VALUES($1,'revoked',CURRENT_TIMESTAMP,'fedora','44',CURRENT_TIMESTAMP,$2,'summary fixture retirement')`, revoked, owner.ID)
	hidden := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for _, id := range hidden {
		fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,os_id,os_version,last_seen_at)
 VALUES($1,'active',CURRENT_TIMESTAMP,'hidden-os','hidden-version',CURRENT_TIMESTAMP-interval '48 hours')`, id)
	}
	group := uuid.NewString()
	fleetSummaryExec(t, f, "INSERT INTO device_groups(id,name) VALUES($1,'summary scope')", group)
	for _, id := range append(slices.Clone(visible), hidden[0], hidden[2]) {
		fleetSummaryExec(t, f, "INSERT INTO device_group_memberships(group_id,device_id) VALUES($1,$2)", group, id)
	}
	for _, id := range append(slices.Clone(visible), hidden...) {
		fleetSummaryExec(t, f, "INSERT INTO device_labels(device_id,label) VALUES($1,'site-a')", id)
		if id != hidden[2] {
			fleetSummaryExec(t, f, "INSERT INTO device_labels(device_id,label) VALUES($1,'workstation')", id)
		}
	}
	principal := scopedReader(owner, &authv1.DeviceScope{
		DeviceIds: append(slices.Clone(visible), hidden[1], hidden[2]),
		Labels:    []string{"site-a", "workstation"},
		GroupIds:  []string{group},
	})
	// A global grant for another permission cannot broaden the fleet scope.
	principal.Bindings = append(principal.Bindings, &authv1.RoleBinding{Permissions: []string{string(identity.PermissionReadAudit)}})
	ctx := identity.WithPrincipal(f.ctx, principal)
	got := fleetSummary(t, f.svc, ctx, 0)
	wantLifecycle := &adminv1.FleetLifecycleSummary{TotalDevices: 209, PendingDevices: 1, ActiveDevices: 206, RevokedDevices: 1, RecoveryHoldDevices: 1}
	wantContact := &adminv1.FleetContactSummary{RecentDevices: 206, StaleDevices: 1, UnknownDevices: 2, StaleAfterSeconds: 86400}
	wantOS := &adminv1.FleetOSSummary{Groups: []*adminv1.FleetOSCount{
		{OsId: "ubuntu", OsVersion: "22.04", Devices: 205},
		{OsId: "fedora", OsVersion: "44", Devices: 2},
		{Devices: 1},
		{OsId: "ubuntu", OsVersion: "24.04", Devices: 1},
	}}
	if !proto.Equal(got.GetLifecycle(), wantLifecycle) || !proto.Equal(got.GetContact(), wantContact) || !proto.Equal(got.GetOperatingSystems(), wantOS) {
		t.Fatalf("scoped counts included hidden devices or sampled a page: %v", got)
	}
	if got.GetResourceCompliance().GetUnassignedDevices() != 209 || got.GetResourceCompliance().GetTotalResources() != 0 {
		t.Fatalf("unassigned devices were sampled or called compliant: %v", got.GetResourceCompliance())
	}
	all := fleetSummary(t, f.svc, f.ownerCtx, 0)
	wantLifecycle.TotalDevices += 3
	wantLifecycle.ActiveDevices += 3
	wantContact.StaleDevices += 3
	if !proto.Equal(all.GetLifecycle(), wantLifecycle) || !proto.Equal(all.GetContact(), wantContact) {
		t.Fatalf("unrestricted totals lost devices: %v", all)
	}
	if all.GetOperatingSystems().GetGroups()[1].GetOsId() != "hidden-os" || all.GetOperatingSystems().GetGroups()[1].GetDevices() != 3 {
		t.Fatalf("unrestricted OS groups lost hidden population: %v", all.GetOperatingSystems())
	}
	// Alternative scopes are ORed, rather than intersected with the first one.
	principal.Bindings[0].Scopes = append(principal.Bindings[0].Scopes, &authv1.DeviceScope{DeviceIds: []string{hidden[0]}})
	if got := fleetSummary(t, f.svc, identity.WithPrincipal(f.ctx, principal), 0); got.GetLifecycle().GetTotalDevices() != 210 {
		t.Fatalf("alternative scope did not add exactly one device: %v", got.GetLifecycle())
	}
	principal = scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}})
	empty := fleetSummary(t, f.svc, identity.WithPrincipal(f.ctx, principal), 0)
	if empty.GetLifecycle().GetTotalDevices() != 0 || len(empty.GetOperatingSystems().GetGroups()) != 0 || empty.GetOperatingSystems().GetOtherDevices() != 0 || empty.GetResourceCompliance().GetUnassignedDevices() != 0 || len(empty.GetRecentActions()) != 0 {
		t.Fatalf("empty authorized population leaked aggregate state: %v", empty)
	}
}

func TestFleetSummaryOSGroupsAreBoundedWithoutLosingCounts(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	fleetSummaryExec(t, f, "UPDATE devices SET os_id='',os_version='' WHERE id=$1", f.deviceID)
	fleetSummaryExec(t, f, "INSERT INTO device_labels(device_id,label) VALUES($1,'visible')", f.deviceID)
	for group := 1; group <= 24; group++ {
		for range group {
			id := uuid.NewString()
			fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,os_id,os_version) VALUES($1,'active',CURRENT_TIMESTAMP,$2,'1')`, id, fmt.Sprintf("os-%02d", group))
			fleetSummaryExec(t, f, "INSERT INTO device_labels(device_id,label) VALUES($1,'visible')", id)
		}
	}
	// This would rank first if authorization were applied after the group limit.
	fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at,os_id,os_version)
 SELECT gen_random_uuid(),'active',CURRENT_TIMESTAMP,'hidden-leading-os','1' FROM generate_series(1,400)`)
	ctx := identity.WithPrincipal(f.ctx, scopedReader(owner, &authv1.DeviceScope{Labels: []string{"visible"}}))
	got := fleetSummary(t, f.svc, ctx, 0)
	groups := got.GetOperatingSystems().GetGroups()
	if len(groups) != 20 || got.GetOperatingSystems().GetOtherDevices() != 11 || got.GetLifecycle().GetTotalDevices() != 301 {
		t.Fatalf("bounded groups lost exact remainder or scope: %v", got)
	}
	total := got.GetOperatingSystems().GetOtherDevices()
	for i, row := range groups {
		count := 24 - i
		if row.GetOsId() != fmt.Sprintf("os-%02d", count) || row.GetOsVersion() != "1" || row.GetDevices() != uint64(count) {
			t.Fatalf("OS rank %d: %v", i, row)
		}
		total += row.GetDevices()
	}
	if total != got.GetLifecycle().GetTotalDevices() {
		t.Fatalf("OS groups plus remainder=%d, fleet=%d", total, got.GetLifecycle().GetTotalDevices())
	}
}

// Add another enrolled device to the same isolated schema and real service.
func fleetSummaryEnroll(t *testing.T, f *enrolledFixture) *enrolledFixture {
	t.Helper()
	other := &enrolledFixture{ctx: f.ctx, svc: f.svc, conn: f.conn, ownerCtx: f.ownerCtx, now: f.now, key: ed25519Key(t)}
	_, _, _, response := enrollDevice(t, f.ctx, f.svc, f.ownerCtx, other.key)
	other.deviceID = response.Msg.GetDeviceId()
	other.generation = response.Msg.GetEnrollmentGeneration()
	var err error
	other.principal, err = f.svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, response.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, f.ctx, f.svc, other.principal, other.key, 0)
	return other
}

func TestFleetSummaryResourceComplianceMatchesDeviceState(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	assignment := f.assign(t, nil)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Superseded heads must not be counted, even for a visible device.
	oldAssignment := uuid.NewString()
	exec(`INSERT INTO resource_assignments(id,device_id,generation_id,request_id,request_digest,actor_id,authorization_version,revision_id,document,assigned_at)
 SELECT $1,device_id,generation_id,$2,request_digest,actor_id,authorization_version,revision_id,document,assigned_at
 FROM resource_assignments WHERE id=$3`, oldAssignment, uuid.NewString(), assignment.GetAssignmentId())
	exec(`INSERT INTO resource_assignment_resources(assignment_id,resource_id,resource_kind,canonical_key,position,document,disposition)
 SELECT $1,resource_id,resource_kind,canonical_key,position,document,4 FROM resource_assignment_resources WHERE assignment_id=$2`, oldAssignment, assignment.GetAssignmentId())
	hiddenDevice, hiddenGeneration, hiddenAssignment := uuid.NewString(), uuid.NewString(), uuid.NewString()
	exec(`INSERT INTO devices(id,state,enrolled_at) VALUES($1,'active',CURRENT_TIMESTAMP)`, hiddenDevice)
	exec(`INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES($1,$2,'active',CURRENT_TIMESTAMP)`, hiddenGeneration, hiddenDevice)
	exec("UPDATE devices SET current_generation_id=$2 WHERE id=$1", hiddenDevice, hiddenGeneration)
	exec(`INSERT INTO resource_assignments(id,device_id,generation_id,request_id,request_digest,actor_id,authorization_version,revision_id,document,assigned_at)
 SELECT $1,$2,$3,$4,request_digest,actor_id,authorization_version,revision_id,document,assigned_at
 FROM resource_assignments WHERE id=$5`, hiddenAssignment, hiddenDevice, hiddenGeneration, uuid.NewString(), assignment.GetAssignmentId())
	exec(`INSERT INTO resource_assignment_resources(assignment_id,resource_id,resource_kind,canonical_key,position,document,disposition)
 SELECT $1,resource_id,resource_kind,canonical_key,position,document,4 FROM resource_assignment_resources WHERE assignment_id=$2`, hiddenAssignment, assignment.GetAssignmentId())
	exec("INSERT INTO resource_assignment_heads(generation_id,assignment_id) VALUES($1,$2)", hiddenGeneration, hiddenAssignment)
	principal := scopedReader(f.actor, &authv1.DeviceScope{DeviceIds: []string{f.principal.DeviceID.String()}})
	ctx := identity.WithPrincipal(t.Context(), principal)
	for _, test := range []struct {
		name       string
		update     string
		blocked    string
		compliance adminv1.ResourceCompliance
		want       *adminv1.FleetResourceComplianceSummary
	}{
		{"unknown", "disposition=1,last_verified_at=NULL,drift_remediated=false", "", adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_UNKNOWN, &adminv1.FleetResourceComplianceSummary{TotalResources: 2, UnknownResources: 2}},
		{"compliant", "disposition=3,last_verified_at=CURRENT_TIMESTAMP,drift_remediated=false", "", adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT, &adminv1.FleetResourceComplianceSummary{TotalResources: 2, CompliantResources: 2}},
		{"remediated", "disposition=3,last_verified_at=CURRENT_TIMESTAMP,drift_remediated=true", "", adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_DRIFT_REMEDIATED, &adminv1.FleetResourceComplianceSummary{TotalResources: 2, DriftRemediatedResources: 2}},
		{"stale", "disposition=3,last_verified_at=CURRENT_TIMESTAMP-interval '1 hour',drift_remediated=true", "", adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_STALE, &adminv1.FleetResourceComplianceSummary{TotalResources: 2, StaleResources: 2}},
		{"attention", "disposition=4,last_verified_at=NULL,drift_remediated=false", "", adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION, &adminv1.FleetResourceComplianceSummary{TotalResources: 2, AttentionResources: 2}},
		{"blocked", "disposition=1,last_verified_at=CURRENT_TIMESTAMP,drift_remediated=false", "authority_changed", adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION, &adminv1.FleetResourceComplianceSummary{TotalResources: 2, AttentionResources: 2}},
		{"dependency_attention", "disposition=CASE WHEN position=0 THEN 4 ELSE 1 END,last_verified_at=CURRENT_TIMESTAMP,drift_remediated=false", "", adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION, &adminv1.FleetResourceComplianceSummary{TotalResources: 2, AttentionResources: 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			exec("UPDATE resource_assignments SET blocked_reason=$2 WHERE id=$1", assignment.GetAssignmentId(), test.blocked)
			exec("UPDATE resource_assignment_resources SET "+test.update+" WHERE assignment_id=$1", assignment.GetAssignmentId())
			detail, err := f.service.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
			if err != nil {
				t.Fatal(err)
			}
			for _, resource := range detail.Msg.GetResources() {
				if resource.GetCompliance() != test.compliance {
					t.Fatalf("fixture did not establish intended device compliance: %v", resource)
				}
			}
			got := fleetSummary(t, f.service, ctx, 0)
			if !proto.Equal(got.GetResourceCompliance(), test.want) {
				t.Fatalf("fleet differs from current device state or leaked hidden/superseded resources: got=%v want=%v", got.GetResourceCompliance(), test.want)
			}
		})
	}
	// The assignment names its actor by current display name, read at request time.
	detail, err := f.service.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	exec("UPDATE principals SET display_name='Avery Admin' WHERE id=$1", detail.Msg.GetAssignment().GetActorId())
	detail, err = f.service.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	if got := detail.Msg.GetAssignment().GetActorDisplayName(); got != "Avery Admin" {
		t.Fatalf("assignment actor display name: %q", got)
	}
	all := fleetSummary(t, f.service, f.adminCtx, 0)
	if all.GetResourceCompliance().GetTotalResources() != 4 || all.GetResourceCompliance().GetAttentionResources() != 4 {
		t.Fatalf("unrestricted current heads lost resources: %v", all.GetResourceCompliance())
	}
	exec("UPDATE resource_assignment_resources SET disposition=1,last_verified_at=NULL,drift_remediated=false WHERE assignment_id=$1", assignment.GetAssignmentId())
	work := f.work(t)
	f.start(t, work)
	applying := fleetSummary(t, f.service, ctx, 0)
	if !proto.Equal(applying.GetResourceCompliance(), &adminv1.FleetResourceComplianceSummary{TotalResources: 2, AttentionResources: 1, UnknownResources: 1}) {
		t.Fatalf("started remediation was reported unknown or compliant: %v", applying.GetResourceCompliance())
	}
	if actions := applying.GetRecentActions(); len(actions) != 1 || actions[0].GetKind() != "resource" || actions[0].GetStartAuthorizedAt() == nil || actions[0].GetClosedAt() != nil || !actions[0].GetOutcomeUnknown() {
		t.Fatalf("open started service action lost uncertainty: %v", actions)
	}
	// A cleared head leaves immutable resources in history, not compliance.
	clearRequest := f.assignmentRequest(proto.String(assignment.GetAssignmentId()))
	clearRequest.Target = nil
	clearRequest.Clear = true
	if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clearRequest)); err != nil {
		t.Fatal(err)
	}
	cleared := fleetSummary(t, f.service, ctx, 0)
	if !proto.Equal(cleared.GetResourceCompliance(), &adminv1.FleetResourceComplianceSummary{UnassignedDevices: 1}) {
		t.Fatalf("cleared head retained historical compliance: %v", cleared.GetResourceCompliance())
	}
}

func TestFleetSummaryFindingsUseCanonicalSeverityAndFreshness(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	hidden := fleetSummaryEnroll(t, f)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	var err error
	f.svc.Advisories, err = advisory.New(f.ctx, f.svc.Pool, nil, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	feedRevision := uuid.NewString()
	fleetSummaryExec(t, f, `INSERT INTO advisory_feeds(id,distro,release,source_url,config_bytes,revision,expires_at,checked_at)
 VALUES('summary-feed','ubuntu','24.04','https://example.test/feed','',$1,CURRENT_TIMESTAMP+interval '1 day',CURRENT_TIMESTAMP)`, feedRevision)
	for _, device := range []*enrolledFixture{f, hidden} {
		snapshot := device.publishPackages(t, 1, "summary-package")
		fleetSummaryExec(t, f, "UPDATE devices SET state='active',host_received_at=CURRENT_TIMESTAMP WHERE id=$1", device.deviceID)
		fleetSummaryExec(t, f, `INSERT INTO advisory_evaluations(device_id,id,snapshot_id,feed_id,feed_revision,evaluated_at,inventory_at,host_received_at,expires_at,state,reason,finding_digest)
 SELECT id,$2,$3,'summary-feed',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,host_received_at,CURRENT_TIMESTAMP+interval '1 day','evaluated','',decode(repeat('00',32),'hex') FROM devices WHERE id=$1`,
			device.deviceID, uuid.NewString(), snapshot, feedRevision)
	}
	// Each device binds its own shared finding set; per-severity counts and the
	// advisory rollup are persisted with the set exactly as the matcher does.
	bindSet := func(device string, severities []string) []string {
		t.Helper()
		setID := uuid.NewString()
		packageDigest := sha256.Sum256([]byte(setID))
		counts := map[string]int{}
		for _, severity := range severities {
			switch severity {
			case "critical", "high", "medium", "low":
				counts[severity]++
			default:
				counts["other"]++
			}
		}
		fleetSummaryExec(t, f, `INSERT INTO advisory_finding_sets(id,feed_id,feed_revision,package_digest,state,reason,finding_digest,finding_count,critical_count,high_count,medium_count,low_count,other_count)
 VALUES($1,'summary-feed',$2,$9,'evaluated','',decode(repeat('11',32),'hex'),$3,$4,$5,$6,$7,$8)`,
			setID, feedRevision, len(severities), counts["critical"], counts["high"], counts["medium"], counts["low"], counts["other"], packageDigest[:])
		keys := make([]string, 0, len(severities))
		rollup := map[string]int{}
		for _, severity := range severities {
			key := uuid.NewString()
			keys = append(keys, key)
			rollup[severity]++
			fleetSummaryExec(t, f, `INSERT INTO advisory_set_findings(set_id,finding_key,advisory_id,package_name,installed_version,fixed_version,architecture,severity,cves,source_url)
 VALUES($1,$2,'SUMMARY-1','summary-package','1','2','amd64',$3,'{}','https://example.test/feed')`, setID, key, severity)
		}
		for severity, n := range rollup {
			fleetSummaryExec(t, f, "INSERT INTO advisory_set_advisories(set_id,advisory_id,severity,findings) VALUES($1,'SUMMARY-1',$2,$3)", setID, severity, n)
		}
		fleetSummaryExec(t, f, "UPDATE advisory_evaluations SET finding_set_id=$1 WHERE device_id=$2", setID, device)
		return keys
	}
	keys := bindSet(f.deviceID, []string{"critical", "critical", "high", "medium", "low", "unrated", "high"})
	accepted := keys[len(keys)-1]
	fleetSummaryExec(t, f, `INSERT INTO advisory_exceptions(finding_id,device_id,actor_id,reason,accepted_at,expires_at)
 VALUES($1,$2,$3,'summary accepted risk',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+interval '1 day')`, accepted, f.deviceID, owner.ID)
	bindSet(hidden.deviceID, []string{"critical", "critical", "critical", "critical"})
	ctx := identity.WithPrincipal(f.ctx, scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}}))
	want := &adminv1.FleetFindingSummary{CriticalFindings: 2, HighFindings: 1, MediumFindings: 1, LowFindings: 1, OtherFindings: 1, EvaluatedDevices: 1}
	got := fleetSummary(t, f.svc, ctx, 0)
	if !proto.Equal(got.GetFindings(), want) {
		t.Fatalf("severity counts included accepted/hidden findings or deduplicated packages: got=%v want=%v", got.GetFindings(), want)
	}
	all := fleetSummary(t, f.svc, f.ownerCtx, 0)
	wantAll := proto.CloneOf(want)
	wantAll.CriticalFindings = 6
	wantAll.EvaluatedDevices = 2
	if !proto.Equal(all.GetFindings(), wantAll) {
		t.Fatalf("unrestricted advisory aggregates lost findings: %v", all.GetFindings())
	}
	fleetSummaryExec(t, f, "UPDATE advisory_exceptions SET accepted_at=CURRENT_TIMESTAMP-interval '2 hours',expires_at=CURRENT_TIMESTAMP-interval '1 hour' WHERE finding_id=$1", accepted)
	want.HighFindings++
	if expiredAcceptance := fleetSummary(t, f.svc, ctx, 0); !proto.Equal(expiredAcceptance.GetFindings(), want) {
		t.Fatalf("expired risk acceptance remained excluded: %v", expiredAcceptance.GetFindings())
	}
	// Expiry is a read-time decision, not dependent on a refresh worker.
	fleetSummaryExec(t, f, "UPDATE advisory_evaluations SET expires_at=CURRENT_TIMESTAMP-interval '1 hour' WHERE device_id=$1", f.deviceID)
	stale := fleetSummary(t, f.svc, ctx, 0)
	if !proto.Equal(stale.GetFindings(), &adminv1.FleetFindingSummary{UnknownDevices: 1}) {
		t.Fatalf("expired findings remained open or evaluated: %v", stale.GetFindings())
	}
	fleetSummaryExec(t, f, "UPDATE advisory_evaluations SET expires_at=CURRENT_TIMESTAMP+interval '1 day' WHERE device_id=$1", f.deviceID)
	fleetSummaryExec(t, f, "UPDATE advisory_feeds SET revision=$1 WHERE id='summary-feed'", uuid.NewString())
	changedFeed := fleetSummary(t, f.svc, f.ownerCtx, 0)
	if !proto.Equal(changedFeed.GetFindings(), &adminv1.FleetFindingSummary{UnknownDevices: 2}) {
		t.Fatalf("changed feed revision retained old evaluation: %v", changedFeed.GetFindings())
	}
}

func TestFleetSummaryPendingApprovalsRespectInboxAuthority(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	hidden := fleetSummaryEnroll(t, f)
	reviewerCtx := approvalReviewer(t, f.svc, f.ctx)
	reviewer, _ := identity.PrincipalFromContext(reviewerCtx)
	create := func(device string) string {
		t.Helper()
		response, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{
			LifetimeSeconds: 3600,
			Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: &adminv1.RevokeDeviceRequest{
				RequestId: uuid.NewString(), DeviceId: device, Reason: "summary inbox fixture",
			}},
		}))
		if err != nil {
			t.Fatal(err)
		}
		return response.Msg.GetApproval().GetId()
	}
	visible := create(f.deviceID)
	create(hidden.deviceID)
	expired, approved, rejected := create(f.deviceID), create(f.deviceID), create(f.deviceID)
	fleetSummaryExec(t, f, "UPDATE approval_requests SET created_at=CURRENT_TIMESTAMP-interval '2 hours',expires_at=CURRENT_TIMESTAMP-interval '1 hour' WHERE id=$1", expired)
	if _, err := f.svc.ApproveApproval(reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approved, Reason: "summary approved fixture"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RejectApproval(reviewerCtx, connect.NewRequest(&adminv1.RejectApprovalRequest{ApprovalId: rejected, Reason: "summary rejected fixture"})); err != nil {
		t.Fatal(err)
	}
	if got := fleetSummary(t, f.svc, f.ownerCtx, 0); got.GetApprovals() == nil || got.GetApprovals().GetPendingApprovals() != 2 {
		t.Fatalf("pending count included expired or decided requests: %v", got.GetApprovals())
	} else if got.GetApprovals().GetReadyToRun() != 1 {
		t.Fatalf("the requester's approved request is not ready to run: %v", got.GetApprovals())
	}
	if got := fleetSummary(t, f.svc, reviewerCtx, 0); got.GetApprovals() == nil || got.GetApprovals().GetReadyToRun() != 0 {
		t.Fatalf("another requester's approved request counted as ready for the approver: %v", got.GetApprovals())
	}
	// Persisted account scopes drive the fresh inbox read. The fleet principal
	// intentionally sees only the other device: these permissions are independent.
	fleetSummaryExec(t, f, `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes',jsonb_build_array(jsonb_build_object('deviceIds',jsonb_build_array($2::text)))) WHERE id=$1`, reviewer.ID, f.deviceID)
	scopedCtx := identity.WithPrincipal(f.ctx, scopedReader(reviewer, &authv1.DeviceScope{DeviceIds: []string{hidden.deviceID}}))
	scoped := fleetSummary(t, f.svc, scopedCtx, 0)
	if scoped.GetLifecycle().GetTotalDevices() != 1 || scoped.GetApprovals() == nil || scoped.GetApprovals().GetPendingApprovals() != 1 {
		t.Fatalf("pending inbox and fleet scopes were conflated: %v", scoped)
	}
	page, err := f.svc.ListApprovals(reviewerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 200}))
	if err != nil {
		t.Fatal(err)
	}
	var pending uint64
	for _, item := range page.Msg.GetApprovals() {
		if item.GetState() == adminv1.ApprovalState_APPROVAL_STATE_PENDING {
			pending++
			if item.GetId() != visible {
				t.Fatalf("unexpected visible pending approval: %v", item)
			}
		}
	}
	if pending != scoped.GetApprovals().GetPendingApprovals() {
		t.Fatalf("summary disagrees with actual inbox: summary=%d inbox=%d", scoped.GetApprovals().GetPendingApprovals(), pending)
	}
	// An inbox permission does not grant authority for the requested action.
	fleetSummaryExec(t, f, "UPDATE local_accounts SET role='auditor' WHERE id=$1", reviewer.ID)
	omitted := fleetSummary(t, f.svc, scopedCtx, 0)
	if omitted.GetApprovals() != nil {
		t.Fatalf("revoked action authority retained approval totals: %v", omitted.GetApprovals())
	}
}

func TestFleetSummaryAuthorizationAndOmittedSections(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	request := connect.NewRequest(&adminv1.GetFleetSummaryRequest{})
	if _, err := f.svc.GetFleetSummary(f.ctx, request); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unauthenticated summary: %v", err)
	}
	denied := owner
	denied.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionReadAudit)}}}
	if _, err := f.svc.GetFleetSummary(identity.WithPrincipal(f.ctx, denied), request); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("audit-only grant exposed fleet summary: %v", err)
	}
	auditor := insertPrincipal(t, f.ctx, f.conn, identity.RoleAuditor)
	got := fleetSummary(t, f.svc, identity.WithPrincipal(f.ctx, auditor), 0)
	if got.GetFindings() != nil || got.GetApprovals() != nil || got.GetLifecycle() == nil || got.GetContact() == nil || got.GetOperatingSystems() == nil || got.GetResourceCompliance() == nil {
		t.Fatalf("unavailable/denied sections were fabricated as zero or required sections omitted: %v", got)
	}
	f.svc.Identity = nil
	if got := fleetSummary(t, f.svc, f.ownerCtx, 0); got.GetApprovals() != nil {
		t.Fatalf("missing identity service fabricated inbox totals: %v", got.GetApprovals())
	}
	if _, err := f.svc.GetFleetSummary(f.ownerCtx, connect.NewRequest(&adminv1.GetFleetSummaryRequest{RecentActionLimit: 21})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("oversized action preview accepted: %v", err)
	}
}

func TestFleetSummaryRecentActionsAreNewestBoundedAndScoped(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	hidden := fleetSummaryEnroll(t, f.enrolledFixture)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	seed := f.create(t, f.request(lockActionSpec()))
	// Real authorization creates the source action. Only projection metadata is
	// varied below; this test makes no native-execution or signature claims.
	fleetSummaryExec(t, f.enrolledFixture, "UPDATE device_actions SET issued_at=$2,expires_at=$3,closed_at=$2,closed_reason='expired_unstarted' WHERE id=$1", seed.GetActionId(), f.now.Add(-48*time.Hour), f.now.Add(-47*time.Hour))
	resource := uuid.NewString()
	published, err := f.svc.PublishProfileRevision(f.ownerCtx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{
		RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "summary action history",
		Spec: &policyv1.ResourceProfile{Name: "Summary history", Resources: []*policyv1.ProfileResource{{
			ResourceId: resource,
			Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "summary.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "summary.service",
				Runtime:    resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE,
				Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED,
			}}}, Ownership: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}, Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
		}}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	assigned, err := f.svc.SetResourceAssignment(f.ownerCtx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{
		RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "summary action history",
		Target: &adminv1.ResourceAssignmentTarget{ProfileId: published.Msg.GetRevision().GetProfileId(), RevisionId: published.Msg.GetRevision().GetRevisionId()},
	}))
	if err != nil {
		t.Fatal(err)
	}
	assignment := assigned.Msg.GetAssignment().GetAssignmentId()
	work, err := f.svc.GetResourceWork(f.deviceCtx(), connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 1}))
	if err != nil || work.Msg.GetWork() == nil {
		t.Fatalf("create real service action fixture: %v", err)
	}
	serviceSeed := work.Msg.GetWork().GetActionId()
	fleetSummaryExec(t, f.enrolledFixture, "UPDATE resource_actions SET issued_at=$2,expires_at=$3,closed_at=$2,closed_reason='expired_unstarted' WHERE id=$1", serviceSeed, f.now.Add(-48*time.Hour), f.now.Add(-47*time.Hour))
	type expectedAction struct {
		id, device, kind string
		at               time.Time
	}
	var want []expectedAction
	for i := range 24 {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)
		at := f.now.Add(-time.Duration(24-i) * time.Minute)
		kind := "device"
		if i%2 == 0 {
			kind = "resource"
			fleetSummaryExec(t, f.enrolledFixture, `INSERT INTO resource_actions(id,device_id,generation_id,assignment_id,resource_id,resource_sequence,intent_envelope,intent_document,issued_at,expires_at,closed_at,closed_reason)
 SELECT $1,device_id,generation_id,$2,$3,$4,intent_envelope,intent_document,$5,$6,$5,'expired_unstarted' FROM resource_actions WHERE id=$7`,
				id, assignment, resource, i+1, at, at.Add(time.Hour), serviceSeed)
		} else {
			fleetSummaryExec(t, f.enrolledFixture, `INSERT INTO device_actions(id,device_id,generation_id,capability,request_id,request_digest,request_document,actor_id,authorization_version,intent_envelope,intent_document,issued_at,expires_at,closed_at,closed_reason)
 SELECT $1,device_id,generation_id,capability,$2,request_digest,request_document,actor_id,authorization_version,intent_envelope,intent_document,$3,$4,$3,'expired_unstarted' FROM device_actions WHERE id=$5`,
				id, uuid.NewString(), at, at.Add(time.Hour), seed.GetActionId())
		}
		want = append(want, expectedAction{id: id, device: f.deviceID, kind: kind, at: at})
	}
	// Equal timestamps require deterministic ID ordering across both tables.
	tied := f.now.Add(-time.Minute)
	fleetSummaryExec(t, f.enrolledFixture, "UPDATE resource_actions SET issued_at=$2 WHERE id=$1", want[22].id, tied)
	want[22].at = tied
	// History follows the authorized device, not only its current generation.
	oldGeneration := uuid.NewString()
	fleetSummaryExec(t, f.enrolledFixture, "INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES($1,$2,'revoked',$3)", oldGeneration, f.deviceID, f.now.Add(-72*time.Hour))
	fleetSummaryExec(t, f.enrolledFixture, "UPDATE device_actions SET generation_id=$2 WHERE id=$1", want[23].id, oldGeneration)
	hiddenAssignment := uuid.NewString()
	fleetSummaryExec(t, f.enrolledFixture, `INSERT INTO resource_assignments(id,device_id,generation_id,request_id,request_digest,actor_id,authorization_version,revision_id,document,assigned_at)
 SELECT $1,$2,$3,$4,request_digest,actor_id,authorization_version,revision_id,document,assigned_at FROM resource_assignments WHERE id=$5`,
		hiddenAssignment, hidden.deviceID, hidden.generation, uuid.NewString(), assignment)
	fleetSummaryExec(t, f.enrolledFixture, `INSERT INTO resource_assignment_resources(assignment_id,resource_id,resource_kind,canonical_key,position,document)
 SELECT $1,resource_id,resource_kind,canonical_key,position,document FROM resource_assignment_resources WHERE assignment_id=$2`, hiddenAssignment, assignment)
	// Rows for hidden devices are newer than every visible row and numerous
	// enough to consume the preview if either branch limits before scoping.
	hiddenActions := make([]string, 0, 25)
	for i := range 25 {
		id := uuid.NewString()
		hiddenActions = append(hiddenActions, id)
		fleetSummaryExec(t, f.enrolledFixture, `INSERT INTO device_actions(id,device_id,generation_id,capability,request_id,request_digest,request_document,actor_id,authorization_version,intent_envelope,intent_document,issued_at,expires_at,closed_at,closed_reason)
 SELECT $1,$2,$3,capability,$4,request_digest,request_document,actor_id,authorization_version,intent_envelope,intent_document,$5,$6,$5,'expired_unstarted' FROM device_actions WHERE id=$7`,
			id, hidden.deviceID, hidden.generation, uuid.NewString(), f.now.Add(time.Duration(i)*time.Second), f.now.Add(time.Hour), seed.GetActionId())
		fleetSummaryExec(t, f.enrolledFixture, `INSERT INTO resource_actions(id,device_id,generation_id,assignment_id,resource_id,resource_sequence,intent_envelope,intent_document,issued_at,expires_at,closed_at,closed_reason)
 SELECT $1,$2,$3,$4,resource_id,$5,intent_envelope,intent_document,$6,$7,$6,'expired_unstarted' FROM resource_actions WHERE id=$8`,
			id, hidden.deviceID, hidden.generation, hiddenAssignment, i+1, f.now.Add(time.Duration(i)*time.Second), f.now.Add(time.Hour), serviceSeed)
	}
	slices.Reverse(want)
	principal := scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}})
	principal.Bindings = append(principal.Bindings, &authv1.RoleBinding{Permissions: []string{string(identity.PermissionReadAudit)}})
	ctx := identity.WithPrincipal(f.ctx, principal)
	for _, limit := range []uint32{0, 1, 7, 20} {
		t.Run(fmt.Sprintf("limit-%d", limit), func(t *testing.T) {
			count := int(limit)
			if count == 0 {
				count = 10
			}
			got := fleetSummary(t, f.svc, ctx, limit).GetRecentActions()
			if len(got) != count {
				t.Fatalf("preview count=%d, want=%d", len(got), count)
			}
			for i, row := range got {
				expected := want[i]
				if row.GetActionId() != expected.id || row.GetDeviceId() != expected.device || row.GetKind() != expected.kind || !row.GetCreatedAt().AsTime().Equal(expected.at) {
					t.Fatalf("newest authorized action %d: got=%v want=%+v", i, row, expected)
				}
				if row.GetClosedReason() != "expired_unstarted" || row.GetClosedAt() == nil || row.GetStartAuthorizedAt() != nil || row.GetOutcomeUnknown() {
					t.Fatalf("unstarted closure invented execution state: %v", row)
				}
				if expected.kind == "resource" {
					if row.GetResourceId() != resource || row.GetUnit() != "summary.service" || row.GetCapability() != "" {
						t.Fatalf("service action metadata lost or fabricated: %v", row)
					}
				} else if row.GetCapability() != "device.lock-sessions.v1" || row.GetResourceId() != "" || row.GetUnit() != "" {
					t.Fatalf("imperative action metadata changed: %v", row)
				}
			}
		})
	}
	unrestricted := fleetSummary(t, f.svc, f.ownerCtx, 20)
	if len(unrestricted.GetRecentActions()) != 20 {
		t.Fatalf("unrestricted preview did not honor limit: %v", unrestricted.GetRecentActions())
	}
	for i, row := range unrestricted.GetRecentActions() {
		kind := "resource"
		if i%2 != 0 {
			kind = "device"
		}
		if row.GetDeviceId() != hidden.deviceID || row.GetActionId() != hiddenActions[24-i/2] || row.GetKind() != kind {
			t.Fatalf("unrestricted timestamp/ID/kind order changed at %d: %v", i, row)
		}
	}
	principal = scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}})
	if got := fleetSummary(t, f.svc, identity.WithPrincipal(f.ctx, principal), 20); len(got.GetRecentActions()) != 0 {
		t.Fatalf("hidden actions leaked into an empty scope: %v", got.GetRecentActions())
	}
}

// The background population serves unrestricted readers only while fresh;
// scoped readers and an expired population always read live.
func TestFleetSummaryBackgroundPopulationIsFreshUnrestrictedOnly(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	if err := f.svc.RefreshFleetPopulation(f.ctx); err != nil {
		t.Fatal(err)
	}
	before := fleetSummary(t, f.svc, f.ownerCtx, 0).GetLifecycle().GetTotalDevices()
	fleetSummaryEnroll(t, f)
	if cached := fleetSummary(t, f.svc, f.ownerCtx, 0).GetLifecycle().GetTotalDevices(); cached != before {
		t.Fatalf("fresh unrestricted population not served: %d want cached %d", cached, before)
	}
	scoped := identity.WithPrincipal(f.ctx, scopedReader(owner, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}}))
	if got := fleetSummary(t, f.svc, scoped, 0).GetLifecycle().GetTotalDevices(); got != 1 {
		t.Fatalf("scoped reader used the unrestricted population: %d", got)
	}
	f.svc.Clock = func() time.Time { return time.Now().Add(directory.FleetSummaryMaxAge + time.Minute) }
	if live := fleetSummary(t, f.svc, f.ownerCtx, 0).GetLifecycle().GetTotalDevices(); live != before+1 {
		t.Fatalf("expired population served: %d want live %d", live, before+1)
	}
	f.svc.Clock = time.Now
	if err := f.svc.RefreshFleetPopulation(f.ctx); err != nil {
		t.Fatal(err)
	}
	if refreshed := fleetSummary(t, f.svc, f.ownerCtx, 0).GetLifecycle().GetTotalDevices(); refreshed != before+1 {
		t.Fatalf("refresh did not publish a new population: %d", refreshed)
	}
}
