// SPDX-License-Identifier: Apache-2.0

//go:build integration

package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/reports/reportdb"
)

func TestReportsUseCurrentNormalizedComplianceAndFindings(t *testing.T) {
	_, ctx, pool, actor := reportFixture(t)
	device, generation, assignment := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO devices(id,state,hostname,enrolled_at) VALUES($1,'active','=unsafe spreadsheet',now())", device); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES($1,$2,'active',now())", generation, device); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE devices SET current_generation_id=$1 WHERE id=$2", generation, device); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO resource_assignments(id,device_id,generation_id,request_id,request_digest,actor_id,authorization_version,document,assigned_at,reconcile_interval_seconds)
VALUES($1,$2,$3,$4,$5,$6,1,$7,now(),300)`, assignment, device, generation, uuid.New(), make([]byte, 32), actor, []byte{8, 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO resource_assignment_heads(generation_id,assignment_id) VALUES($1,$2)", generation, assignment); err != nil {
		t.Fatal(err)
	}
	resources := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for i, id := range resources {
		disposition := int16(1)
		dependencies := []uuid.UUID{}
		if i == 0 {
			disposition = 4
		}
		if i == 1 || i == 2 {
			dependencies = append(dependencies, resources[i-1])
		}
		if _, err := pool.Exec(ctx, `INSERT INTO resource_assignment_resources(assignment_id,resource_id,resource_kind,canonical_key,position,document,depends_on,disposition)
VALUES($1,$2,1,$3,$4,$5,$6,$7)`, assignment, id, id.String()+".service", i, []byte{8, 1}, dependencies, disposition); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, "UPDATE resource_assignment_resources SET last_verified_at=now()-interval '601 seconds' WHERE resource_id=$1", resources[3]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE resource_assignment_resources SET last_verified_at=now(),drift_remediated=true WHERE resource_id=$1", resources[4]); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	count, err := writeDomainReport(ctx, reportdb.New(pool), &output, integrationsv1.ReportKind_REPORT_KIND_COMPLIANCE, integrationsv1.ReportFormat_REPORT_FORMAT_JSON)
	if err != nil || count != 6 {
		t.Fatalf("compliance row count=%d: %v", count, err)
	}
	var records []map[string]any
	if err := json.Unmarshal(output.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	states := make(map[string]string)
	for _, record := range records {
		id, idOK := record["resource_id"].(string)
		state, stateOK := record["state"].(string)
		if !idOK || !stateOK || record["resource_kind"] != float64(1) || record["canonical_key"] != id+".service" {
			t.Fatalf("report lost typed resource identity: %v", record)
		}
		states[id] = state
	}
	for i, want := range []string{"ATTENTION", "ATTENTION", "ATTENTION", "STALE", "DRIFT_REMEDIATED", "UNKNOWN"} {
		if states[resources[i].String()] != want {
			t.Fatalf("resource %d state=%q want=%q", i, states[resources[i].String()], want)
		}
	}
	output.Reset()
	count, err = writeDomainReport(ctx, reportdb.New(pool), &output, integrationsv1.ReportKind_REPORT_KIND_COMPLIANCE, integrationsv1.ReportFormat_REPORT_FORMAT_CSV)
	if err != nil || count != 6 {
		t.Fatalf("compliance CSV row count=%d: %v", count, err)
	}
	complianceCSV, err := csv.NewReader(&output).ReadAll()
	if err != nil || len(complianceCSV) != 7 {
		t.Fatalf("compliance CSV rows=%v: %v", complianceCSV, err)
	}
	wantColumns := []string{"device_id", "assignment_id", "resource_id", "resource_kind", "canonical_key", "reason", "last_verified_at", "observed_at", "state"}
	if !slices.Equal(complianceCSV[0], wantColumns) {
		t.Fatalf("compliance CSV columns=%v want=%v", complianceCSV[0], wantColumns)
	}
	for _, row := range complianceCSV[1:] {
		if row[0] != device.String() || row[1] != assignment.String() || row[3] != "1" || row[4] != row[2]+".service" || row[8] != states[row[2]] {
			t.Fatalf("compliance CSV lost typed resource identity or state: %v", row)
		}
	}
	finding, set := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_finding_sets(id,feed_id,feed_revision,package_digest,state,reason,finding_digest,finding_count,critical_count,high_count,medium_count,low_count,other_count)
VALUES($1,'offline',$2,$3,'evaluated','',$3,1,0,1,0,0,0)`, set, uuid.New(), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_set_findings(set_id,finding_key,advisory_id,package_name,installed_version,fixed_version,architecture,severity,cves,source_url)
VALUES($1,$2,'CVE-test','openssl','1.0','1.1','amd64','high',ARRAY['CVE-test'],'https://vendor.example.test/advisory')`, set, finding); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_evaluations(device_id,id,evaluated_at,expires_at,state,reason,finding_digest,finding_set_id)
VALUES($1,$2,now(),now()+interval '1 hour','unknown','inventory unavailable',$3,$4)`, device, uuid.New(), make([]byte, 32), set); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	count, err = writeDomainReport(ctx, reportdb.New(pool), &output, integrationsv1.ReportKind_REPORT_KIND_FINDINGS, integrationsv1.ReportFormat_REPORT_FORMAT_JSON)
	if err != nil || count != 1 {
		t.Fatalf("findings row count=%d: %v", count, err)
	}
	if err := json.Unmarshal(output.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if records[0]["package_name"] != "openssl" || records[0]["installed_version"] != "1.0" || records[0]["state"] != "unknown" {
		t.Fatalf("findings lost actual package/freshness: %v", records[0])
	}
	// Make the retained finding current, then exercise the same root-validity
	// decision used by new JSON/CSV reports independently of persisted state.
	snapshot, revision := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO package_snapshots(id,device_id,generation_id,sequence,state,manifest_digest,manifest_bytes,created_at,started_at,finished_at,accepted_at,open_until,receipt_expires_at,committed_at,backend,package_count,batch_count,encoded_bytes,metadata_bytes,reserved_bytes,bulk_retained)
VALUES($1,$2,$3,1,'committed',$4,$5,now(),now(),now(),now(),now()+interval '24 hours',now()+interval '2160 hours',now(),'rpm',0,0,0,0,0,true)`, snapshot, device, generation, make([]byte, 32), []byte{8, 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO package_attempts(generation_id,sequence,started_at,finished_at,received_at,status,backend,snapshot_id,digest)
VALUES($1,1,now(),now(),now(),1,'rpm',$2,$3)`, generation, snapshot, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE enrollment_generations SET current_snapshot_id=$1 WHERE id=$2", snapshot, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_feeds(id,distro,release,source_url,config_bytes,revision,checked_at,expires_at,complete_snapshot)
VALUES('report-current','rhel','9','https://vendor.example.test/advisory',$1,$2,now(),now()+interval '1 hour',true)`, []byte{8, 1}, revision); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE advisory_finding_sets SET feed_id='report-current',feed_revision=$1 WHERE id=$2", revision, set); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE advisory_evaluations SET snapshot_id=$1,feed_id='report-current',feed_revision=$2,state='evaluated',reason='' WHERE device_id=$3", snapshot, revision, device); err != nil {
		t.Fatal(err)
	}
	for _, accepted := range []bool{false, true} {
		if accepted {
			if _, err := pool.Exec(ctx, `INSERT INTO advisory_exceptions(device_id,finding_id,actor_id,reason,accepted_at,expires_at)
VALUES($1,$2,$3,'controlled report authority test',now(),now()+interval '1 hour')`, device, finding, actor); err != nil {
				t.Fatal(err)
			}
		}
		for _, platform := range []struct{ id, version string }{{"rhel", "9.8"}, {"rhel", "10.2"}, {"ubuntu", "24.04"}} {
			if _, err := pool.Exec(ctx, "UPDATE devices SET os_id=$1,os_version=$2 WHERE id=$3", platform.id, platform.version, device); err != nil {
				t.Fatal(err)
			}
			for _, valid := range []bool{true, false} {
				rows, err := reportdb.New(pool).FindingsReportRows(ctx, reportdb.FindingsReportRowsParams{AfterDevice: uuid.Nil, AfterID: uuid.Nil, RpmAuthorityValid: valid})
				if err != nil || len(rows) != 1 {
					t.Fatalf("current finding root=%t platform=%v rows=%v err=%v", valid, platform, rows, err)
				}
				var record map[string]any
				if err := json.Unmarshal([]byte(rows[0].Record), &record); err != nil {
					t.Fatal(err)
				}
				want := "affected"
				if accepted {
					want = "accepted"
				}
				if !valid && platform.id == "rhel" {
					want = "unknown"
				}
				if record["state"] != want {
					t.Fatalf("report bypassed current root: valid=%t platform=%v accepted=%t record=%v want=%s", valid, platform, accepted, record, want)
				}
			}
		}
	}
	output.Reset()
	if _, err := writeDomainReport(ctx, reportdb.New(pool), &output, integrationsv1.ReportKind_REPORT_KIND_INVENTORY, integrationsv1.ReportFormat_REPORT_FORMAT_CSV); err != nil {
		t.Fatal(err)
	}
	csvRows, err := csv.NewReader(&output).ReadAll()
	if err != nil || len(csvRows) != 2 || csvRows[1][1] != "'=unsafe spreadsheet" {
		t.Fatalf("CSV formula not neutralized: %v %v", csvRows, err)
	}
}
