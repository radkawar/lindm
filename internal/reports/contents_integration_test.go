//go:build integration

package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
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
	finding := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_evaluations(device_id,id,evaluated_at,expires_at,state,reason,finding_digest)
VALUES($1,$2,now(),now()+interval '1 hour','unknown','inventory unavailable',$3)`, device, uuid.New(), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_findings(id,device_id,advisory_id,package_name,installed_version,fixed_version,architecture,severity,cves,feed_id,source_url)
VALUES($1,$2,'CVE-test','openssl','1.0','1.1','amd64','high',ARRAY['CVE-test'],'offline','https://vendor.example.test/advisory')`, finding, device); err != nil {
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
	output.Reset()
	if _, err := writeDomainReport(ctx, reportdb.New(pool), &output, integrationsv1.ReportKind_REPORT_KIND_INVENTORY, integrationsv1.ReportFormat_REPORT_FORMAT_CSV); err != nil {
		t.Fatal(err)
	}
	csvRows, err := csv.NewReader(&output).ReadAll()
	if err != nil || len(csvRows) != 2 || csvRows[1][1] != "'=unsafe spreadsheet" {
		t.Fatalf("CSV formula not neutralized: %v %v", csvRows, err)
	}
}
