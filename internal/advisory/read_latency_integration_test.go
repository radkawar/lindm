//go:build integration

package advisory

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/testdb"
)

// candidateTracer captures the exact AdvisoryCandidates statement and arguments
// the matcher executed, so the plan check explains the real query.
type candidateTracer struct {
	mu   sync.Mutex
	sql  string
	args []any
}

func (c *candidateTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "-- name: AdvisoryCandidates ") {
		c.mu.Lock()
		c.sql, c.args = data.SQL, slices.Clone(data.Args)
		c.mu.Unlock()
	}
	return ctx
}

func (*candidateTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// A 2,000-package device against a feed generation with 400,000 unrelated
// records: device reads serve the persisted evaluation within the latency
// budget and never match inline, and both candidate branches probe the
// identity index instead of scanning the generation.
func TestDeviceFindingsReadLatencyAndMatchPlan(t *testing.T) {
	base, _ := testdb.Open(t)
	tracer := new(candidateTracer)
	cfg := base.Config()
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx := t.Context()
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(ctx, source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var revision uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT revision FROM advisory_feeds WHERE id=$1", source.Id).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	binary, err := proto.Marshal(&advisoryv1.Advisory{Id: "BENCH-2026-0001", PackageName: "bench", FixedVersion: "0:1.0-2.fc44", Severity: "important", Cves: []string{"CVE-2026-0001"}})
	if err != nil {
		t.Fatal(err)
	}
	sourceRecord, err := proto.Marshal(&advisoryv1.Advisory{Id: "BENCH-2026-0002", PackageName: "bench-src", SourcePackage: true, FixedVersion: "0:1.0-2.fc44", Severity: "moderate", Cves: []string{"CVE-2026-0002"}})
	if err != nil {
		t.Fatal(err)
	}
	const packageCount = 2000
	mustExec(t, ctx, pool, `INSERT INTO advisory_record_generations(generation,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes)
SELECT $1,gen_random_uuid(),$2,'NOISE-'||g,'noise-'||g,g%2=0,'x86_64',$3 FROM generate_series(1,400000) g`, revision, source.Id, binary)
	mustExec(t, ctx, pool, `INSERT INTO advisory_record_generations(generation,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes)
SELECT $1,gen_random_uuid(),$2,'BENCH-2026-0001','bench-'||g,false,'x86_64',$3 FROM generate_series(0,$4::int-1) g`, revision, source.Id, binary, packageCount)
	mustExec(t, ctx, pool, `INSERT INTO advisory_record_generations(generation,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes)
SELECT $1,gen_random_uuid(),$2,'BENCH-2026-0002','bench-src-'||g,true,'',$3 FROM generate_series(0,$4::int/4-1) g`, revision, source.Id, sourceRecord, packageCount)
	// The seeded manifest holds one package (its bytes are bounded); the
	// remaining published rows are inserted directly, as a committed snapshot.
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "bench-0", Version: "0:1.0-1.fc44", Architecture: "x86_64", Manager: "rpm", SourceName: "bench-src-0", SourceVersion: "0:1.0-1.fc44"})
	mustExec(t, ctx, pool, `INSERT INTO snapshot_packages(snapshot_id,position,name,version,architecture,manager,source_name,source_version)
SELECT s.id,g,'bench-'||g,'0:1.0-1.fc44','x86_64','rpm','bench-src-'||(g/4),'0:1.0-1.fc44'
FROM package_snapshots s, generate_series(1,$2::int-1) g WHERE s.device_id=$1`, id, packageCount)
	mustExec(t, ctx, pool, "UPDATE package_snapshots SET package_count=$2 WHERE device_id=$1", id, packageCount)
	mustExec(t, ctx, pool, "ANALYZE advisory_record_generations")
	mustExec(t, ctx, pool, "ANALYZE snapshot_packages")
	request := &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 200}

	pending, err := s.ListDevice(ctx, request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if pending.Freshness.GetReason() != evaluationPending || pending.Freshness.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || len(pending.Findings) != 0 {
		t.Fatalf("read matched inline instead of reporting a pending evaluation: %v", pending.Freshness)
	}

	started := time.Now()
	if err := drainEvaluations(ctx, s); err != nil {
		t.Fatal(err)
	}
	t.Logf("background evaluation of %d packages: %s", packageCount, time.Since(started))
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("background evaluation exceeded its bound: %s", elapsed)
	}

	tracer.mu.Lock()
	statement, args := tracer.sql, tracer.args
	tracer.mu.Unlock()
	if statement == "" {
		t.Fatal("matcher did not execute AdvisoryCandidates")
	}
	var plan []byte
	if err := pool.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+statement, args...).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	var root []struct{ Plan planNode }
	if err := json.Unmarshal(plan, &root); err != nil || len(root) != 1 {
		t.Fatalf("decode plan: %v", err)
	}
	identityProbes := 0
	var walk func(planNode)
	walk = func(n planNode) {
		if n.RelationName == "advisory_record_generations" && n.NodeType == "Seq Scan" {
			t.Fatalf("candidate matching scans the whole feed generation:\n%s", plan)
		}
		if n.IndexName == "advisory_record_generations_identity_idx" {
			identityProbes++
		}
		for _, child := range n.Plans {
			walk(child)
		}
	}
	walk(root[0].Plan)
	if identityProbes != 2 {
		t.Fatalf("binary and source branches must each probe the identity index, got %d:\n%s", identityProbes, plan)
	}

	first, err := s.ListDevice(ctx, request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Freshness.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED || len(first.Findings) != 200 || first.NextPageToken == "" {
		t.Fatalf("persisted evaluation: %v, %d findings", first.Freshness, len(first.Findings))
	}
	var findings int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_findings WHERE device_id=$1", id).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if findings != packageCount+packageCount {
		t.Fatalf("binary and source matches: got %d findings", findings)
	}

	const reads = 200
	latencies := make([]time.Duration, 0, reads)
	for range reads {
		started := time.Now()
		out, err := s.ListDevice(ctx, request, true, []byte("[]"))
		latencies = append(latencies, time.Since(started))
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Findings) != 200 {
			t.Fatalf("read returned %d findings", len(out.Findings))
		}
	}
	slices.Sort(latencies)
	p50, p99 := latencies[reads/2], latencies[reads*99/100-1]
	t.Logf("ListDevice over %d findings: p50 %s p99 %s max %s", findings, p50, p99, latencies[reads-1])
	if p99 > 200*time.Millisecond {
		t.Fatalf("device findings p99 %s exceeds 200ms", p99)
	}
}

type planNode struct {
	NodeType     string     `json:"Node Type"`
	RelationName string     `json:"Relation Name"`
	IndexName    string     `json:"Index Name"`
	Plans        []planNode `json:"Plans"`
}
