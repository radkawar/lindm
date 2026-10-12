package loadlab

import (
	"encoding/gob"
	"io"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Remote histograms merge into exact combined percentiles, not averaged ones.
func TestRemoteHistogramsMergeExactly(t *testing.T) {
	local, remote := &measurements{}, &measurements{}
	for range 98 {
		local.observe("GetSyncState", 2*time.Millisecond, nil)
	}
	remote.observe("GetSyncState", 900*time.Millisecond, nil)
	remote.observe("GetSyncState", 1500*time.Millisecond, connect.NewError(connect.CodeInternal, nil))
	if err := local.merge(remote.export(true)); err != nil {
		t.Fatal(err)
	}
	if len(remote.export(false)) != 0 {
		t.Fatal("export reset left remote histograms")
	}
	got := local.snapshot(false)["GetSyncState"]
	if got.Calls != 100 || got.Errors != 1 || got.NonRetryableErrors != 1 || got.P99Milliseconds != 900 || got.MaxMilliseconds != 1500 || got.Codes["internal"] != 1 {
		t.Fatalf("merged histogram=%+v", got)
	}
	if err := local.merge(map[string]HistogramData{"Bad": {Bins: map[int64]uint64{1: 1}, Calls: 2}}); err == nil {
		t.Fatal("inconsistent remote histogram accepted")
	}
	if err := local.merge(map[string]HistogramData{"Bad": {Bins: map[int64]uint64{40000: 1}, Calls: 1}}); err == nil {
		t.Fatal("out-of-range remote bin accepted")
	}
}

func TestAdvisoryFreshnessRequiresCheckedCoverage(t *testing.T) {
	warm := advisoryFreshnessWarmup.Seconds()
	cases := []struct {
		samples []AdvisorySample
		breach  bool
	}{
		{nil, true},
		{[]AdvisorySample{{ElapsedSeconds: warm - 1, Evaluated: 0, Total: 10}}, true},
		{[]AdvisorySample{{ElapsedSeconds: warm - 1, Evaluated: 0, Total: 10}, {ElapsedSeconds: warm, Evaluated: 8, Total: 10}}, false},
		{[]AdvisorySample{{ElapsedSeconds: warm, Evaluated: 8, Total: 10}, {ElapsedSeconds: warm + 30, Evaluated: 7, Total: 10}}, true},
		{[]AdvisorySample{{ElapsedSeconds: warm, Evaluated: 0, Total: 0}}, true},
		{[]AdvisorySample{{ElapsedSeconds: 1, Error: "deadline_exceeded"}, {ElapsedSeconds: warm, Evaluated: 10, Total: 10}}, true},
	}
	for i, tc := range cases {
		if got := advisoryFreshnessBreached(tc.samples); got != tc.breach {
			t.Fatalf("case %d: breached=%v want %v", i, got, tc.breach)
		}
	}
}

func TestPackageBaselineLeadsSnapshotAndCarriesSourceIdentity(t *testing.T) {
	baseline := []*inventoryv1.Package{{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.19", Architecture: "amd64", Manager: "dpkg", SourceName: "openssh", SourceVersion: "1:9.6p1-3ubuntu13.19"}}
	encoded, err := encodePackageBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePackageBaseline(encoded)
	if err != nil || len(decoded) != 1 || decoded[0].GetName() != "openssh-server" {
		t.Fatalf("baseline round trip: %v %v", decoded, err)
	}
	data, err := packages(501, decoded)
	if err != nil || len(data.batches) != 2 {
		t.Fatalf("packages: %v", err)
	}
	var first inventoryv1.PackageBatch
	if err := proto.Unmarshal(data.batches[0], &first); err != nil {
		t.Fatal(err)
	}
	if first.Packages[0].GetName() != "openssh-server" {
		t.Fatalf("baseline not first: %v", first.Packages[0])
	}
	for _, p := range first.Packages[1:] {
		if p.GetSourceName() != p.GetName() || p.GetSourceVersion() != p.GetVersion() {
			t.Fatalf("synthetic dpkg package lacks source identity: %v", p)
		}
	}
	if _, err := packages(0, decoded); err == nil {
		t.Fatal("baseline larger than snapshot accepted")
	}
}

// The generator protocol rejects work before initialization and exits cleanly
// when the orchestrator closes its stdin.
func TestGeneratorProtocolRequiresInitialization(t *testing.T) {
	requestReader, requestWriter := io.Pipe()
	responseReader, responseWriter := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- ServeGenerator(t.Context(), requestReader, responseWriter) }()
	g := &remoteGenerator{stdin: requestWriter, encoder: gob.NewEncoder(requestWriter), pending: make(map[uint64]chan generatorResponse), done: make(chan struct{})}
	go g.read(responseReader)
	if _, err := g.call(t.Context(), generatorRequest{Enroll: &generatorEnroll{Index: 0, Secret: "unused"}}); err == nil || err.Error() != "generator is not initialized" {
		t.Fatalf("uninitialized enrollment: %v", err)
	}
	if err := requestWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("generator did not exit cleanly: %v", err)
	}
	if startRemoteGeneratorErr := func() error {
		_, err := startRemoteGenerator(t.Context(), "bad host", "/bin/true", "", "", io.Discard)
		return err
	}(); startRemoteGeneratorErr == nil {
		t.Fatal("unsafe generator host accepted")
	}
}

func TestRemoteGeneratorRejectsUnsafeAffinityBeforeLaunch(t *testing.T) {
	for _, cpus := range []string{"0;echo unsafe", "0-2,1", "8192", "3-1"} {
		if _, err := startRemoteGenerator(t.Context(), "unused", "/bin/true", "", cpus, io.Discard); err == nil {
			t.Fatalf("unsafe CPU list %q accepted", cpus)
		}
	}
}

func TestGeneratorMetricsObserveCurrentProcess(t *testing.T) {
	before, err := measureGenerator()
	if err != nil {
		t.Fatal(err)
	}
	after, err := measureGenerator()
	if err != nil {
		t.Fatal(err)
	}
	if before.RSSBytes == 0 || after.RSSBytes == 0 || after.CPUSeconds < before.CPUSeconds {
		t.Fatalf("invalid process counters before=%+v after=%+v", before, after)
	}
}
