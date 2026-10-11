package labhost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestReturnedEvidenceDoesNotOverwriteExistingRecord(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "downloaded.json")
	destination := filepath.Join(root, "evidence.json")
	if err := os.WriteFile(source, []byte("new record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("retained record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishRecord(source, destination); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing evidence not refused: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "retained record\n" {
		t.Fatal("existing record was changed")
	}
	fresh := filepath.Join(root, "fresh.json")
	if err := publishRecord(source, fresh); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("evidence mode = %v", info.Mode())
	}
}

// The dgx20 Ubuntu 26.04 inspect record named the cleaned remote run path
// (/home/r/lindm-lab/runs/run-…/records/inventory-record) as its
// InventoryRecordPath although the file had been copied to the requested
// local path. Returned records must name the local copies.
func TestReturnedRecordNamesLocalOutputCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "returned-record.json")
	remote := "/home/r/lindm-lab/runs/run-x/records/inventory-record"
	if err := os.WriteFile(path, []byte(`{"InventoryRecordPath":"`+remote+`","InventoryRecordSHA256":"ab","ImageID":"/home/r/lindm-lab/runs/run-x/records/other","MatchedPackages":675}`), 0600); err != nil {
		t.Fatal(err)
	}
	host := &labv1.LabHost{Name: "dgx20", Transport: "ssh", SshAlias: "dgx20"}
	if err := annotateRemoteRecord(path, host, time.Unix(0, 0), time.Unix(1, 0), "rev", "diff", map[string]string{remote: "/local/inventory.json"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		InventoryRecordPath, InventoryRecordSHA256, ImageID string
		MatchedPackages                                     int
		LabHost                                             map[string]any `json:"lab_host"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.InventoryRecordPath != "/local/inventory.json" || record.InventoryRecordSHA256 != "ab" || record.ImageID != "/home/r/lindm-lab/runs/run-x/records/other" || record.MatchedPackages != 675 || record.LabHost["name"] != "dgx20" {
		t.Fatalf("returned record = %s", data)
	}
}

func TestRemotePackageRelocationPreservesRepositoryBasename(t *testing.T) {
	root := t.TempDir()
	name := "lindm-agent_0.7.0_arm64.deb"
	build := filepath.Join(root, "build", name)
	repository := filepath.Join(root, "repository")
	pool := filepath.Join(repository, "pool", "main", "l", "lindm-agent", name)
	for _, path := range []string{build, pool} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("unchanged artifact bytes"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stage := &remoteStage{ctx: t.Context(), local: t.TempDir(), remote: t.TempDir(), stderr: io.Discard, copied: make(map[string]string)}
	stagedBuild, err := stage.input(build)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(stagedBuild) != name {
		t.Fatalf("package basename changed: %s", stagedBuild)
	}
	record := filepath.Join(root, "record.json")
	input := map[string]any{"artifact": map[string]string{"path": build}, "apt": map[string]string{"root": repository}}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, data, 0600); err != nil {
		t.Fatal(err)
	}
	stagedRecord, err := stage.record(record)
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(stagedRecord)
	if err != nil {
		t.Fatal(err)
	}
	var relocated struct {
		Artifact struct{ Path string }
		APT      struct{ Root string }
	}
	if err := json.Unmarshal(data, &relocated); err != nil {
		t.Fatal(err)
	}
	// The lifecycle validator derives this path from the artifact basename.
	poolArtifact := filepath.Join(relocated.APT.Root, "pool", "main", "l", "lindm-agent", filepath.Base(relocated.Artifact.Path))
	data, err = os.ReadFile(poolArtifact)
	if err != nil || string(data) != "unchanged artifact bytes" {
		t.Fatalf("relocated repository artifact unavailable or changed: %q, %v", data, err)
	}
	other := filepath.Join(root, "other", name)
	if err := os.MkdirAll(filepath.Dir(other), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("distinct artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	stagedOther, err := stage.input(other)
	if err != nil || stagedOther == stagedBuild || filepath.Base(stagedOther) != name {
		t.Fatalf("same-named inputs collide or lose basename: %s, %v", stagedOther, err)
	}
	data, err = os.ReadFile(stagedBuild)
	if err != nil || string(data) != "unchanged artifact bytes" {
		t.Fatalf("earlier artifact overwritten: %q, %v", data, err)
	}
}

func TestAssistanceEvidenceReturnKeepsOwnerCredentialsRemote(t *testing.T) {
	source, destination := t.TempDir(), filepath.Join(t.TempDir(), "returned")
	for name, data := range map[string]string{"assistance.json": "record", "guest.png": "screenshot", "owner-access": "secret", heldMarker: "held secret"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(data), 0400); err != nil {
			t.Fatal(err)
		}
	}
	// The run creates the destination before it starts; a split held run's
	// controller writes its own owner-access there, which must survive.
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "owner-access"), []byte("local secret"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := collectAssistanceEvidence(t.Context(), "", source, destination, io.Discard); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"assistance.json": "record", "guest.png": "screenshot", "owner-access": "local secret"} {
		got, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil || string(got) != want {
			t.Fatalf("returned %s = %q, %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(destination, heldMarker)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("held marker was returned: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(source, "owner-access")); err != nil || string(got) != "secret" {
		t.Fatalf("remote owner credentials changed: %q, %v", got, err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("returned evidence directory is not private: %v, %v", info, err)
	}
}

func TestReverseForwardOptionsRequirePortIPPort(t *testing.T) {
	options, err := reverseForwardOptions([]string{"43707:127.0.0.1:43707", "50639:192.168.0.109:50639"})
	if err != nil || strings.Join(options, " ") != "-o ExitOnForwardFailure=yes -R 127.0.0.1:43707:127.0.0.1:43707 -R 127.0.0.1:50639:192.168.0.109:50639" {
		t.Fatalf("options = %q, %v", options, err)
	}
	if options, err := reverseForwardOptions(nil); err != nil || options != nil {
		t.Fatalf("no forwards = %q, %v", options, err)
	}
	for _, bad := range []string{"43707:localhost:43707", "0:127.0.0.1:1", "1:127.0.0.1:70000", "127.0.0.1:1", "1:127.0.0.1:1:2", "-oProxyCommand=x:127.0.0.1:1"} {
		if _, err := reverseForwardOptions([]string{bad}); err == nil {
			t.Errorf("forward %q accepted", bad)
		}
	}
}

func TestWatchHeldDeliversMarkerOnceAndRemovesIt(t *testing.T) {
	marker := filepath.Join(t.TempDir(), heldMarker)
	var got []string
	run := RemoteRun{Host: &labv1.LabHost{}, OnHeld: func(_ context.Context, data []byte) error {
		got = append(got, string(data))
		return nil
	}}
	if err := os.WriteFile(marker, []byte(`{"device_id":"d"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run.watchHeld(t.Context(), marker, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != `{"device_id":"d"}` {
		t.Fatalf("OnHeld calls = %q", got)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker not removed: %v", err)
	}
	if err := os.WriteFile(marker, make([]byte, maxHeldMarker+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run.watchHeld(t.Context(), marker, 10*time.Millisecond); err == nil {
		t.Fatal("oversized marker accepted")
	}
	failing := RemoteRun{Host: &labv1.LabHost{}, OnHeld: func(context.Context, []byte) error { return errors.New("owner access failed") }}
	if err := os.WriteFile(marker, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := failing.watchHeld(t.Context(), marker, 10*time.Millisecond); err == nil {
		t.Fatal("OnHeld failure was not reported")
	}
	// Ctrl-C while OnHeld waits (e.g. for device findings) is an orderly
	// shutdown: the run's end must not surface as a held-access failure.
	ctx, cancel := context.WithCancel(t.Context())
	interrupted := RemoteRun{Host: &labv1.LabHost{}, OnHeld: func(ctx context.Context, _ []byte) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}}
	if err := os.WriteFile(marker, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := interrupted.watchHeld(ctx, marker, 10*time.Millisecond); err != nil {
		t.Fatalf("cancellation during OnHeld reported %v", err)
	}
}

// vm device-actions finalizes its record 0400 and rsync -a preserves the mode;
// the returned copy must still gain host provenance and be published
// (debian12-arm64-dgx21-device-actions-encryption-01 was left on the host).
func TestReadOnlyReturnedRecordIsAnnotated(t *testing.T) {
	root := t.TempDir()
	returned := filepath.Join(root, "returned-record.json")
	if err := os.WriteFile(returned, []byte(`{"passed":true}`+"\n"), 0400); err != nil {
		t.Fatal(err)
	}
	host := &labv1.LabHost{Name: "dgx21", Transport: "ssh", SshAlias: "dgx21", Runtime: "native"}
	start := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	if err := annotateRemoteRecord(returned, host, start, start.Add(time.Minute), "5231542", "digest", nil); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "evidence.json")
	if err := publishRecord(returned, destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Passed  bool `json:"passed"`
		LabHost struct {
			Name     string  `json:"name"`
			Revision string  `json:"source_revision"`
			Elapsed  float64 `json:"elapsed_seconds"`
		} `json:"lab_host"`
	}
	if err := json.Unmarshal(data, &record); err != nil || !record.Passed || record.LabHost.Name != "dgx21" || record.LabHost.Revision != "5231542" || record.LabHost.Elapsed != 60 {
		t.Fatalf("annotated record = %s: %v", data, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 2 {
		t.Fatalf("annotation left temporary files: %v, %v", entries, err)
	}
}
