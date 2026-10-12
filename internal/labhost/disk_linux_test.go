package labhost

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lindm/internal/diskgc"
)

func TestDiskRefusalErrorAndIs(t *testing.T) {
	refusal := &DiskRefusal{Host: "spark", Path: "/srv/lab", Free: 10 << 30, Need: LaneDiskBytes(2)}
	message := refusal.Error()
	for _, want := range []string{"spark", "/srv/lab", "10.0 GiB free", "needs 64.0 GiB", "go run ./cmd/dev gc"} {
		if !strings.Contains(message, want) {
			t.Errorf("refusal %q does not name %q", message, want)
		}
	}
	if !errors.Is(refusal, ErrInsufficientDisk) || !errors.Is(errors.Join(errors.New("other"), refusal), ErrInsufficientDisk) {
		t.Fatal("refusal does not match ErrInsufficientDisk")
	}
	if errors.Is(refusal, context.Canceled) || errors.Is(errors.New("lab hosts: insufficient disk space"), ErrInsufficientDisk) {
		t.Fatal("ErrInsufficientDisk matched an unrelated error")
	}
	var typed *DiskRefusal
	if !errors.As(errors.Join(refusal), &typed) || typed.Need != 64<<30 {
		t.Fatalf("refusal is not recoverable as *DiskRefusal: %+v", typed)
	}
}

func TestAdmitDisk(t *testing.T) {
	need := LaneDiskBytes(2)
	for _, tc := range []struct {
		name       string
		free       []int64 // successive measurements
		collectErr error
		collects   int
		refused    bool
	}{
		{name: "fits", free: []int64{need}},
		{name: "fits after collection", free: []int64{need - 1, need}, collects: 1},
		{name: "fits after incomplete collection", free: []int64{need - 1, need}, collectErr: errors.New("partial"), collects: 1},
		{name: "short after collection", free: []int64{1 << 30, 2 << 30}, collects: 1, refused: true},
		{name: "short after failed collection", free: []int64{1 << 30, 1 << 30}, collectErr: errors.New("gc failed"), collects: 1, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			measured, collects := 0, 0
			slots := &Slots{host: "spark", work: work,
				diskFree: func(path string) (int64, error) {
					if path != work {
						t.Errorf("measured %s, want the work directory %s", path, work)
					}
					free := tc.free[min(measured, len(tc.free)-1)]
					measured++
					return free, nil
				},
				diskCollect: func(_ context.Context, workDirs []string, _ io.Writer) ([]diskgc.Result, error) {
					if len(workDirs) != 1 || workDirs[0] != work {
						t.Errorf("collected %v, want only %s", workDirs, work)
					}
					collects++
					return nil, tc.collectErr
				},
			}
			var log bytes.Buffer
			err := slots.AdmitDisk(t.Context(), 2, &log)
			if collects != tc.collects || measured != len(tc.free) {
				t.Fatalf("collected %d times and measured %d times, want %d and %d", collects, measured, tc.collects, len(tc.free))
			}
			if tc.collects > 0 && !strings.Contains(log.String(), "collecting stale lab data") {
				t.Errorf("collection was not reported: %q", log.String())
			}
			var refusal *DiskRefusal
			if !tc.refused {
				if err != nil {
					t.Fatalf("lane refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInsufficientDisk) || !errors.As(err, &refusal) {
				t.Fatalf("want a typed disk refusal, got %v", err)
			}
			if *refusal != (DiskRefusal{Host: "spark", Path: work, Free: tc.free[len(tc.free)-1], Need: need}) {
				t.Fatalf("refusal reports %+v", *refusal)
			}
			if tc.collectErr != nil && !errors.Is(err, tc.collectErr) {
				t.Fatalf("refusal dropped the collection failure: %v", err)
			}
		})
	}
	slots := &Slots{host: "spark", work: "/missing",
		diskFree: func(string) (int64, error) { return 0, errors.New("statfs failed") },
		diskCollect: func(context.Context, []string, io.Writer) ([]diskgc.Result, error) {
			t.Fatal("collected without a measurement")
			return nil, nil
		},
	}
	if err := slots.AdmitDisk(t.Context(), 1, io.Discard); err == nil || errors.Is(err, ErrInsufficientDisk) {
		t.Fatalf("unmeasurable disk was not a plain failure: %v", err)
	}
}

func TestCollectRunsLocalScript(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	runs := filepath.Join(work, "runs")
	mkdir := func(path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, size int) {
		t.Helper()
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), size), 0600); err != nil {
			t.Fatal(err)
		}
	}
	busy, fresh, stale, other := filepath.Join(runs, "run-busy"), filepath.Join(runs, "run-fresh"), filepath.Join(runs, "run-stale"), filepath.Join(runs, "other")
	for _, dir := range []string{busy, fresh, filepath.Join(stale, "work"), other, filepath.Join(work, "images")} {
		mkdir(dir)
	}
	write(filepath.Join(stale, "work", "disk.qcow2"), 256<<10)
	write(filepath.Join(busy, "disk.qcow2"), 4096)
	old := time.Now().Add(-2 * time.Hour)
	for _, path := range []string{filepath.Join(stale, "work", "disk.qcow2"), filepath.Join(stale, "work"), stale, busy, filepath.Join(busy, "disk.qcow2"), other} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	sleep := exec.Command("sleep", "300")
	sleep.Dir = busy
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sleep.Process.Kill(); _ = sleep.Wait() })
	// Inode change times cannot be set: let the quiet period pass them, then
	// make the fresh run's last write unambiguously recent.
	quiet := time.Second
	time.Sleep(2100 * time.Millisecond)
	write(filepath.Join(fresh, "serial.log"), 10)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(fresh, "serial.log"), future, future); err != nil {
		t.Fatal(err)
	}
	collect := func(minFree int64, dryRun bool) (int64, diskgc.Result) {
		t.Helper()
		free, result, err := collectRuns(t.Context(), "", QuoteShell(work), minFree, quiet, dryRun, diskgc.Result{Class: "test runs"})
		if err != nil {
			t.Fatal(err)
		}
		if free <= 0 {
			t.Fatalf("free space %d", free)
		}
		return free, result
	}
	exists := func(path string) bool {
		_, err := os.Lstat(path)
		return err == nil
	}

	if _, result := collect(0, false); result.Removed != 0 || result.Kept != 0 || !exists(stale) {
		t.Fatalf("collected although free space exceeded the minimum: %+v", result)
	}
	_, result := collect(math.MaxInt64, true)
	if result.Removed != 1 || result.Kept != 2 || result.Reclaimed < 256<<10 || !exists(stale) {
		t.Fatalf("dry run reported %+v or removed the stale run", result)
	}
	_, result = collect(math.MaxInt64, false)
	if result.Removed != 1 || result.Kept != 2 || result.Reclaimed < 256<<10 {
		t.Fatalf("collection reported %+v", result)
	}
	notes := strings.Join(result.Notes, "\n")
	if !strings.Contains(notes, "run-busy: in use") || !strings.Contains(notes, "run-fresh: changed within the quiet period") {
		t.Fatalf("kept runs are not explained: %q", notes)
	}
	if exists(stale) {
		t.Fatal("stale run survived")
	}
	for _, path := range []string{busy, fresh, other, filepath.Join(work, "images")} {
		if !exists(path) {
			t.Fatalf("%s was removed", path)
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(runs, ".gc-*")); len(matches) != 0 {
		t.Fatalf("claims left behind: %v", matches)
	}

	// A claim an interrupted collection left is finished.
	claim := filepath.Join(runs, ".gc-run-old-1")
	mkdir(claim)
	write(filepath.Join(claim, "disk.qcow2"), 4096)
	if _, result = collect(math.MaxInt64, false); result.Removed != 1 || exists(claim) {
		t.Fatalf("interrupted claim was not finished: %+v", result)
	}
}

func TestRemoteShellPath(t *testing.T) {
	if got := remoteShellPath("~/lab work"); got != `"$HOME"/'lab work'` {
		t.Fatalf("home path rendered as %s", got)
	}
	if got := remoteShellPath("/srv/it's"); got != `'/srv/it'"'"'s'` {
		t.Fatalf("absolute path rendered as %s", got)
	}
}
