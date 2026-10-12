//go:build linux

package diskgc

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// busy starts a process that uses dir as its cwd, or names it on its command
// line when named is set, until the test ends.
func busy(t *testing.T, dir string, named bool) {
	t.Helper()
	cmd := exec.Command("sh", "-c", "sleep 600", "sh")
	if named {
		cmd.Args = append(cmd.Args, "-evidence="+dir)
	} else {
		cmd.Dir = dir
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// The process is visible in /proc once started; its cwd and cmdline are
	// set before exec returns.
	deadline := time.Now().Add(10 * time.Second)
	for {
		procs, err := scanProcesses()
		if err != nil {
			t.Fatal(err)
		}
		if procs.user(dir) != "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("busy process never showed in /proc")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBuildCacheRemovesOnlyStaleEntries(t *testing.T) {
	cache := t.TempDir()
	stale := filepath.Join(cache, "ab", strings.Repeat("a", 64)+"-d")
	fresh := filepath.Join(cache, "ab", strings.Repeat("b", 64)+"-a")
	foreign := filepath.Join(cache, "ab", "notes.txt")
	for _, path := range []string{stale, fresh, foreign, filepath.Join(cache, "README")} {
		write(t, path, "x")
	}
	old := time.Now().Add(-3 * time.Hour)
	for _, path := range []string{stale, foreign, filepath.Join(cache, "README")} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := BuildCache(t.Context(), cache, time.Minute, false); err == nil {
		t.Fatal("a horizon under the go command's refresh interval was accepted")
	}
	dry, err := BuildCache(t.Context(), cache, 2*time.Hour, true)
	if err != nil || dry.Removed != 1 || !exists(stale) {
		t.Fatalf("dry run: %+v, %v", dry, err)
	}
	result, err := BuildCache(t.Context(), cache, 2*time.Hour, false)
	if err != nil || result.Removed != 1 || result.Kept != 1 || result.Reclaimed <= 0 {
		t.Fatalf("result %+v, %v", result, err)
	}
	if exists(stale) || !exists(fresh) || !exists(foreign) || !exists(filepath.Join(cache, "README")) {
		t.Fatal("removed the wrong files")
	}
}

func TestMatrixInputsKeepEvidenceAndLiveRuns(t *testing.T) {
	root := t.TempDir()
	for _, run := range []string{"finished", "running", "named"} {
		write(t, filepath.Join(root, run, "inputs", "amd64", "build.json"), "{}")
		write(t, filepath.Join(root, run, "fedora-43", "lifecycle-x86_64.json"), "{}")
	}
	busy(t, filepath.Join(root, "running"), false)
	busy(t, filepath.Join(root, "named"), true)
	recent, err := MatrixInputs(t.Context(), root, time.Hour, false)
	if err != nil || recent.Removed != 0 || recent.Kept != 3 {
		t.Fatalf("recently changed runs: %+v, %v", recent, err)
	}
	result, err := MatrixInputs(t.Context(), root, time.Nanosecond, false)
	if err != nil || result.Removed != 1 || result.Kept != 2 {
		t.Fatalf("result %+v, %v", result, err)
	}
	if exists(filepath.Join(root, "finished", "inputs")) || !exists(filepath.Join(root, "finished", "fedora-43", "lifecycle-x86_64.json")) {
		t.Fatal("finished run: inputs kept or evidence removed")
	}
	if !exists(filepath.Join(root, "running", "inputs")) || !exists(filepath.Join(root, "named", "inputs")) {
		t.Fatal("removed the inputs of a live run")
	}
	if again, err := MatrixInputs(t.Context(), root, time.Nanosecond, false); err != nil || again.Removed != 0 {
		t.Fatalf("second run not idempotent: %+v, %v", again, err)
	}
}

func TestLabRunsRemoveOnlyStaleRunDirectories(t *testing.T) {
	work := t.TempDir()
	for _, dir := range []string{"lindm-vm-stale", "lindm-vm-busy", "runs/run-stale", "demos/kept", "images/sha256-x", ".leases/local", "other"} {
		write(t, filepath.Join(work, dir, "file"), "x")
	}
	// An interrupted gc's claimed directory is finished off.
	write(t, filepath.Join(work, ".gc-lindm-vm-old-1", "file"), "x")
	busy(t, filepath.Join(work, "lindm-vm-busy"), false)
	result, err := LabRuns(t.Context(), []string{work, filepath.Join(work, "missing")}, time.Nanosecond, false)
	if err != nil || result.Removed != 3 || result.Kept != 1 || !strings.Contains(result.String(), "lindm-vm-busy: in use by pid") {
		t.Fatalf("result %+v, %v", result, err)
	}
	for _, gone := range []string{"lindm-vm-stale", "runs/run-stale", ".gc-lindm-vm-old-1"} {
		if exists(filepath.Join(work, gone)) {
			t.Fatalf("%s survived", gone)
		}
	}
	for _, kept := range []string{"lindm-vm-busy", "demos/kept", "images/sha256-x", ".leases/local", "other"} {
		if !exists(filepath.Join(work, kept)) {
			t.Fatalf("%s removed", kept)
		}
	}
}

func TestImagesRemoveOnlyUnreferencedUnlockedEntries(t *testing.T) {
	digest := func(c string) string { return strings.Repeat(c, 64) }
	images, golden, plain := t.TempDir(), t.TempDir(), t.TempDir()
	for _, cache := range []string{images, golden} {
		write(t, filepath.Join(cache, imageCacheMarker), "lindm verified image cache v1\n")
	}
	entry := func(cache, name, source string) string {
		path := filepath.Join(cache, name)
		write(t, filepath.Join(path, "image"), "bytes")
		if source != "" {
			write(t, filepath.Join(path, SourceFile), source+"\n")
		}
		return path
	}
	kept := []string{
		entry(images, "sha256-"+digest("a"), ""),                           // referenced image
		entry(images, "sha256-"+digest("c"), ""),                           // locked
		entry(images, "debian-installed/sha256-"+digest("e"), digest("a")), // built from a referenced image
		entry(images, "repository-snapshots/sha256/"+digest("f"), ""),      // referenced closure
		entry(golden, "golden-"+digest("1"), digest("b")),                  // pinned
		entry(golden, "golden-"+digest("2"), ""),                           // no provenance
		entry(plain, "sha256-"+digest("b"), ""),                            // not a lab cache
	}
	removed := []string{
		entry(images, "sha256-"+digest("b"), ""),
		entry(images, "debian-installed/sha256-"+digest("d"), digest("b")),
		entry(images, "repository-snapshots/sha256/"+digest("9"), ""),
		entry(golden, "golden-"+digest("3"), digest("b")),
	}
	write(t, filepath.Join(golden, ".references", "golden-"+digest("1"), "pin"), "/vm")
	lock, err := os.OpenFile(filepath.Join(images, "."+digest("c")+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	referenced := map[string]bool{digest("a"): true, digest("f"): true}
	if _, err := Images(t.Context(), []string{images}, nil, false); err == nil {
		t.Fatal("an empty reference set was accepted")
	}
	result, err := Images(t.Context(), []string{images, golden, plain, filepath.Join(plain, "missing")}, referenced, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != len(removed) {
		t.Fatalf("removed %d, want %d: %s", result.Removed, len(removed), result)
	}
	for _, path := range kept {
		if !exists(path) {
			t.Fatalf("%s removed", path)
		}
	}
	for _, path := range removed {
		if exists(path) {
			t.Fatalf("%s kept", path)
		}
	}
	for _, note := range []string{"locked by a lab process", "pinned by a persistent VM", "records no source image"} {
		if !strings.Contains(result.String(), note) {
			t.Fatalf("report lacks %q:\n%s", note, result)
		}
	}
}

func TestHostReportsEachClass(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("GOCACHE", cache)
	work := t.TempDir()
	var log bytes.Buffer
	results, err := Host(context.Background(), []string{work}, &log)
	if err != nil || len(results) != 2 || !strings.Contains(log.String(), "gc: go-build-cache") || !strings.Contains(log.String(), "gc: lab-runs") {
		t.Fatalf("results %+v, %v, log %q", results, err, log.String())
	}
	if free, err := Free(work); err != nil || free <= 0 {
		t.Fatalf("free %d, %v", free, err)
	}
}
