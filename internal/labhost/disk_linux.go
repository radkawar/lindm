// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/diskgc"
)

// laneGuestDiskBytes is the free space one guest needs on its host's work
// directory filesystem: its installer or golden disk is created with a 24 GiB
// virtual size (installed images, encrypted goldens and the guests installed
// from them grow up to that), and its thin overlay, firmware variables, TPM
// state, serial logs and evidence take the remaining 8 GiB.
const laneGuestDiskBytes int64 = 32 << 30

// LaneDiskBytes is the free space a lane of guests needs on its host's work
// directory filesystem before it may start.
func LaneDiskBytes(guests uint32) int64 { return int64(guests) * laneGuestDiskBytes }

// ErrInsufficientDisk matches every DiskRefusal.
var ErrInsufficientDisk = errors.New("lab hosts: insufficient disk space")

// DiskRefusal is a lane refused before admission because its host's work
// directory filesystem lacks the space the lane needs, even after collecting
// that host's stale lab data. Starting it would end in ENOSPC mid-run.
type DiskRefusal struct {
	Host, Path string
	Free, Need int64
}

func (r *DiskRefusal) Error() string {
	return fmt.Sprintf("lab host %s: %s has %s free but the lane needs %s; free space with `go run ./cmd/devenv gc` (stale lab runs, old build cache, unreferenced images) or remove unneeded files on that filesystem", r.Host, r.Path, gib(r.Free), gib(r.Need))
}

func (r *DiskRefusal) Is(target error) bool { return target == ErrInsufficientDisk }

func gib(bytes int64) string { return fmt.Sprintf("%.1f GiB", float64(bytes)/(1<<30)) }

// AdmitDisk refuses a lane of guests whose need exceeds the free space on the
// executing host's work directory filesystem. When short it collects that
// host's stale lab data once (diskgc.Host, reported to log) and measures
// again. It never waits and takes no slot or FIFO ticket: call it before
// RunAdmitted or RunBatchWorker. Concurrent lanes are not reserved against
// each other; each measures what is free when it starts.
func (s *Slots) AdmitDisk(ctx context.Context, guests uint32, log io.Writer) error {
	need := LaneDiskBytes(guests)
	free, err := s.diskFree(s.work)
	if err != nil {
		return fmt.Errorf("lab hosts: measure free disk: %w", err)
	}
	if free >= need {
		return nil
	}
	if _, err := fmt.Fprintf(log, "lab host %s: %s has %s free but the lane needs %s; collecting stale lab data\n", s.host, s.work, gib(free), gib(need)); err != nil {
		return err
	}
	_, collectErr := s.diskCollect(ctx, []string{s.work}, log)
	if free, err = s.diskFree(s.work); err != nil {
		return errors.Join(collectErr, fmt.Errorf("lab hosts: measure free disk: %w", err))
	}
	if free < need {
		return errors.Join(&DiskRefusal{Host: s.host, Path: s.work, Free: free, Need: need}, collectErr)
	}
	if collectErr != nil {
		if _, err := fmt.Fprintf(log, "lab host %s: collection was incomplete, but the lane now fits: %v\n", s.host, collectErr); err != nil {
			return err
		}
	}
	return nil
}

// remoteShellPath renders a configured host path for the explicit remote Bash:
// "~/" is the remote user's home, never the controller's.
func remoteShellPath(path string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return `"$HOME"/` + QuoteShell(rest)
	}
	return QuoteShell(path)
}

// CollectRemoteRuns reads the free space of an SSH host's work directory
// filesystem and, only when it is below minFree, removes the host's stale
// remote run directories <work>/runs/run-*: those no process of the lab user
// on that host uses (cwd, root, executable or open file beneath it, or its
// path on a command line) and in which nothing changed (mtime or ctime)
// within quiet. Each is claimed by renaming it to runs/.gc-* before removal,
// and claims an interrupted collection left are finished. Reclaimed counts
// allocated bytes (what a dry run would remove). The returned free space is
// measured after collection. A local-transport host is measured but not
// collected here: diskgc.LabRuns covers its work directory.
func CollectRemoteRuns(ctx context.Context, host *labv1.LabHost, minFree int64, quiet time.Duration, dryRun bool) (int64, diskgc.Result, error) {
	result := diskgc.Result{Class: host.GetName() + " runs"}
	if err := Validate(&labv1.LabConfig{Hosts: []*labv1.LabHost{host}}); err != nil {
		return 0, result, err
	}
	if host.Transport != "ssh" {
		work, err := ResolveWorkDirectory(host)
		if err != nil {
			return 0, result, err
		}
		free, err := diskgc.Free(work)
		result.Notes = append(result.Notes, "local host: its runs are collected with the local lab runs")
		return free, result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return collectRuns(ctx, host.SshAlias, remoteShellPath(host.WorkDirectory), minFree, quiet, dryRun, result)
}

// collectRunsNotes bounds the explanations the remote script reports.
const collectRunsNotes = 20

// collectRuns runs the collection script through executionCommand: alias ""
// runs it in a local Bash. work is a shell expression for the work directory.
func collectRuns(ctx context.Context, alias, work string, minFree int64, quiet time.Duration, dryRun bool, result diskgc.Result) (int64, diskgc.Result, error) {
	if quiet < 0 {
		return 0, result, errors.New("lab hosts: quiet period must not be negative")
	}
	dry := "0"
	if dryRun {
		dry = "1"
	}
	// Every diagnostic is discarded: only "free", "result" and "note" lines
	// are output. A process scan that cannot see the script's own descriptor
	// and command line would call every run stale, so it aborts instead.
	script := `# lindm-collect-runs
set -u
cd / || exit 1
work=` + work + `
min_free=` + strconv.FormatInt(minFree, 10) + `
quiet=` + strconv.FormatInt(int64(quiet/time.Second), 10) + `
dry=` + dry + `
max_notes=` + strconv.Itoa(collectRunsNotes) + `
free_bytes() {
 local probe=$work blocks size
 while [ ! -e "$probe" ]; do probe=${probe%/*}; [ -n "$probe" ] || probe=/; done
 read -r blocks size < <(stat -f -c '%a %S' -- "$probe" 2>/dev/null) || return 1
 printf '%s\n' "$((blocks * size))"
}
free=$(free_bytes) || { printf 'error cannot measure free space\n'; exit 1; }
printf 'free %s\n' "$free"
if [ "$free" -ge "$min_free" ]; then exit 0; fi
removed=0 kept=0 reclaimed=0 notes=0 more=0
note() {
 if [ "$notes" -lt "$max_notes" ]; then printf 'note %s\n' "$1"; notes=$((notes + 1)); else more=$((more + 1)); fi
}
allocated() { local bytes; bytes=$(du -s -B1 -- "$1" 2>/dev/null | cut -f1); printf '%s\n' "${bytes:-0}"; }
if [ -d "$work/runs" ] && [ ! -L "$work/runs" ]; then
 # /proc reports canonical paths; command lines may carry the given one.
 given=$work
 work=$(cd -P -- "$work" 2>/dev/null && pwd -P) || { printf 'error cannot resolve the work directory\n'; exit 1; }
 uses=$(mktemp) || { printf 'error cannot create scan file\n'; exit 1; }
 trap 'rm -f -- "$uses"' EXIT
 exec 9>>"$uses"
 find /proc/[0-9]*/cwd /proc/[0-9]*/root /proc/[0-9]*/exe /proc/[0-9]*/fd/ -maxdepth 1 -type l -printf '%l\n' 2>/dev/null >> "$uses"
 cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' '\n' >> "$uses"
 exec 9>&-
 if ! grep -qxF -- "$uses" "$uses" || ! grep -qxF -- '# lindm-collect-runs' "$uses"; then
  printf 'error cannot inspect the processes of this host\n'; exit 1
 fi
 cutoff=$(( $(date +%s) - quiet ))
 for dir in "$work"/runs/.gc-*; do
  [ -d "$dir" ] && [ ! -L "$dir" ] || continue
  size=$(allocated "$dir")
  if [ "$dry" = 1 ]; then reclaimed=$((reclaimed + size)); removed=$((removed + 1)); continue; fi
  chmod -R u+w -- "$dir" 2>/dev/null
  if rm -rf -- "$dir" 2>/dev/null; then reclaimed=$((reclaimed + size)); removed=$((removed + 1)); else kept=$((kept + 1)); note "${dir##*/}: removal failed"; fi
 done
 for dir in "$work"/runs/run-*; do
  [ -d "$dir" ] && [ ! -L "$dir" ] || continue
  name=${dir##*/}
  if grep -qF -e "$dir" -e "$given/runs/$name" -- "$uses"; then kept=$((kept + 1)); note "$name: in use"; continue; fi
  if ! recent=$(find "$dir" \( -newermt "@$cutoff" -o -newerct "@$cutoff" \) -print -quit 2>/dev/null); then
   kept=$((kept + 1)); note "$name: not fully readable"; continue
  fi
  if [ -n "$recent" ]; then kept=$((kept + 1)); note "$name: changed within the quiet period"; continue; fi
  size=$(allocated "$dir")
  if [ "$dry" = 1 ]; then reclaimed=$((reclaimed + size)); removed=$((removed + 1)); continue; fi
  trash="$work/runs/.gc-$name-$$"
  if ! mv -T -- "$dir" "$trash" 2>/dev/null; then
   [ -e "$dir" ] || continue
   kept=$((kept + 1)); note "$name: claim failed"; continue
  fi
  chmod -R u+w -- "$trash" 2>/dev/null
  if rm -rf -- "$trash" 2>/dev/null; then
   reclaimed=$((reclaimed + size)); removed=$((removed + 1))
  else
   reclaimed=$((reclaimed + size - $(allocated "$trash"))); kept=$((kept + 1)); note "$name: removal failed"
  fi
 done
fi
printf 'result %s %s %s %s\n' "$removed" "$kept" "$reclaimed" "$more"
free=$(free_bytes) || { printf 'error cannot measure free space\n'; exit 1; }
printf 'free %s\n' "$free"`
	output, err := runOutput(ctx, alias, script)
	if err != nil {
		return 0, result, fmt.Errorf("lab hosts: collect runs: %w", err)
	}
	free, collected, more := int64(-1), false, 0
	for line := range strings.Lines(output) {
		kind, value, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		switch kind {
		case "free":
			if free, err = strconv.ParseInt(value, 10, 64); err != nil {
				return 0, result, fmt.Errorf("lab hosts: collect runs: invalid free space %q", value)
			}
		case "result":
			if _, err := fmt.Sscanf(value, "%d %d %d %d", &result.Removed, &result.Kept, &result.Reclaimed, &more); err != nil {
				return 0, result, fmt.Errorf("lab hosts: collect runs: invalid result %q", value)
			}
			collected = true
		case "note":
			if len(result.Notes) < collectRunsNotes {
				result.Notes = append(result.Notes, value)
			}
		}
	}
	if more > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("and %d more", more))
	}
	if free < 0 || (!collected && free < minFree) {
		return 0, result, errors.New("lab hosts: collect runs: incomplete report")
	}
	return free, result, nil
}
