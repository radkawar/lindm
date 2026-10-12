package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab/worktree"
	"lindm/internal/diskgc"
	"lindm/internal/labhost"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
)

const gcUsage = `Usage: go run ./cmd/dev gc [-dry-run] [-build-cache-age D] [-quiet D] [-matrix-root DIR] [-spark-min-free BYTES]

Reclaim disk space on this workstation, printing the bytes reclaimed per class:

  go-build-cache  Go build cache entries untouched for -build-cache-age (6h).
  matrix-inputs   inputs/ of finished lab matrix runs under -matrix-root
                  (~/.cache/lindm-matrix); records, logs and evidence stay.
  worktrees       dev worktree prune: clean merged (or audited LANDED or
                  SNAPSHOT) private worktrees no process uses, archived first.
  lab-runs        stale lane scratch (lindm-*) and run directories (runs/run-*)
                  in local lab hosts' work directories.
  lab-images      cached lab images, repository closures, installed images and
                  goldens no image manifest on main or a live worktree, nor the
                  registry, references, unless locked, open or pinned.
  remote-runs     stale runs/run-* on SSH lab hosts, only on a host whose work
                  directory has less than -spark-min-free (300 GiB) free.

A run directory is stale when no live process uses or names it and nothing in
it changed within -quiet (1h). Cache entries are removed under the flock their
lab readers take. Idempotent; concurrent runs and builds are safe. dev land
runs it when the shared checkout's filesystem has under 200 GiB free, and lab
admission runs the host classes before refusing a lane for lack of disk.
`

// landGCThreshold is the free space below which dev land collects first.
const landGCThreshold = 200 << 30

// gcOptions selects what one gc run removes.
type gcOptions struct {
	dryRun        bool
	buildCacheAge time.Duration
	quiet         time.Duration
	matrixRoot    string
	sparkMinFree  int64
}

func defaultGCOptions() (gcOptions, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return gcOptions{}, err
	}
	return gcOptions{buildCacheAge: diskgc.DefaultBuildCacheAge, quiet: diskgc.DefaultQuiet, matrixRoot: filepath.Join(cache, "lindm-matrix"), sparkMinFree: 300 << 30}, nil
}

func runGC(args []string) error {
	options, err := defaultGCOptions()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("gc", flag.ContinueOnError)
	flags.BoolVar(&options.dryRun, "dry-run", false, "report what would be removed")
	flags.DurationVar(&options.buildCacheAge, "build-cache-age", options.buildCacheAge, "keep Go build cache entries used within this")
	flags.DurationVar(&options.quiet, "quiet", options.quiet, "keep run directories changed within this")
	flags.StringVar(&options.matrixRoot, "matrix-root", options.matrixRoot, "directory holding lab matrix run directories")
	flags.Int64Var(&options.sparkMinFree, "spark-min-free", options.sparkMinFree, "collect an SSH lab host's runs only below this many free bytes")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), gcUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	if flags.NArg() != 0 || options.quiet <= 0 || options.sparkMinFree < 0 {
		return errors.New("gc takes no positional arguments, a positive -quiet and a non-negative -spark-min-free")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	repo, err := worktree.Open(ctx, ".")
	if err != nil {
		return err
	}
	return collect(ctx, repo, options)
}

// collect runs every class once, reporting each, and returns their joined
// failures; one class failing never stops the others.
func collect(ctx context.Context, repo *worktree.Repository, options gcOptions) error {
	unlock, ok, err := gcLock()
	if err != nil {
		return err
	}
	if !ok {
		_, err := fmt.Println("gc: another gc is running; skipped")
		return err
	}
	defer unlock()
	before, _ := diskgc.Free(repo.Main)
	var total int64
	var failures []error
	report := func(result diskgc.Result, err error) {
		total += result.Reclaimed
		fmt.Println("gc: " + result.String())
		if err != nil {
			fmt.Printf("gc: %s: %v\n", result.Class, err)
			failures = append(failures, fmt.Errorf("%s: %w", result.Class, err))
		}
	}
	if cache, err := diskgc.GoBuildCache(ctx); err != nil {
		report(diskgc.Result{Class: "go-build-cache"}, err)
	} else {
		report(diskgc.BuildCache(ctx, cache, options.buildCacheAge, options.dryRun))
	}
	report(diskgc.MatrixInputs(ctx, options.matrixRoot, options.quiet, options.dryRun))
	report(pruneMerged(ctx, repo, options.dryRun))
	config, err := labhost.Load()
	if err != nil {
		report(diskgc.Result{Class: "lab-runs"}, err)
	}
	var local []string
	var remote []*labv1.LabHost
	for _, host := range config.GetHosts() {
		if host.GetTransport() != "local" {
			remote = append(remote, host)
			continue
		}
		work, err := labhost.ResolveWorkDirectory(host)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		local = append(local, work)
	}
	report(diskgc.LabRuns(ctx, local, options.quiet, options.dryRun))
	caches, referenced, err := imageCaches(ctx, repo, local)
	if err != nil {
		report(diskgc.Result{Class: "lab-images"}, err)
	} else {
		report(diskgc.Images(ctx, caches, referenced, options.dryRun))
	}
	for _, host := range remote {
		free, result, err := labhost.CollectRemoteRuns(ctx, host, options.sparkMinFree, options.quiet, options.dryRun)
		result.Class = "remote-runs " + host.GetName()
		if err == nil && free >= options.sparkMinFree {
			result.Notes = append(result.Notes, fmt.Sprintf("%s free, above the %s threshold", diskgc.Size(free), diskgc.Size(options.sparkMinFree)))
		}
		report(result, err)
	}
	after, _ := diskgc.Free(repo.Main)
	verb := "reclaimed"
	if options.dryRun {
		verb = "would reclaim"
	}
	fmt.Printf("gc: %s %s in total; %s free on %s (was %s)\n", verb, diskgc.Size(total), diskgc.Size(after), repo.Main, diskgc.Size(before))
	return errors.Join(failures...)
}

// gcLock serializes gc runs on this host, so concurrent triggers (several
// landings, lab admission) do not repeat the same scans.
func gcLock() (unlock func(), ok bool, err error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, false, err
	}
	file, err := os.OpenFile(filepath.Join(cache, "lindm-gc.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() { _ = file.Close() }, true, nil
}

// pruneMerged runs dev worktree prune with its defaults: landed trees go,
// archived first; unlanded or used trees stay.
func pruneMerged(ctx context.Context, repo *worktree.Repository, dryRun bool) (diskgc.Result, error) {
	result := diskgc.Result{Class: "worktrees"}
	err := repo.Prune(ctx, nil, worktree.PruneOptions{DryRun: dryRun, Now: time.Now()}, func(decision worktree.Decision) error {
		if !decision.Removed {
			result.Kept++
			return nil
		}
		result.Removed++
		if decision.Status != nil {
			result.Reclaimed += decision.Status.Bytes
		}
		return nil
	})
	return result, err
}

// imageCaches returns the lab image and golden caches of the shared checkout,
// every live worktree and the local lab work directories, and the digests
// that image manifests there and the platform registry reference. Every
// SHA-256 anywhere in a manifest counts as referenced, so a manifest of an
// older schema (a stale worktree's) still protects its image and closure; an
// unreadable manifest directory fails the class, since what it references is
// unknown.
func imageCaches(ctx context.Context, repo *worktree.Repository, workDirs []string) ([]string, map[string]bool, error) {
	entries, err := repo.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	roots := []string{repo.Main}
	for _, entry := range entries {
		if !entry.Missing {
			roots = append(roots, entry.Path)
		}
	}
	referenced := map[string]bool{}
	var caches []string
	for _, root := range roots {
		if err := manifestDigests(filepath.Join(root, labmatrix.ImagesDir), referenced); err != nil {
			return nil, nil, fmt.Errorf("image references in %s: %w", root, err)
		}
		caches = append(caches, filepath.Join(root, ".cache", "lab", "images"), filepath.Join(root, ".cache", "lab", "encrypted"))
	}
	for _, release := range platform.Releases() {
		for _, target := range release.Lab.OSUpdateTargets {
			if target.ClosureSHA256 != "" {
				referenced[target.ClosureSHA256] = true
			}
		}
	}
	for _, work := range workDirs {
		caches = append(caches, filepath.Join(work, "images"), filepath.Join(work, "encrypted"))
	}
	return caches, referenced, nil
}

var sha256Hex = regexp.MustCompile(`[0-9a-f]{64}`)

// maxManifestBytes bounds one image manifest read for references.
const maxManifestBytes = 1 << 20

// manifestDigests adds every SHA-256 in dir's image manifests to referenced.
func manifestDigests(dir string, referenced map[string]bool) error {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
		if err := errors.Join(err, file.Close()); err != nil {
			return err
		}
		if len(data) > maxManifestBytes {
			return fmt.Errorf("%s exceeds %d bytes", path, maxManifestBytes)
		}
		for _, digest := range sha256Hex.FindAll(bytes.ToLower(data), -1) {
			referenced[string(digest)] = true
		}
	}
	return nil
}

// collectIfLow runs gc before a landing when the shared checkout's filesystem
// is short of space; gc failures are reported, never fatal to the landing.
func collectIfLow(ctx context.Context, repo *worktree.Repository) {
	free, err := diskgc.Free(repo.Main)
	if err != nil || free >= landGCThreshold {
		return
	}
	fmt.Printf("land: %s free on %s (under %s); running dev gc first\n", diskgc.Size(free), repo.Main, diskgc.Size(landGCThreshold))
	options, err := defaultGCOptions()
	if err == nil {
		err = collect(ctx, repo, options)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "land: gc incomplete (landing continues): %v\n", err)
	}
}
