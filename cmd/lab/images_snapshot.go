package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"lindm/internal/vmlab"
	"lindm/internal/vmlab/reposnapshot"
)

func runImageSnapshot(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("images snapshot", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "pinned native base ImageManifest")
	cache := flags.String("cache", ".cache/lab/images", "verified image and repository closure cache")
	snapshotCache := flags.String("snapshot-cache", "", "repository cache (default: image cache)")
	date := flags.String("snapshot-date", "", "required authenticated YYYY-MM-DD repository snapshot")
	digest := flags.String("repomd-sha256", "", "required exact signed repomd SHA256")
	retained := flags.String("retained-metadata", "", "optional retained signed metadata directory; all bytes reauthenticated")
	maxBytes := flags.Uint64("max-bytes", 4<<30, "aggregate closure byte ceiling (maximum 16 GiB)")
	maxPackages := flags.Uint("max-packages", 2500, "native solver package ceiling (maximum 5000)")
	work := flags.String("work-dir", "", "disposable admitted VM parent")
	diagnostics := flags.String("diagnostics", "", "existing private directory for native solver failure evidence")
	record := flags.String("record", "", "required new native acquisition evidence JSON file")
	flags.String("repo", ".", "checkout used for remote native driver build")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *date == "" || *digest == "" || *record == "" || *maxPackages > uint(reposnapshot.HardMaxPackages) {
		return errors.New("images snapshot requires -manifest, -snapshot-date, -repomd-sha256, -record and explicit bounded native closure inputs")
	}
	image, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	if *snapshotCache == "" {
		*snapshotCache = *cache
	}
	result, err := vmlab.CaptureRepositorySnapshot(ctx, image, vmlab.RepositorySnapshotOptions{CacheDir: *cache, WorkDir: *work, DiagnosticsDir: *diagnostics, Hardware: hardware.options(), Capture: reposnapshot.CaptureOptions{Cache: *snapshotCache, RetainedMetadata: *retained, Date: *date, RepomdSHA256: *digest, MaxBytes: *maxBytes, MaxPackages: uint32(*maxPackages)}})
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, map[string]any{
		"distribution": result.Distribution, "architecture": result.Architecture, "repository_snapshot_date": result.SnapshotDate,
		"repository_snapshot_manifest_sha256": result.ManifestSha256, "repository_snapshot_repomd_sha256": result.RepomdSha256,
		"repository_snapshot_root": filepath.Join(*snapshotCache, "repository-snapshots", "sha256", result.ManifestSha256, "repository"),
		"total_bytes":              result.TotalBytes, "retained_files": len(result.Files), "solver_version": result.SolverVersion,
	})
}

// Snapshot transfer is a bounded cache operation, not a guest lane. Both ends
// authenticate the same manifest; stdout is exclusively the binary stream.
func runSnapshotTransfer(ctx context.Context, operation string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("images "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	cache := flags.String("cache", "", "repository snapshot cache")
	digest := flags.String("sha256", "", "exact repository closure content address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *cache == "" || *digest == "" {
		return errors.New("snapshot transfer requires -cache and -sha256, without positional arguments")
	}
	switch operation {
	case "snapshot-export":
		return reposnapshot.Export(ctx, *cache, *digest, stdout)
	case "snapshot-import":
		if err := vmlab.InitializeImageCache(ctx, *cache); err != nil {
			return err
		}
		return reposnapshot.Import(ctx, *cache, *digest, stdin)
	default:
		return errors.New("unsupported snapshot transfer operation")
	}
}
