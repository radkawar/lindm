// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/vmlab"
	"lindm/internal/vmlab/reposnapshot"
)

func collectRepositorySnapshot(ctx context.Context, alias, remoteBinary, remoteCache, cache, record string, stderr io.Writer) error {
	f, err := os.Open(record)
	if err != nil {
		return err
	}
	b, readErr := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(b) > 1<<20 {
		return errors.New("snapshot record exceeds bound")
	}
	var evidence struct {
		Digest string `json:"repository_snapshot_manifest_sha256"`
	}
	if err := json.Unmarshal(b, &evidence); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(evidence.Digest)
	if err != nil || len(decoded) != 32 || evidence.Digest != strings.ToLower(evidence.Digest) {
		return errors.New("missing snapshot evidence content address")
	}
	if err := vmlab.InitializeImageCache(ctx, cache); err != nil {
		return err
	}
	transferCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := "exec " + QuoteShell(remoteBinary) + " images snapshot-export -cache " + QuoteShell(remoteCache) + " -sha256 " + QuoteShell(evidence.Digest)
	cmd := executionCommand(transferCtx, alias, command)
	cmd.Stderr = stderr
	stream, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return errors.Join(err, stream.Close())
	}
	importErr := reposnapshot.Import(transferCtx, cache, evidence.Digest, stream)
	if importErr != nil {
		cancel()
	}
	closeErr = stream.Close()
	return errors.Join(importErr, closeErr, cmd.Wait(), ctx.Err())
}

// stageRepositorySnapshot admits only authenticated, bounded manifest files to
// the selected host's persistent cache. Captures are portable between hosts;
// there is no dependency on scheduling a replay back onto its capture host.
// A host whose cache already authenticates the exact closure keeps it: every
// lane otherwise streamed the full multi-GiB closure again, and concurrent
// lanes saturated the controller link until SSH keepalives failed (observed).
func stageRepositorySnapshot(ctx context.Context, alias, remoteBinary, remoteCache, cache, digest string, stderr io.Writer) error {
	present := executionCommand(ctx, alias, "exec "+QuoteShell(remoteBinary)+" images snapshot-present -cache "+QuoteShell(remoteCache)+" -sha256 "+QuoteShell(digest))
	if present.Run() == nil {
		_, err := fmt.Fprintf(stderr, "lab host %s: repository closure %s already authenticated in host cache\n", alias, digest)
		return err
	}
	transferCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := "exec " + QuoteShell(remoteBinary) + " images snapshot-import -cache " + QuoteShell(remoteCache) + " -sha256 " + QuoteShell(digest)
	cmd := executionCommand(transferCtx, alias, command)
	cmd.Stdout, cmd.Stderr = stderr, stderr
	stream, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return errors.Join(err, stream.Close())
	}
	exportErr := reposnapshot.Export(transferCtx, cache, digest, stream)
	closeErr := stream.Close()
	if exportErr != nil {
		cancel()
	}
	return errors.Join(exportErr, closeErr, cmd.Wait(), ctx.Err())
}

// stageRepositoryMetadata streams only the authenticated finite metadata set.
// A retained directory is not an authority to recursively copy cache contents.
func (s *remoteStage) stageRepositoryMetadata(image *labv1.ImageManifest, args []string, retained string) error {
	options := reposnapshot.CaptureOptions{
		Cache: filepath.Join(s.local, "metadata-export"), RetainedMetadata: retained,
		Distribution: image.GetDistribution(), Architecture: image.GetArchitecture(),
		Date: FlagValue(args, "snapshot-date"), RepomdSHA256: FlagValue(args, "repomd-sha256"),
		BaseImageSHA256: image.GetSha256(), MaxBytes: 512 << 20, MaxPackages: reposnapshot.HardMaxPackages,
	}
	return reposnapshot.ExportMetadata(s.ctx, options, func(item *labv1.RepositorySnapshotFile, payload io.Reader) error {
		destination := filepath.Join(s.remote, "snapshot-metadata", filepath.FromSlash(item.GetPath()))
		command := "set -euC; umask 077; mkdir -p -- " + QuoteShell(filepath.Dir(destination)) +
			"; cat > " + QuoteShell(destination) + "; chmod 0400 -- " + QuoteShell(destination)
		cmd := executionCommand(s.ctx, s.alias, command)
		cmd.Stdin = io.LimitReader(payload, int64(item.GetSizeBytes()))
		cmd.Stdout, cmd.Stderr = s.stderr, s.stderr
		return cmd.Run()
	})
}
