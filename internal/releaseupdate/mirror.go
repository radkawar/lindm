package releaseupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// OpenTargetFunc returns a streaming transport for the exact hash-prefixed path.
// The mirror verifies its length/hash before publishing any new timestamp.
type OpenTargetFunc func(context.Context, string) (io.ReadCloser, error)
type MirrorConfig struct {
	Directory     string
	BootstrapRoot []byte
	Fetch         FetchFunc
	OpenTarget    OpenTargetFunc
}

// Mirror copies only verified public files and retains a protected high-water
// checkpoint within the destination. Offline transports never bypass freshness.
func Mirror(ctx context.Context, cfg MirrorConfig) (err error) {
	if cfg.OpenTarget == nil {
		return errors.New("releaseupdate: streaming target transport required")
	}
	if err = ownedDirectory(cfg.Directory); err != nil {
		return err
	}
	lock, err := acquireLock(cfg.Directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	client, err := NewClient(ClientConfig{StateDir: filepath.Join(cfg.Directory, ".mirror-state"), BootstrapRoot: cfg.BootstrapRoot, Fetch: cfg.Fetch})
	if err != nil {
		return err
	}
	state, err := client.loadState()
	if err != nil {
		return err
	}
	update, err := client.refresh(ctx, state)
	if err != nil {
		return err
	}
	trusted := update.GetTrustedMetadataSet()
	if len(trusted.Targets[metadata.TARGETS].Signed.Targets) > 4096 {
		return errors.New("releaseupdate: mirror target limit exceeded")
	}
	for _, dir := range []string{"metadata", "targets"} {
		if err = mkdirDurable(filepath.Join(cfg.Directory, dir), 0700); err != nil {
			return err
		}
	}
	publisher := &Publisher{cfg: PublisherConfig{Directory: cfg.Directory}}
	// Carry the entire root transition chain so pre-rotation installations can
	// update from this mirror without contacting the original repository.
	chain, err := trustedmetadata.New(cfg.BootstrapRoot)
	if err != nil {
		return err
	}
	rootBytes := cfg.BootstrapRoot
	if err = publisher.immutable(fmt.Sprintf("metadata/%d.root.json", chain.Root.Signed.Version), rootBytes); err != nil {
		return err
	}
	if trusted.Root.Signed.Version-chain.Root.Signed.Version > 1024 {
		return errors.New("releaseupdate: mirror root chain bound exceeded")
	}
	for version := chain.Root.Signed.Version + 1; version <= trusted.Root.Signed.Version; version++ {
		rootBytes, err = cfg.Fetch(ctx, fmt.Sprintf("metadata/%d.root.json", version), MaxMetadataBytes)
		if err != nil {
			return err
		}
		if int64(len(rootBytes)) > MaxMetadataBytes {
			return errors.New("releaseupdate: oversized root")
		}
		if _, err = chain.UpdateRoot(rootBytes); err != nil {
			return err
		}
		if err = validateRoot(chain.Root); err != nil {
			return err
		}
		if err = publisher.immutable(fmt.Sprintf("metadata/%d.root.json", version), rootBytes); err != nil {
			return err
		}
	}
	expected, err := trusted.Root.ToBytes(false)
	if err != nil {
		return err
	}
	actual, err := chain.Root.ToBytes(false)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, actual) {
		return errors.New("releaseupdate: mirror root equivocation")
	}
	snapshotInfo := trusted.Timestamp.Signed.Meta["snapshot.json"]
	snapshotBytes, err := cfg.Fetch(ctx, fmt.Sprintf("metadata/%d.snapshot.json", snapshotInfo.Version), MaxMetadataBytes)
	if err != nil {
		return err
	}
	if int64(len(snapshotBytes)) > MaxMetadataBytes {
		return errors.New("releaseupdate: oversized snapshot")
	}
	if err = snapshotInfo.VerifyLengthHashes(snapshotBytes); err != nil {
		return err
	}
	targetsInfo := trusted.Snapshot.Signed.Meta["targets.json"]
	targetsBytes, err := cfg.Fetch(ctx, fmt.Sprintf("metadata/%d.targets.json", targetsInfo.Version), MaxMetadataBytes)
	if err != nil {
		return err
	}
	if int64(len(targetsBytes)) > MaxMetadataBytes {
		return errors.New("releaseupdate: oversized targets")
	}
	if err = targetsInfo.VerifyLengthHashes(targetsBytes); err != nil {
		return err
	}
	rolloutInfo := trusted.Snapshot.Signed.Meta["rollout.json"]
	rolloutBytes, err := cfg.Fetch(ctx, fmt.Sprintf("metadata/%d.rollout.json", rolloutInfo.Version), MaxMetadataBytes)
	if err != nil {
		return err
	}
	if int64(len(rolloutBytes)) > MaxMetadataBytes {
		return errors.New("releaseupdate: oversized rollout")
	}
	if err = rolloutInfo.VerifyLengthHashes(rolloutBytes); err != nil {
		return err
	}
	for _, role := range []string{metadata.TARGETS, rolloutRole} {
		for name, info := range trusted.Targets[role].Signed.Targets {
			info.Path = name
			if err = validTarget(info, MaxTargetBytes); err != nil {
				return err
			}
			relative := "targets/" + hashPath(name, info.Hashes["sha256"])
			destination := filepath.Join(cfg.Directory, filepath.FromSlash(relative))
			if err = mkdirDurable(filepath.Dir(destination), 0700); err != nil {
				return err
			}
			source, openErr := cfg.OpenTarget(ctx, relative)
			if openErr != nil {
				return openErr
			}
			if source == nil {
				return errors.New("releaseupdate: missing target stream")
			}
			copyErr := copyTarget(ctx, source, destination, info.Length, info.Hashes["sha256"])
			if err = errors.Join(copyErr, source.Close()); err != nil {
				return err
			}
			if role == rolloutRole {
				data, err := publisher.read(relative, MaxCatalogBytes)
				if err != nil {
					return err
				}
				channel, err := decodeChannel(client.validator, data, client.cfg.Now())
				if err != nil {
					return err
				}
				if name != "channels/"+channel.GetRing()+".json" {
					return errors.New("releaseupdate: mirror channel binding mismatch")
				}
				if err = validateOfflineArtifacts(client.validator, trusted.Targets[metadata.TARGETS], channel); err != nil {
					return err
				}
			}
		}
	}
	if err = publisher.immutable(fmt.Sprintf("metadata/%d.rollout.json", rolloutInfo.Version), rolloutBytes); err != nil {
		return err
	}
	if err = publisher.immutable(fmt.Sprintf("metadata/%d.targets.json", targetsInfo.Version), targetsBytes); err != nil {
		return err
	}
	if err = publisher.immutable(fmt.Sprintf("metadata/%d.snapshot.json", snapshotInfo.Version), snapshotBytes); err != nil {
		return err
	}
	if err = atomicWrite(filepath.Join(cfg.Directory, "metadata/root.json"), rootBytes, 0600); err != nil {
		return err
	}
	timestampBytes, err := trusted.Timestamp.ToBytes(false)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(cfg.Directory, "metadata/timestamp.json"), timestampBytes, 0600)
}
