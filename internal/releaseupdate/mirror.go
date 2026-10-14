// SPDX-License-Identifier: Apache-2.0

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
	rootBytes, err := mirrorRootChain(ctx, cfg, publisher, &trusted)
	if err != nil {
		return err
	}
	snapshotInfo := trusted.Timestamp.Signed.Meta["snapshot.json"]
	snapshotBytes, err := fetchMirrorMetadata(ctx, cfg.Fetch, "snapshot", snapshotInfo)
	if err != nil {
		return err
	}
	targetsInfo := trusted.Snapshot.Signed.Meta["targets.json"]
	targetsBytes, err := fetchMirrorMetadata(ctx, cfg.Fetch, "targets", targetsInfo)
	if err != nil {
		return err
	}
	rolloutInfo := trusted.Snapshot.Signed.Meta["rollout.json"]
	rolloutBytes, err := fetchMirrorMetadata(ctx, cfg.Fetch, "rollout", rolloutInfo)
	if err != nil {
		return err
	}
	if err = mirrorTargets(ctx, cfg, client, publisher, &trusted); err != nil {
		return err
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

// mirrorRootChain publishes the entire root transition chain from the bootstrap
// root to the trusted root, so pre-rotation installations can update from this
// mirror without contacting the original repository. It returns the newest root.
func mirrorRootChain(ctx context.Context, cfg MirrorConfig, publisher *Publisher, trusted *trustedmetadata.TrustedMetadata) ([]byte, error) {
	chain, err := trustedmetadata.New(cfg.BootstrapRoot)
	if err != nil {
		return nil, err
	}
	rootBytes := cfg.BootstrapRoot
	if err = publisher.immutable(fmt.Sprintf("metadata/%d.root.json", chain.Root.Signed.Version), rootBytes); err != nil {
		return nil, err
	}
	if trusted.Root.Signed.Version-chain.Root.Signed.Version > 1024 {
		return nil, errors.New("releaseupdate: mirror root chain bound exceeded")
	}
	for version := chain.Root.Signed.Version + 1; version <= trusted.Root.Signed.Version; version++ {
		rootBytes, err = cfg.Fetch(ctx, fmt.Sprintf("metadata/%d.root.json", version), MaxMetadataBytes)
		if err != nil {
			return nil, err
		}
		if int64(len(rootBytes)) > MaxMetadataBytes {
			return nil, errors.New("releaseupdate: oversized root")
		}
		if _, err = chain.UpdateRoot(rootBytes); err != nil {
			return nil, err
		}
		if err = validateRoot(chain.Root); err != nil {
			return nil, err
		}
		if err = publisher.immutable(fmt.Sprintf("metadata/%d.root.json", version), rootBytes); err != nil {
			return nil, err
		}
	}
	expected, err := trusted.Root.ToBytes(false)
	if err != nil {
		return nil, err
	}
	actual, err := chain.Root.ToBytes(false)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(expected, actual) {
		return nil, errors.New("releaseupdate: mirror root equivocation")
	}
	return rootBytes, nil
}

// fetchMirrorMetadata fetches one versioned role file and verifies it against
// the trusted length and hashes.
func fetchMirrorMetadata(ctx context.Context, fetch FetchFunc, role string, info *metadata.MetaFiles) ([]byte, error) {
	data, err := fetch(ctx, fmt.Sprintf("metadata/%d.%s.json", info.Version, role), MaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxMetadataBytes {
		return nil, errors.New("releaseupdate: oversized " + role)
	}
	if err = info.VerifyLengthHashes(data); err != nil {
		return nil, err
	}
	return data, nil
}

// mirrorTargets streams every trusted target into its hash-prefixed path,
// verifying length and hash, and checks each rollout channel's binding and
// offline artifacts.
func mirrorTargets(ctx context.Context, cfg MirrorConfig, client *Client, publisher *Publisher, trusted *trustedmetadata.TrustedMetadata) error {
	for _, role := range []string{metadata.TARGETS, rolloutRole} {
		for name, info := range trusted.Targets[role].Signed.Targets {
			info.Path = name
			if err := validTarget(info, MaxTargetBytes); err != nil {
				return err
			}
			relative := "targets/" + hashPath(name, info.Hashes["sha256"])
			destination := filepath.Join(cfg.Directory, filepath.FromSlash(relative))
			if err := mkdirDurable(filepath.Dir(destination), 0700); err != nil {
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
			if err := errors.Join(copyErr, source.Close()); err != nil {
				return err
			}
			if role != rolloutRole {
				continue
			}
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
	return nil
}
