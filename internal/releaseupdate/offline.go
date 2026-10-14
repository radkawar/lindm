// SPDX-License-Identifier: Apache-2.0

package releaseupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	updatev1 "lindm/gen/lindm/update/v1"
)

const (
	maxOfflineRootTransitions = 1024
	maxOfflineTargets         = 4096
	maxOfflineRings           = 128
)

// ErrOfflineRollback reports an offline targets publication older than the
// site's currently published targets version.
var ErrOfflineRollback = errors.New("releaseupdate: offline_targets_rollback")

// OfflineExportConfig selects a verified station repository for an offline bundle.
type OfflineExportConfig struct {
	Source        string           // station repository (metadata/ + targets/) published by Publisher
	BootstrapRoot []byte           // authenticated root JSON that anchors Source
	Destination   string           // must not exist; created mode 0700
	Rings         []string         // channel catalogs to carry as proposals; each must exist in the verified rollout role
	Now           func() time.Time // nil = time.Now
}

// OfflineExport describes the verified station state written by ExportOffline.
type OfflineExport struct {
	FirstRootVersion, RootVersion, TargetsVersion int64
	Rings                                         []string
}

// OfflineImportConfig publishes an exported offline targets authority into a
// site repository using only online custody.
type OfflineImportConfig struct {
	Directory      string           // site published repository; absent/empty => initialized by this import
	Signers        RoleSigners      // site ONLINE custody only: Rollout, Snapshot, Timestamp (Root/Targets must be empty)
	BootstrapRoot  []byte           // authenticated site release root (from the verified execution bootstrap)
	Source         string           // directory produced by ExportOffline, already integrity-checked by caller
	TargetsVersion int64            // targets version named by the caller's signed bundle manifest
	Rings          []string         // proposals to publish (paused)
	Now            func() time.Time // nil = time.Now
}

// OfflineImport describes the site publication committed by ImportOffline.
type OfflineImport struct {
	RootVersion, TargetsVersion int64
	Unchanged                   bool                           // identical targets version+bytes already published; nothing committed
	Channels                    []*updatev1.AgentUpdateChannel // channels published paused by this import
}

type offlineRoot struct {
	version int64
	data    []byte
}

// ExportOffline verifies Source through the complete client refresh and writes
// only verified public files: the root chain from BootstrapRoot, the snapshot-bound
// targets metadata, every top-level target and the requested rollout catalogs.
// Destination is removed again when any verification or write fails.
func ExportOffline(ctx context.Context, cfg OfflineExportConfig) (result *OfflineExport, err error) {
	if cfg.Source == "" || !filepath.IsAbs(cfg.Destination) {
		return nil, errors.New("releaseupdate: offline export source and absolute destination required")
	}
	if err = validateOfflineRings(cfg.Rings); err != nil {
		return nil, err
	}
	if err = os.Mkdir(cfg.Destination, 0700); err != nil {
		return nil, fmt.Errorf("create offline export: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(cfg.Destination))
		}
	}()
	if err = syncDir(filepath.Dir(cfg.Destination)); err != nil {
		return nil, err
	}
	state, err := os.MkdirTemp("", "lindm-offline-export-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(state)) }()
	client, err := NewClient(ClientConfig{StateDir: state, BootstrapRoot: cfg.BootstrapRoot, Fetch: DirectoryFetch(cfg.Source), Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	checkpoint, err := client.loadState()
	if err != nil {
		return nil, err
	}
	update, err := client.refresh(ctx, checkpoint)
	if err != nil {
		return nil, fmt.Errorf("verify offline export source: %w", err)
	}
	trusted := update.GetTrustedMetadataSet()
	targets, rollout := trusted.Targets[metadata.TARGETS], trusted.Targets[rolloutRole]
	if trusted.Snapshot == nil || targets == nil || rollout == nil {
		return nil, errors.New("releaseupdate: incomplete verified offline export source")
	}
	if len(targets.Signed.Targets) > maxOfflineTargets {
		return nil, errors.New("releaseupdate: offline export target limit exceeded")
	}
	for _, dir := range []string{"metadata", "targets", "channels"} {
		if err = mkdirDurable(filepath.Join(cfg.Destination, dir), 0700); err != nil {
			return nil, err
		}
	}
	export := &Publisher{cfg: PublisherConfig{Directory: cfg.Destination}}
	first, err := exportRootChain(ctx, export, client.cfg.Fetch, cfg.BootstrapRoot, trusted.Root)
	if err != nil {
		return nil, err
	}
	targetsInfo := trusted.Snapshot.Signed.Meta["targets.json"]
	targetsName := fmt.Sprintf("metadata/%d.targets.json", targets.Signed.Version)
	if targetsInfo == nil || targetsInfo.Version != targets.Signed.Version {
		return nil, errors.New("releaseupdate: offline export targets binding mismatch")
	}
	targetsBytes, err := client.cfg.Fetch(ctx, targetsName, MaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	if err = verifyBoundMetadata(targetsInfo, targetsBytes); err != nil {
		return nil, err
	}
	if err = export.immutable(targetsName, targetsBytes); err != nil {
		return nil, err
	}
	source, err := os.OpenRoot(cfg.Source)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	for _, name := range slices.Sorted(maps.Keys(targets.Signed.Targets)) {
		info := targets.Signed.Targets[name]
		if info == nil {
			return nil, errors.New("releaseupdate: nil offline target")
		}
		info.Path = name
		if err = validTarget(info, MaxTargetBytes); err != nil {
			return nil, err
		}
		relative := "targets/" + hashPath(name, info.Hashes["sha256"])
		if err = copyVerifiedTarget(ctx, source, relative, filepath.Join(cfg.Destination, filepath.FromSlash(relative)), info); err != nil {
			return nil, fmt.Errorf("export target %s: %w", name, err)
		}
	}
	for _, ring := range cfg.Rings {
		data, err := exportChannel(source, client, targets, rollout, ring)
		if err != nil {
			return nil, fmt.Errorf("export channel %s: %w", ring, err)
		}
		if err = export.immutable("channels/"+ring+".json", data); err != nil {
			return nil, err
		}
	}
	return &OfflineExport{FirstRootVersion: first, RootVersion: trusted.Root.Signed.Version, TargetsVersion: targets.Signed.Version, Rings: slices.Clone(cfg.Rings)}, nil
}

// exportRootChain writes BootstrapRoot and every successor through the verified
// current root, re-verifying the exact transported bytes as a chain.
func exportRootChain(ctx context.Context, export *Publisher, fetch FetchFunc, bootstrap []byte, current *metadata.Metadata[metadata.RootType]) (int64, error) {
	chain, err := trustedmetadata.New(bootstrap)
	if err != nil {
		return 0, err
	}
	first := chain.Root.Signed.Version
	if current.Signed.Version < first || current.Signed.Version-first > maxOfflineRootTransitions {
		return 0, errors.New("releaseupdate: offline export root chain bound exceeded")
	}
	if err = export.immutable(fmt.Sprintf("metadata/%d.root.json", first), bootstrap); err != nil {
		return 0, err
	}
	for version := first + 1; version <= current.Signed.Version; version++ {
		name := fmt.Sprintf("metadata/%d.root.json", version)
		data, err := fetch(ctx, name, MaxMetadataBytes)
		if err != nil {
			return 0, err
		}
		if _, err = chain.UpdateRoot(data); err != nil {
			return 0, err
		}
		if err = validateRoot(chain.Root); err != nil {
			return 0, err
		}
		if err = export.immutable(name, data); err != nil {
			return 0, err
		}
	}
	expected, err := current.ToBytes(false)
	if err != nil {
		return 0, err
	}
	actual, err := chain.Root.ToBytes(false)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(expected, actual) {
		return 0, errors.New("releaseupdate: offline export root equivocation")
	}
	return first, nil
}

// exportChannel returns the exact rollout-authenticated catalog bytes for ring.
func exportChannel(source *os.Root, client *Client, targets, rollout *metadata.Metadata[metadata.TargetsType], ring string) ([]byte, error) {
	name := "channels/" + ring + ".json"
	info := rollout.Signed.Targets[name]
	if info == nil {
		return nil, ErrNotFound
	}
	info.Path = name
	if err := validTarget(info, MaxCatalogBytes); err != nil {
		return nil, err
	}
	data, err := readBounded(source, "targets/"+hashPath(name, info.Hashes["sha256"]), MaxCatalogBytes)
	if err != nil {
		return nil, err
	}
	if err = info.VerifyLengthHashes(data); err != nil {
		return nil, err
	}
	channel, err := decodeChannel(client.validator, data, client.cfg.Now())
	if err != nil {
		return nil, err
	}
	if channel.GetRing() != ring {
		return nil, errors.New("releaseupdate: offline channel binding mismatch")
	}
	if err = validateOfflineArtifacts(client.validator, targets, channel); err != nil {
		return nil, err
	}
	return data, nil
}

// ImportOffline publishes offline-signed targets into the site repository with
// online custody only. It verifies the root chain and targets signatures itself,
// rejects targets rollback/equivocation, and commits the targets together with
// paused channel proposals as a single timestamp.
func ImportOffline(ctx context.Context, cfg OfflineImportConfig) (result *OfflineImport, err error) {
	if len(cfg.Signers.Root) != 0 || len(cfg.Signers.Targets) != 0 {
		return nil, errors.New("releaseupdate: offline import accepts online custody only")
	}
	if cfg.Source == "" || cfg.TargetsVersion < 1 {
		return nil, errors.New("releaseupdate: offline import source and targets version required")
	}
	if err = validateOfflineRings(cfg.Rings); err != nil {
		return nil, err
	}
	p, err := publisherConfig(PublisherConfig{Directory: cfg.Directory, Signers: cfg.Signers, Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	lock, err := acquireLock(cfg.Directory)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	now := p.cfg.Now()
	start, current, err := p.offlineStart(cfg.BootstrapRoot)
	if err != nil {
		return nil, err
	}
	source, err := os.OpenRoot(cfg.Source)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	root, roots, err := applyOfflineRoots(source, start)
	if err != nil {
		return nil, err
	}
	siteRootVersion := roots[0].version
	if current != nil {
		// An initialized site already holds its own root files; persist successors only.
		roots = roots[1:]
	}
	if !now.Before(root.Signed.Expires) {
		return nil, errors.New("releaseupdate: offline root expired")
	}
	if err = validateSigners(root, cfg.Signers); err != nil {
		return nil, err
	}
	targets, targetBytes, err := readOfflineTargets(source, cfg.TargetsVersion)
	if err != nil {
		return nil, err
	}
	if current != nil {
		switch published := current.targets.Signed.Version; {
		case cfg.TargetsVersion < published:
			return nil, fmt.Errorf("import targets %d below published %d: %w", cfg.TargetsVersion, published, ErrOfflineRollback)
		case cfg.TargetsVersion == published && bytes.Equal(targetBytes, current.targetBytes):
			return &OfflineImport{RootVersion: siteRootVersion, TargetsVersion: published, Unchanged: true}, nil
		case cfg.TargetsVersion == published:
			return nil, errors.New("releaseupdate: offline targets equivocation")
		}
	}
	if err = verifyOfflineTargets(root, targets, cfg.Signers.Rollout, now); err != nil {
		return nil, err
	}
	pending := &publication{targets: targets, targetBytes: targetBytes}
	if current != nil {
		pending.rollout, pending.version = current.rollout, current.version
		if err = p.validateSiteChannels(current.rollout, targets, cfg.Rings); err != nil {
			return nil, err
		}
	} else {
		pending.rollout = metadata.Targets(now.Add(7 * 24 * time.Hour))
		pending.rollout.Signed.Version = 0
	}
	channels := make([]*updatev1.AgentUpdateChannel, 0, len(cfg.Rings))
	for _, ring := range cfg.Rings {
		channel, err := p.offlineProposal(source, pending.rollout, targets, ring, now)
		if err != nil {
			return nil, fmt.Errorf("import channel proposal %s: %w", ring, err)
		}
		channels = append(channels, channel)
	}
	for _, dir := range []string{"metadata", "targets"} {
		if err = mkdirDurable(filepath.Join(cfg.Directory, dir), 0700); err != nil {
			return nil, err
		}
	}
	if err = p.importOfflineTargets(ctx, source, targets); err != nil {
		return nil, err
	}
	for _, file := range roots {
		if err = p.immutable(fmt.Sprintf("metadata/%d.root.json", file.version), file.data); err != nil {
			return nil, err
		}
	}
	if err = p.immutable(fmt.Sprintf("metadata/%d.targets.json", cfg.TargetsVersion), targetBytes); err != nil {
		return nil, err
	}
	for _, channel := range channels {
		if err = p.stageChannel(ctx, pending, channel, nil, false); err != nil {
			return nil, err
		}
	}
	if err = p.commit(ctx, root, pending, false); err != nil {
		return nil, err
	}
	// Like RotateRoot, the convenience alias follows the commit: root() discovers
	// versioned successors and an uninitialized retry rewrites identical files.
	if len(roots) > 0 {
		if err = atomicWrite(filepath.Join(cfg.Directory, "metadata/root.json"), roots[len(roots)-1].data, 0600); err != nil {
			return nil, err
		}
	}
	return &OfflineImport{RootVersion: root.Signed.Version, TargetsVersion: cfg.TargetsVersion, Channels: channels}, nil
}

// offlineStart returns the trusted starting root and, for an initialized site,
// its verified current publication. A nil publication means uninitialized.
func (p *Publisher) offlineStart(bootstrap []byte) ([]byte, *publication, error) {
	_, err := os.Lstat(filepath.Join(p.cfg.Directory, "metadata/root.json"))
	if errors.Is(err, os.ErrNotExist) {
		if len(bootstrap) == 0 || int64(len(bootstrap)) > MaxMetadataBytes {
			return nil, nil, errors.New("releaseupdate: bootstrap root required for uninitialized site")
		}
		root, err := metadata.Root().FromBytes(bootstrap)
		if err != nil {
			return nil, nil, err
		}
		if err = validateRoot(root); err != nil {
			return nil, nil, err
		}
		if err = root.VerifyDelegate(metadata.ROOT, root); err != nil {
			return nil, nil, err
		}
		return bytes.Clone(bootstrap), nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	root, err := p.root()
	if err != nil {
		return nil, nil, fmt.Errorf("verify site root: %w", err)
	}
	current, err := p.current(root)
	if err != nil {
		return nil, nil, fmt.Errorf("verify site publication: %w", err)
	}
	data, err := root.ToBytes(false)
	if err != nil {
		return nil, nil, err
	}
	return data, current, nil
}

// applyOfflineRoots applies consecutive newer Source roots to start. The first
// returned entry is the start root; later entries are the exact applied bytes.
func applyOfflineRoots(source *os.Root, start []byte) (*metadata.Metadata[metadata.RootType], []offlineRoot, error) {
	chain, err := trustedmetadata.New(start)
	if err != nil {
		return nil, nil, err
	}
	roots := []offlineRoot{{version: chain.Root.Signed.Version, data: start}}
	for transitions := 0; ; transitions++ {
		name := fmt.Sprintf("metadata/%d.root.json", chain.Root.Signed.Version+1)
		data, err := readBounded(source, name, MaxMetadataBytes)
		if errors.Is(err, os.ErrNotExist) {
			return chain.Root, roots, nil
		}
		if err != nil {
			return nil, nil, err
		}
		if transitions == maxOfflineRootTransitions {
			return nil, nil, errors.New("releaseupdate: offline root chain bound exceeded")
		}
		if _, err = chain.UpdateRoot(data); err != nil {
			return nil, nil, fmt.Errorf("apply offline root %s: %w", name, err)
		}
		if err = validateRoot(chain.Root); err != nil {
			return nil, nil, err
		}
		roots = append(roots, offlineRoot{version: chain.Root.Signed.Version, data: data})
	}
}

func readOfflineTargets(source *os.Root, version int64) (*metadata.Metadata[metadata.TargetsType], []byte, error) {
	name := fmt.Sprintf("metadata/%d.targets.json", version)
	data, err := readBounded(source, name, MaxMetadataBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read offline targets: %w", err)
	}
	if err = metadataShape(name, data); err != nil {
		return nil, nil, err
	}
	targets, err := metadata.Targets().FromBytes(data)
	if err != nil {
		return nil, nil, err
	}
	if targets.Signed.Version != version {
		return nil, nil, errors.New("releaseupdate: offline targets version binding mismatch")
	}
	return targets, data, nil
}

// verifyOfflineTargets binds targets to the site root and requires the site's
// online rollout custody to satisfy the offline-signed rollout delegation.
func verifyOfflineTargets(root *metadata.Metadata[metadata.RootType], targets *metadata.Metadata[metadata.TargetsType], rollout []signature.Signer, now time.Time) error {
	if err := root.VerifyDelegate(metadata.TARGETS, targets); err != nil {
		return fmt.Errorf("verify offline targets: %w", err)
	}
	if !now.Before(targets.Signed.Expires) {
		return errors.New("releaseupdate: offline targets expired")
	}
	if err := validateRolloutDelegation(root, targets); err != nil {
		return err
	}
	role := targets.Signed.Delegations.Roles[0]
	return validateRoleSigners(role.KeyIDs, role.Threshold, rollout)
}

// validateSiteChannels keeps every site channel that this import does not
// replace consistent with the new offline release authority.
func (p *Publisher) validateSiteChannels(rollout, targets *metadata.Metadata[metadata.TargetsType], replaced []string) error {
	for _, name := range slices.Sorted(maps.Keys(rollout.Signed.Targets)) {
		ring := strings.TrimSuffix(strings.TrimPrefix(name, "channels/"), ".json")
		if slices.Contains(replaced, ring) {
			continue
		}
		channel, err := p.channel(rollout, ring)
		if err != nil {
			return err
		}
		if err = validateOfflineArtifacts(p.validator, targets, channel); err != nil {
			return fmt.Errorf("site channel %s: %w", ring, err)
		}
	}
	return nil
}

// offlineProposal re-issues a station catalog as a paused site channel. Only
// its artifacts are retained; the station's validity window may have lapsed.
func (p *Publisher) offlineProposal(source *os.Root, rollout, targets *metadata.Metadata[metadata.TargetsType], ring string, now time.Time) (*updatev1.AgentUpdateChannel, error) {
	data, err := readBounded(source, "channels/"+ring+".json", MaxCatalogBytes)
	if err != nil {
		return nil, err
	}
	channel := new(updatev1.AgentUpdateChannel)
	if err = protojson.Unmarshal(data, channel); err != nil {
		return nil, err
	}
	if channel.GetRing() != ring {
		return nil, errors.New("releaseupdate: offline channel binding mismatch")
	}
	generation := channel.GetGeneration()
	existing, err := p.channel(rollout, ring)
	if err == nil {
		generation = max(generation, existing.GetGeneration())
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if generation == math.MaxUint64 {
		return nil, errors.New("releaseupdate: channel generation exhausted")
	}
	expires := now.Add(7 * 24 * time.Hour)
	if targets.Signed.Expires.Before(expires) {
		expires = targets.Signed.Expires
	}
	channel.Generation = generation + 1
	channel.Paused = true
	channel.EligiblePercentage = 0
	channel.RolloutRequestId = ""
	channel.IssuedAt = timestamppb.New(now)
	channel.ExpiresAt = timestamppb.New(expires)
	if err = validateChannel(p.validator, channel, now); err != nil {
		return nil, err
	}
	if err = validateOfflineArtifacts(p.validator, targets, channel); err != nil {
		return nil, err
	}
	return channel, nil
}

// importOfflineTargets copies every top-level target that the site does not
// already hold byte-for-byte. Nothing is referenced until commit.
func (p *Publisher) importOfflineTargets(ctx context.Context, source *os.Root, targets *metadata.Metadata[metadata.TargetsType]) (err error) {
	site, err := os.OpenRoot(p.cfg.Directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, site.Close()) }()
	for _, name := range slices.Sorted(maps.Keys(targets.Signed.Targets)) {
		info := targets.Signed.Targets[name]
		info.Path = name
		if err = validTarget(info, MaxTargetBytes); err != nil {
			return err
		}
		relative := "targets/" + hashPath(name, info.Hashes["sha256"])
		same, err := sameTarget(ctx, site, relative, info)
		if err != nil {
			return err
		}
		if same {
			continue
		}
		if err = copyVerifiedTarget(ctx, source, relative, filepath.Join(p.cfg.Directory, filepath.FromSlash(relative)), info); err != nil {
			return fmt.Errorf("import target %s: %w", name, err)
		}
	}
	return nil
}

func validateOfflineRings(rings []string) error {
	if len(rings) > maxOfflineRings {
		return errors.New("releaseupdate: offline ring bound exceeded")
	}
	seen := make(map[string]bool, len(rings))
	for _, ring := range rings {
		if strings.Contains(ring, "/") || !safeTargetPath("channels/"+ring+".json") || seen[ring] {
			return fmt.Errorf("releaseupdate: invalid or duplicate offline ring %q", ring)
		}
		seen[ring] = true
	}
	return nil
}

// verifyBoundMetadata requires a SHA-256 snapshot binding, so re-read bytes are
// exactly those the client refresh verified.
func verifyBoundMetadata(info *metadata.MetaFiles, data []byte) error {
	if info.Length < 1 || len(info.Hashes) != 1 || len(info.Hashes["sha256"]) != sha256.Size {
		return errors.New("releaseupdate: unbound offline metadata")
	}
	return info.VerifyLengthHashes(data)
}

func copyVerifiedTarget(ctx context.Context, source *os.Root, relative, destination string, info *metadata.TargetFiles) (err error) {
	if err = mkdirDurable(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	input, err := openRegular(source, relative)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	return copyTarget(ctx, input, destination, info.Length, info.Hashes["sha256"])
}

// sameTarget reports whether name already holds exactly the descriptor bytes.
func sameTarget(ctx context.Context, root *os.Root, name string, info *metadata.TargetFiles) (same bool, err error) {
	file, err := openRegular(root, name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	st, err := file.Stat()
	if err != nil || st.Size() != info.Length {
		return false, err
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(contextReader{ctx, file}, info.Length+1))
	if err != nil {
		return false, err
	}
	return n == info.Length && bytes.Equal(hash.Sum(nil), info.Hashes["sha256"]), nil
}
