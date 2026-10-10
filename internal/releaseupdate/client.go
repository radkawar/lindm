package releaseupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	updatev1 "lindm/gen/lindm/update/v1"
)

// FetchFunc only transports requested repository-relative bytes. A missing file
// must return ErrNotFound; all other transport failures remain fatal.
type FetchFunc func(context.Context, string, int64) ([]byte, error)
type ClientConfig struct {
	StateDir      string
	BootstrapRoot []byte
	Fetch         FetchFunc
	Now           func() time.Time
}
type Client struct {
	cfg       ClientConfig
	validator protovalidate.Validator
	mu        sync.Mutex
}
type SelectionRequest struct {
	Ring, DeviceID, CurrentVersion, Architecture, PackageFormat string
	ProtocolVersion                                             uint32
}

// Selection exposes transport hints, not writable authority. Stage uses the
// private signed descriptor and rejects selections from another Client.
type Selection struct {
	Artifact        *updatev1.AgentUpdateArtifact
	TargetPath      string
	Length          int64
	SHA256          string
	SignaturePath   string
	SignatureLength int64
	SignatureSHA256 string
	owner           *Client
	target          *metadata.TargetFiles
	signature       *metadata.TargetFiles
	expires         time.Time
}

// Deadline returns the immutable earliest expiry of the verified catalog and
// metadata chain. Streaming transports must apply it to their own Read context;
// an io.Reader cannot be forcibly interrupted by Stage.
func (s *Selection) Deadline() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.expires
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Fetch == nil || len(cfg.BootstrapRoot) == 0 || int64(len(cfg.BootstrapRoot)) > MaxMetadataBytes {
		return nil, errors.New("releaseupdate: bootstrap root and fetch transport required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := protectedDirectory(cfg.StateDir); err != nil {
		return nil, err
	}
	root, err := metadata.Root().FromBytes(cfg.BootstrapRoot)
	if err != nil {
		return nil, err
	}
	if err = validateRoot(root); err != nil {
		return nil, err
	}
	if err = root.VerifyDelegate(metadata.ROOT, root); err != nil {
		return nil, err
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&updatev1.AgentUpdateChannel{}, &updatev1.AgentUpdateArtifact{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	cfg.BootstrapRoot = bytes.Clone(cfg.BootstrapRoot)
	return &Client{cfg: cfg, validator: validator}, nil
}

type boundedFetcher struct {
	ctx        context.Context
	fetch      FetchFunc
	checkpoint func() error
}

func (f boundedFetcher) DownloadFile(url string, limit int64, _ time.Duration) ([]byte, error) {
	name, ok := strings.CutPrefix(url, "https://transport.invalid/")
	if !ok || !safePath(name) || !strings.HasPrefix(name, "metadata/") || limit < 1 || limit > MaxMetadataBytes {
		return nil, errors.New("releaseupdate: invalid metadata request")
	}
	if err := f.ctx.Err(); err != nil {
		return nil, err
	}
	if f.checkpoint != nil {
		if err := f.checkpoint(); err != nil {
			return nil, err
		}
	}
	data, err := f.fetch(f.ctx, name, limit)
	if errors.Is(err, ErrNotFound) {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: 404, URL: url}
	}
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("releaseupdate: metadata transport exceeded bound")
	}
	if err = metadataShape(name, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Client) loadState() (result *updatev1.ClientState, err error) {
	root, err := os.OpenRoot(c.cfg.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	data, err := readBounded(root, "state.pb", maxStateBytes)
	digest := sha256.Sum256(c.cfg.BootstrapRoot)
	marker, markerErr := readBounded(root, "initialized", sha256.Size)
	if errors.Is(err, os.ErrNotExist) && errors.Is(markerErr, os.ErrNotExist) {
		return &updatev1.ClientState{BootstrapSha256: digest[:], RootJson: c.cfg.BootstrapRoot, ChannelGenerations: map[string]uint64{}, ChannelSha256: map[string]string{}}, nil
	}
	if markerErr != nil || !bytes.Equal(marker, digest[:]) {
		return nil, errors.New("releaseupdate: missing or foreign initialization marker")
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("releaseupdate: initialized checkpoint is missing")
	}
	if err != nil {
		return nil, err
	}
	state := new(updatev1.ClientState)
	if err = proto.Unmarshal(data, state); err != nil {
		return nil, err
	}
	if !bytes.Equal(state.GetBootstrapSha256(), digest[:]) || len(state.GetRootJson()) == 0 {
		return nil, errors.New("releaseupdate: checkpoint bootstrap binding mismatch")
	}
	if state.ChannelGenerations == nil {
		state.ChannelGenerations = map[string]uint64{}
	}
	if state.ChannelSha256 == nil {
		state.ChannelSha256 = map[string]string{}
	}
	return state, nil
}
func (c *Client) persist(state *updatev1.ClientState) error {
	data, err := proto.Marshal(state)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxStateBytes {
		return errors.New("releaseupdate: checkpoint exceeds bound")
	}
	marker := filepath.Join(c.cfg.StateDir, "initialized")
	if _, statErr := os.Lstat(marker); errors.Is(statErr, os.ErrNotExist) {
		if _, stateErr := os.Lstat(filepath.Join(c.cfg.StateDir, "state.pb")); !errors.Is(stateErr, os.ErrNotExist) {
			return errors.New("releaseupdate: initialized checkpoint marker disappeared")
		}
		digest := sha256.Sum256(c.cfg.BootstrapRoot)
		if err = atomicWrite(marker, digest[:], 0600); err != nil {
			return err
		}
	} else if statErr != nil {
		return statErr
	}
	return atomicWrite(filepath.Join(c.cfg.StateDir, "state.pb"), data, 0600)
}

func (c *Client) Select(ctx context.Context, request SelectionRequest) (selection *Selection, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	lock, err := acquireLock(c.cfg.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if request.DeviceID == "" || len(request.DeviceID) > 256 || !safePath(request.Ring) || strings.Contains(request.Ring, "/") {
		return nil, errors.New("releaseupdate: invalid selection identity")
	}
	if _, err = ParseVersion(request.CurrentVersion); err != nil {
		return nil, err
	}
	state, err := c.loadState()
	if err != nil {
		return nil, err
	}
	now := c.cfg.Now().UTC()
	update, err := c.refresh(ctx, state)
	if err != nil {
		return nil, err
	}
	trusted := update.GetTrustedMetadataSet()
	catalogPath := "channels/" + request.Ring + ".json"
	info, err := update.GetTargetInfo(catalogPath)
	if err != nil {
		return nil, err
	}
	if err = validTarget(info, MaxCatalogBytes); err != nil {
		return nil, err
	}
	data, err := c.cfg.Fetch(ctx, "targets/"+hashPath(catalogPath, info.Hashes["sha256"]), info.Length)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxCatalogBytes {
		return nil, errors.New("releaseupdate: catalog transport exceeded bound")
	}
	if err = info.VerifyLengthHashes(data); err != nil {
		return nil, err
	}
	channel, err := decodeChannel(c.validator, data, now)
	if err != nil {
		return nil, err
	}
	if channel.GetRing() != request.Ring {
		return nil, errors.New("releaseupdate: catalog ring mismatch")
	}
	if err = validateOfflineArtifacts(c.validator, trusted.Targets[metadata.TARGETS], channel); err != nil {
		return nil, err
	}
	prior := state.ChannelGenerations[request.Ring]
	digest := digestBytes(data)
	if channel.GetGeneration() < prior || (channel.GetGeneration() == prior && state.ChannelSha256[request.Ring] != digest) {
		return nil, errors.New("releaseupdate: catalog rollback or equivocation")
	}
	if len(state.ChannelGenerations) >= 128 && prior == 0 {
		return nil, errors.New("releaseupdate: too many channel checkpoints")
	}
	state.ChannelGenerations[request.Ring] = channel.GetGeneration()
	state.ChannelSha256[request.Ring] = digest
	if err = c.persist(state); err != nil {
		return nil, err
	}
	if channel.GetPaused() || !eligible(request.DeviceID, request.Ring, channel.GetEligiblePercentage()) {
		return nil, ErrNoUpdate
	}
	var selected *updatev1.AgentUpdateArtifact
	for _, artifact := range channel.GetArtifacts() {
		if artifact.GetArchitecture() != request.Architecture || artifact.GetPackageFormat() != request.PackageFormat || request.ProtocolVersion < artifact.GetMinimumProtocolVersion() || request.ProtocolVersion > artifact.GetMaximumProtocolVersion() {
			continue
		}
		lower, _ := compareVersion(request.CurrentVersion, artifact.GetMinimumAgentVersion())
		upper, _ := compareVersion(request.CurrentVersion, artifact.GetMaximumAgentVersion())
		newer, _ := compareVersion(artifact.GetVersion(), request.CurrentVersion)
		if lower < 0 || upper > 0 || newer <= 0 {
			continue
		}
		if selected == nil {
			selected = artifact
		} else if cmp, _ := compareVersion(artifact.GetVersion(), selected.GetVersion()); cmp > 0 {
			selected = artifact
		}
	}
	if selected == nil {
		return nil, ErrNoUpdate
	}
	info = trusted.Targets[metadata.TARGETS].Signed.Targets[selected.GetTargetPath()]
	if err = validTarget(info, MaxTargetBytes); err != nil {
		return nil, err
	}
	expiry := channel.GetExpiresAt().AsTime()
	for _, e := range []time.Time{trusted.Root.Signed.Expires, trusted.Timestamp.Signed.Expires, trusted.Snapshot.Signed.Expires, trusted.Targets[metadata.TARGETS].Signed.Expires, trusted.Targets[rolloutRole].Signed.Expires} {
		if e.Before(expiry) {
			expiry = e
		}
	}
	result := &Selection{Artifact: proto.CloneOf(selected), TargetPath: "targets/" + hashPath(info.Path, info.Hashes["sha256"]), Length: info.Length, SHA256: hex.EncodeToString(info.Hashes["sha256"]), owner: c, target: info, expires: expiry}
	if selected.GetSignatureTargetPath() != "" {
		signature := trusted.Targets[metadata.TARGETS].Signed.Targets[selected.GetSignatureTargetPath()]
		if err = validTarget(signature, MaxSignatureBytes); err != nil {
			return nil, err
		}
		result.signature = signature
		result.SignaturePath = "targets/" + hashPath(signature.Path, signature.Hashes["sha256"])
		result.SignatureLength = signature.Length
		result.SignatureSHA256 = hex.EncodeToString(signature.Hashes["sha256"])
	}
	return result, nil
}

func (c *Client) refresh(ctx context.Context, state *updatev1.ClientState) (update *updater.Updater, err error) {
	now := c.cfg.Now().UTC()
	if state.GetObservedAt() != nil && now.Before(state.GetObservedAt().AsTime()) {
		return nil, errors.New("releaseupdate: clock rollback")
	}
	work, err := os.MkdirTemp(c.cfg.StateDir, ".refresh-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(work)) }()
	cached := map[string][]byte{"root": state.RootJson, "timestamp": state.TimestampJson, "snapshot": state.SnapshotJson, "targets": state.TargetsJson, rolloutRole: state.RolloutJson}
	for role, data := range cached {
		if len(data) > 0 {
			if int64(len(data)) > MaxMetadataBytes {
				return nil, errors.New("releaseupdate: cached metadata too large")
			}
			if err = os.WriteFile(filepath.Join(work, role+".json"), data, 0600); err != nil {
				return nil, err
			}
		}
	}
	fetch := boundedFetcher{ctx: ctx, fetch: c.cfg.Fetch, checkpoint: func() error {
		if update == nil {
			return nil
		}
		return c.checkpoint(update, state, now)
	}}
	cfg := &tufconfig.UpdaterConfig{MaxRootRotations: 32, MaxDelegations: 1, RootMaxLength: MaxMetadataBytes, TimestampMaxLength: MaxMetadataBytes, SnapshotMaxLength: MaxMetadataBytes, TargetsMaxLength: MaxMetadataBytes, Fetcher: fetch, LocalTrustedRoot: state.RootJson, LocalMetadataDir: work, LocalTargetsDir: work, RemoteMetadataURL: "https://transport.invalid/metadata/", PrefixTargetsWithHash: true}
	update, err = updater.New(cfg)
	if err != nil {
		return nil, err
	}
	refreshErr := update.Refresh()
	// Flush even on errors: go-tuf retains verified expired metadata as a high-water mark.
	trusted := update.GetTrustedMetadataSet()
	if err = c.checkpoint(update, state, now); err != nil {
		return nil, errors.Join(refreshErr, err)
	}
	if refreshErr != nil {
		return nil, refreshErr
	}
	if err = validateRoot(trusted.Root); err != nil {
		return nil, err
	}
	if err = validateRolloutDelegation(trusted.Root, trusted.Targets[metadata.TARGETS]); err != nil {
		return nil, err
	}
	// Force exactly the one supported delegated role through go-tuf's normal
	// traversal before deleting its temporary cache. The probe need not exist.
	_, lookupErr := update.GetTargetInfo("channels/__refresh__.json")
	trusted = update.GetTrustedMetadataSet()
	if err = c.checkpoint(update, state, now); err != nil {
		return nil, errors.Join(lookupErr, err)
	}
	rollout := trusted.Targets[rolloutRole]
	if rollout == nil {
		return nil, errors.Join(errors.New("releaseupdate: missing verified rollout role"), lookupErr)
	}
	if err = validateRolloutTargets(rollout); err != nil {
		return nil, err
	}
	if !now.Before(rollout.Signed.Expires) || rollout.Signed.Expires.After(now.Add(7*24*time.Hour)) {
		return nil, errors.New("releaseupdate: rollout validity refused")
	}
	for _, expiry := range []time.Time{trusted.Root.Signed.Expires, trusted.Timestamp.Signed.Expires, trusted.Snapshot.Signed.Expires, trusted.Targets[metadata.TARGETS].Signed.Expires} {
		if !now.Before(expiry) {
			return nil, errors.New("releaseupdate: expired metadata")
		}
	}
	if trusted.Root.Signed.Expires.After(now.Add(366*24*time.Hour)) || trusted.Timestamp.Signed.Expires.After(now.Add(24*time.Hour)) || trusted.Snapshot.Signed.Expires.After(now.Add(7*24*time.Hour)) || trusted.Targets[metadata.TARGETS].Signed.Expires.After(now.Add(7*24*time.Hour)) {
		return nil, errors.New("releaseupdate: excessive metadata validity")
	}
	return update, nil
}

func (c *Client) checkpoint(update *updater.Updater, state *updatev1.ClientState, now time.Time) error {
	trusted := update.GetTrustedMetadataSet()
	var err error
	if trusted.Root != nil {
		state.RootJson, err = trusted.Root.ToBytes(false)
		if err != nil {
			return err
		}
	}
	if trusted.Timestamp != nil {
		state.TimestampJson, err = trusted.Timestamp.ToBytes(false)
		if err != nil {
			return err
		}
	}
	if trusted.Snapshot != nil {
		state.SnapshotJson, err = trusted.Snapshot.ToBytes(false)
		if err != nil {
			return err
		}
	}
	if targets := trusted.Targets[metadata.TARGETS]; targets != nil {
		state.TargetsJson, err = targets.ToBytes(false)
		if err != nil {
			return err
		}
	}
	if rollout := trusted.Targets[rolloutRole]; rollout != nil {
		state.RolloutJson, err = rollout.ToBytes(false)
		if err != nil {
			return err
		}
	}
	state.ObservedAt = timestamppb.New(now)
	return c.persist(state)
}

// Validate nullable object shapes before entering the maintained verifier.
// This does not replace TUF signature, version, hash, or expiry verification.
func metadataShape(name string, data []byte) error {
	switch {
	case strings.HasSuffix(name, ".root.json"):
		root, err := metadata.Root().FromBytes(data)
		if err != nil {
			return err
		}
		return validateRoot(root)
	case strings.HasSuffix(name, "/timestamp.json"):
		timestamp, err := metadata.Timestamp().FromBytes(data)
		if err != nil {
			return err
		}
		if timestamp.Signed.Meta["snapshot.json"] == nil {
			return errors.New("releaseupdate: missing snapshot metadata")
		}
		for _, info := range timestamp.Signed.Meta {
			if info == nil {
				return errors.New("releaseupdate: nil timestamp metadata")
			}
		}
	case strings.HasSuffix(name, ".snapshot.json"):
		snapshot, err := metadata.Snapshot().FromBytes(data)
		if err != nil {
			return err
		}
		if snapshot.Signed.Meta["targets.json"] == nil || snapshot.Signed.Meta["rollout.json"] == nil || len(snapshot.Signed.Meta) != 2 {
			return errors.New("releaseupdate: missing targets metadata")
		}
		for _, info := range snapshot.Signed.Meta {
			if info == nil {
				return errors.New("releaseupdate: nil snapshot metadata")
			}
		}
	case strings.HasSuffix(name, ".targets.json"), strings.HasSuffix(name, ".rollout.json"):
		// go-tuf populates TargetFiles.Path during its custom UnmarshalJSON and
		// dereferences null map values. Decode the same upstream type without that
		// method first, rejecting nullable values before invoking the verifier.
		type targetsShape metadata.TargetsType
		var document struct {
			Signed targetsShape `json:"signed"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			return err
		}
		if len(document.Signed.Targets) > 4096 {
			return errors.New("releaseupdate: unsupported targets authority")
		}
		if strings.HasSuffix(name, ".rollout.json") {
			rollout := &metadata.Metadata[metadata.TargetsType]{Signed: metadata.TargetsType(document.Signed)}
			if err := validateRolloutTargets(rollout); err != nil {
				return err
			}
		} else {
			delegation := document.Signed.Delegations
			if delegation == nil || delegation.SuccinctRoles != nil || len(delegation.Roles) != 1 || len(delegation.Keys) > 16 {
				return errors.New("releaseupdate: bounded rollout delegation required")
			}
			for _, key := range delegation.Keys {
				if key == nil {
					return errors.New("releaseupdate: nil delegation key")
				}
			}
		}
		for name, info := range document.Signed.Targets {
			if info == nil {
				return errors.New("releaseupdate: nil target")
			}
			info.Path = name
			if err := validTarget(info, MaxTargetBytes); err != nil {
				return err
			}
		}
	default:
		return errors.New("releaseupdate: unexpected metadata role")
	}
	return nil
}

func validTarget(info *metadata.TargetFiles, maximum int64) error {
	if info == nil || !safeTargetPath(info.Path) || info.Length < 1 || info.Length > maximum || len(info.Hashes) != 1 || len(info.Hashes["sha256"]) != sha256.Size {
		return errors.New("releaseupdate: invalid SHA256 target descriptor")
	}
	return nil
}

func (c *Client) Stage(ctx context.Context, selection *Selection, source io.Reader, destination string) error {
	if selection == nil {
		return errors.New("releaseupdate: unverified selection")
	}
	return c.stageTarget(ctx, selection, selection.target, source, destination)
}

// StageSignature stages only the detached native signature authenticated in the
// same TUF snapshot as the selected package. Native package trust is not bypassed.
func (c *Client) StageSignature(ctx context.Context, selection *Selection, source io.Reader, destination string) error {
	if selection == nil || selection.signature == nil {
		return errors.New("releaseupdate: no verified detached signature")
	}
	return c.stageTarget(ctx, selection, selection.signature, source, destination)
}

func (c *Client) stageTarget(ctx context.Context, selection *Selection, target *metadata.TargetFiles, source io.Reader, destination string) error {
	if selection.owner != c || target == nil || source == nil {
		return errors.New("releaseupdate: unverified selection")
	}
	if !c.cfg.Now().Before(selection.expires) {
		return errors.New("releaseupdate: selection expired")
	}
	if !filepath.IsAbs(destination) {
		return errors.New("releaseupdate: absolute staging destination required")
	}
	if err := protectedDirectory(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("staging directory: %w", err)
	}
	ctx, cancel := context.WithDeadline(ctx, selection.expires)
	defer cancel()
	return copyTarget(ctx, source, destination, target.Length, target.Hashes["sha256"])
}
