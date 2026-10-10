package releaseupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	updatev1 "lindm/gen/lindm/update/v1"
)

type PublisherConfig struct {
	Directory string
	Signers   RoleSigners
	Now       func() time.Time
}
type Publisher struct {
	cfg       PublisherConfig
	validator protovalidate.Validator
	mu        sync.Mutex
}

func publisherConfig(cfg PublisherConfig) (*Publisher, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := protectedDirectory(cfg.Directory); err != nil {
		return nil, err
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&updatev1.AgentUpdateChannel{}, &updatev1.AgentUpdateArtifact{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	return &Publisher{cfg: cfg, validator: validator}, nil
}
func NewPublisher(cfg PublisherConfig) (*Publisher, error) {
	p, err := publisherConfig(cfg)
	if err != nil {
		return nil, err
	}
	root, err := p.root()
	if err != nil {
		return nil, err
	}
	if err = validateRoot(root); err != nil {
		return nil, err
	}
	if err = root.VerifyDelegate(metadata.ROOT, root); err != nil {
		return nil, err
	}
	if err = validateSigners(root, cfg.Signers); err != nil {
		return nil, err
	}
	current, err := p.current(root)
	if err != nil {
		return nil, err
	}
	role := current.targets.Signed.Delegations.Roles[0]
	if err = validateRoleSigners(role.KeyIDs, role.Threshold, cfg.Signers.Rollout); err != nil {
		return nil, err
	}
	return p, nil
}

func makeRoot(signers RoleSigners, version int64, expires time.Time) (*metadata.Metadata[metadata.RootType], error) {
	root := metadata.Root(expires)
	root.Signed.Version = version
	root.Signed.ConsistentSnapshot = true
	for role, keys := range signers.roles() {
		if role == rolloutRole {
			continue
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("releaseupdate: %s signer required", role)
		}
		for _, signer := range keys {
			if signer == nil {
				return nil, errors.New("releaseupdate: nil signer")
			}
			public, err := signer.PublicKey()
			if err != nil {
				return nil, err
			}
			key, err := metadata.KeyFromPublicKey(public)
			if err != nil {
				return nil, err
			}
			if err = root.Signed.AddKey(key, role); err != nil {
				return nil, err
			}
		}
		root.Signed.Roles[role].Threshold = len(keys)
	}
	if err := validateRoot(root); err != nil {
		return nil, err
	}
	for _, signer := range signers.Root {
		if _, err := root.Sign(signer); err != nil {
			return nil, err
		}
	}
	return root, nil
}

func CreateRepository(ctx context.Context, cfg PublisherConfig) (p *Publisher, err error) {
	p, err = publisherConfig(cfg)
	if err != nil {
		return nil, err
	}
	lock, err := acquireLock(cfg.Directory)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if _, err = os.Lstat(filepath.Join(cfg.Directory, "metadata")); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("releaseupdate: repository metadata already exists")
	}
	if err = mkdirDurable(filepath.Join(cfg.Directory, "metadata"), 0700); err != nil {
		return nil, err
	}
	if err = mkdirDurable(filepath.Join(cfg.Directory, "targets"), 0700); err != nil {
		return nil, err
	}
	root, err := makeRoot(cfg.Signers, 1, p.cfg.Now().Add(365*24*time.Hour))
	if err != nil {
		return nil, err
	}
	data, err := root.ToBytes(false)
	if err != nil {
		return nil, err
	}
	if err = p.immutable("metadata/1.root.json", data); err != nil {
		return nil, err
	}
	if err = atomicWrite(filepath.Join(cfg.Directory, "metadata/root.json"), data, 0600); err != nil {
		return nil, err
	}
	targets := metadata.Targets(p.cfg.Now().Add(7 * 24 * time.Hour))
	targets.Signed.Version = 0
	if err = makeRolloutDelegation(root, targets, cfg.Signers.Rollout); err != nil {
		return nil, err
	}
	rollout := metadata.Targets(p.cfg.Now().Add(7 * 24 * time.Hour))
	rollout.Signed.Version = 0
	if err = p.commit(ctx, root, &publication{targets: targets, rollout: rollout}, true); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Publisher) read(name string, limit int64) (data []byte, err error) {
	root, err := os.OpenRoot(p.cfg.Directory)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return readBounded(root, name, limit)
}
func (p *Publisher) root() (*metadata.Metadata[metadata.RootType], error) {
	data, err := p.read("metadata/root.json", MaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	root, err := metadata.Root().FromBytes(data)
	if err != nil {
		return nil, err
	}
	if err = validateRoot(root); err != nil {
		return nil, err
	}
	if err = root.VerifyDelegate(metadata.ROOT, root); err != nil {
		return nil, err
	}
	// A crash can occur after publishing a versioned rotation but before the
	// convenience root.json alias. Discover only consecutive dual-signed roots.
	for range 32 {
		data, err = p.read(fmt.Sprintf("metadata/%d.root.json", root.Signed.Version+1), MaxMetadataBytes)
		if errors.Is(err, os.ErrNotExist) {
			return root, nil
		}
		if err != nil {
			return nil, err
		}
		next, err := metadata.Root().FromBytes(data)
		if err != nil {
			return nil, err
		}
		if err = validateRoot(next); err != nil {
			return nil, err
		}
		if next.Signed.Version != root.Signed.Version+1 {
			return nil, errors.New("releaseupdate: root version mismatch")
		}
		if err = root.VerifyDelegate(metadata.ROOT, next); err != nil {
			return nil, err
		}
		if err = next.VerifyDelegate(metadata.ROOT, next); err != nil {
			return nil, err
		}
		root = next
	}
	return nil, errors.New("releaseupdate: publisher root transition bound exceeded")
}

func (p *Publisher) immutable(name string, data []byte) error {
	if int64(len(data)) > MaxMetadataBytes {
		return errors.New("releaseupdate: metadata too large")
	}
	existing, err := p.read(name, MaxMetadataBytes)
	if err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return errors.New("releaseupdate: immutable version collision")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(filepath.Join(p.cfg.Directory, filepath.FromSlash(name)), data, 0600)
}

type publication struct {
	targets     *metadata.Metadata[metadata.TargetsType]
	rollout     *metadata.Metadata[metadata.TargetsType]
	targetBytes []byte
	version     int64
}

func (p *Publisher) current(root *metadata.Metadata[metadata.RootType]) (*publication, error) {
	raw, err := p.read("metadata/timestamp.json", MaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	timestamp, err := metadata.Timestamp().FromBytes(raw)
	if err != nil {
		return nil, err
	}
	if err = root.VerifyDelegate(metadata.TIMESTAMP, timestamp); err != nil {
		if root.Signed.Version <= 1 {
			return nil, err
		}
		priorBytes, readErr := p.read(fmt.Sprintf("metadata/%d.root.json", root.Signed.Version-1), MaxMetadataBytes)
		if readErr != nil {
			return nil, errors.Join(err, readErr)
		}
		prior, parseErr := metadata.Root().FromBytes(priorBytes)
		if parseErr != nil {
			return nil, parseErr
		}
		if err = validateRoot(prior); err != nil {
			return nil, err
		}
		if err = prior.VerifyDelegate(metadata.ROOT, root); err != nil {
			return nil, err
		}
		if err = prior.VerifyDelegate(metadata.TIMESTAMP, timestamp); err != nil {
			return nil, err
		}
		root = prior
	}
	snapshotInfo := timestamp.Signed.Meta["snapshot.json"]
	if snapshotInfo == nil {
		return nil, errors.New("releaseupdate: missing snapshot")
	}
	raw, err = p.read(fmt.Sprintf("metadata/%d.snapshot.json", snapshotInfo.Version), MaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	if err = snapshotInfo.VerifyLengthHashes(raw); err != nil {
		return nil, err
	}
	snapshot, err := metadata.Snapshot().FromBytes(raw)
	if err != nil {
		return nil, err
	}
	if snapshot.Signed.Version != snapshotInfo.Version {
		return nil, errors.New("releaseupdate: snapshot version binding mismatch")
	}
	if err = root.VerifyDelegate(metadata.SNAPSHOT, snapshot); err != nil {
		return nil, err
	}
	result := &publication{version: timestamp.Signed.Version}
	for _, role := range []string{metadata.TARGETS, rolloutRole} {
		info := snapshot.Signed.Meta[role+".json"]
		if info == nil {
			return nil, errors.New("releaseupdate: missing targets role")
		}
		raw, err = p.read(fmt.Sprintf("metadata/%d.%s.json", info.Version, role), MaxMetadataBytes)
		if err != nil {
			return nil, err
		}
		if err = info.VerifyLengthHashes(raw); err != nil {
			return nil, err
		}
		if err = metadataShape("metadata/current."+role+".json", raw); err != nil {
			return nil, err
		}
		document, err := metadata.Targets().FromBytes(raw)
		if err != nil {
			return nil, err
		}
		if document.Signed.Version != info.Version {
			return nil, errors.New("releaseupdate: target role version binding mismatch")
		}
		if role == metadata.TARGETS {
			if err = root.VerifyDelegate(role, document); err != nil {
				return nil, err
			}
			if err = validateRolloutDelegation(root, document); err != nil {
				return nil, err
			}
			result.targets, result.targetBytes = document, raw
		} else {
			if err = result.targets.VerifyDelegate(role, document); err != nil {
				return nil, err
			}
			if err = validateRolloutTargets(document); err != nil {
				return nil, err
			}
			result.rollout = document
		}
	}
	return result, nil
}

func signMetadata[T metadata.Roles](root *metadata.Metadata[metadata.RootType], role string, document *metadata.Metadata[T], signers []signature.Signer) ([]byte, error) {
	document.Signatures = nil
	for _, signer := range signers {
		if signer == nil {
			return nil, errors.New("releaseupdate: nil signer")
		}
		if _, err := document.Sign(signer); err != nil {
			return nil, err
		}
	}
	if err := root.VerifyDelegate(role, document); err != nil {
		return nil, err
	}
	return document.ToBytes(false)
}
func metaInfo(version int64, data []byte) *metadata.MetaFiles {
	hash := sha256.Sum256(data)
	return &metadata.MetaFiles{Version: version, Length: int64(len(data)), Hashes: metadata.Hashes{"sha256": hash[:]}}
}

func (p *Publisher) commit(ctx context.Context, root *metadata.Metadata[metadata.RootType], current *publication, offline bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := p.cfg.Now()
	if !now.Before(root.Signed.Expires) {
		return errors.New("releaseupdate: root expired")
	}
	targets, rollout := current.targets, current.rollout
	if len(targets.Signed.Targets) > 4096 {
		return errors.New("releaseupdate: repository target limit exceeded")
	}
	if err := validateRolloutDelegation(root, targets); err != nil {
		return err
	}
	if err := validateRolloutTargets(rollout); err != nil {
		return err
	}
	next := max(current.version, targets.Signed.Version, rollout.Signed.Version) + 1
	available := false
	for range 1024 {
		collision := false
		for _, role := range []string{metadata.TARGETS, rolloutRole, metadata.SNAPSHOT} {
			_, err := os.Lstat(filepath.Join(p.cfg.Directory, fmt.Sprintf("metadata/%d.%s.json", next, role)))
			if err == nil {
				collision = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if !collision {
			available = true
			break
		}
		next++
	}
	if !available || next <= 0 {
		return errors.New("releaseupdate: publication version bound exceeded")
	}
	targetBytes := current.targetBytes
	if offline {
		if len(p.cfg.Signers.Targets) == 0 {
			return errors.New("releaseupdate: offline targets custody required")
		}
		targets.Signed.Version, targets.Signed.Expires = next, now.Add(7*24*time.Hour)
		var err error
		targetBytes, err = signMetadata(root, metadata.TARGETS, targets, p.cfg.Signers.Targets)
		if err != nil {
			return err
		}
	} else if len(targetBytes) == 0 || !now.Before(targets.Signed.Expires) {
		return errors.New("releaseupdate: offline targets publication expired or missing")
	}
	rollout.Signed.Version, rollout.Signed.Expires = next, now.Add(7*24*time.Hour)
	if targets.Signed.Expires.Before(rollout.Signed.Expires) {
		rollout.Signed.Expires = targets.Signed.Expires
	}
	rollout.Signatures = nil
	for _, signer := range p.cfg.Signers.Rollout {
		if signer == nil {
			return errors.New("releaseupdate: nil rollout signer")
		}
		if _, err := rollout.Sign(signer); err != nil {
			return err
		}
	}
	if err := targets.VerifyDelegate(rolloutRole, rollout); err != nil {
		return err
	}
	rolloutBytes, err := rollout.ToBytes(false)
	if err != nil {
		return err
	}
	snapshot := metadata.Snapshot(now.Add(7 * 24 * time.Hour))
	snapshot.Signed.Version = next
	snapshot.Signed.Meta = map[string]*metadata.MetaFiles{"targets.json": metaInfo(targets.Signed.Version, targetBytes), "rollout.json": metaInfo(rollout.Signed.Version, rolloutBytes)}
	snapshotBytes, err := signMetadata(root, metadata.SNAPSHOT, snapshot, p.cfg.Signers.Snapshot)
	if err != nil {
		return err
	}
	timestamp := metadata.Timestamp(now.Add(24 * time.Hour))
	timestamp.Signed.Version = next
	timestamp.Signed.Meta = map[string]*metadata.MetaFiles{"snapshot.json": metaInfo(next, snapshotBytes)}
	timestampBytes, err := signMetadata(root, metadata.TIMESTAMP, timestamp, p.cfg.Signers.Timestamp)
	if err != nil {
		return err
	}
	if offline {
		if err = p.immutable(fmt.Sprintf("metadata/%d.targets.json", targets.Signed.Version), targetBytes); err != nil {
			return err
		}
	}
	if err = p.immutable(fmt.Sprintf("metadata/%d.rollout.json", next), rolloutBytes); err != nil {
		return err
	}
	if err = p.immutable(fmt.Sprintf("metadata/%d.snapshot.json", next), snapshotBytes); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(p.cfg.Directory, "metadata/timestamp.json"), timestampBytes, 0600)
}

func (p *Publisher) importTarget(ctx context.Context, name, source string) (info *metadata.TargetFiles, err error) {
	if !safeTargetPath(name) {
		return nil, errors.New("releaseupdate: unsafe target path")
	}
	sourceRoot, err := os.OpenRoot(filepath.Dir(source))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, sourceRoot.Close()) }()
	input, err := openRegular(sourceRoot, filepath.Base(source))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	st, err := input.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < 1 || st.Size() > MaxTargetBytes {
		return nil, errors.New("releaseupdate: target exceeds size bound")
	}
	dir := filepath.Join(p.cfg.Directory, "targets", filepath.FromSlash(path.Dir(name)))
	if err = mkdirDurable(dir, 0700); err != nil {
		return nil, err
	}
	output, err := os.CreateTemp(dir, ".import-")
	if err != nil {
		return nil, err
	}
	temp := output.Name()
	defer func() {
		if e := os.Remove(temp); !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}()
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(contextReader{ctx, input}, MaxTargetBytes+1))
	if copyErr != nil || n != st.Size() {
		return nil, errors.Join(errors.New("releaseupdate: source changed or exceeded bound"), copyErr, output.Close())
	}
	if err = output.Sync(); err != nil {
		return nil, errors.Join(err, output.Close())
	}
	if err = output.Close(); err != nil {
		return nil, err
	}
	info = &metadata.TargetFiles{Path: name, Length: n, Hashes: metadata.Hashes{"sha256": hash.Sum(nil)}}
	destination := filepath.Join(p.cfg.Directory, "targets", filepath.FromSlash(hashPath(name, info.Hashes["sha256"])))
	if err = os.Rename(temp, destination); err != nil {
		return nil, err
	}
	return info, syncDir(dir)
}

func (p *Publisher) channel(targets *metadata.Metadata[metadata.TargetsType], ring string) (*updatev1.AgentUpdateChannel, error) {
	if !safePath(ring) || path.Base(ring) != ring {
		return nil, errors.New("releaseupdate: invalid ring")
	}
	name := "channels/" + ring + ".json"
	info := targets.Signed.Targets[name]
	if info == nil {
		return nil, ErrNotFound
	}
	info.Path = name
	if err := validTarget(info, MaxCatalogBytes); err != nil {
		return nil, err
	}
	data, err := p.read("targets/"+hashPath(name, info.Hashes["sha256"]), MaxCatalogBytes)
	if err != nil {
		return nil, err
	}
	if err = info.VerifyLengthHashes(data); err != nil {
		return nil, err
	}
	channel := new(updatev1.AgentUpdateChannel)
	if err = protojson.Unmarshal(data, channel); err != nil {
		return nil, err
	}
	if err = p.validator.Validate(channel); err != nil {
		return nil, err
	}
	if channel.GetRing() != ring {
		return nil, errors.New("releaseupdate: channel binding mismatch")
	}
	return channel, nil
}
func (p *Publisher) Channel(ctx context.Context, ring string) (channel *updatev1.AgentUpdateChannel, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	lock, err := acquireLock(p.cfg.Directory)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	root, err := p.root()
	if err != nil {
		return nil, err
	}
	current, err := p.current(root)
	if err != nil {
		return nil, err
	}
	return p.channel(current.rollout, ring)
}

func (p *Publisher) publish(ctx context.Context, root *metadata.Metadata[metadata.RootType], current *publication, channel *updatev1.AgentUpdateChannel, files map[string]string, offline bool) error {
	if err := validateChannel(p.validator, channel, p.cfg.Now()); err != nil {
		return err
	}
	if offline && len(p.cfg.Signers.Targets) == 0 {
		return errors.New("releaseupdate: offline targets custody required")
	}
	if !offline && len(files) != 0 {
		return errors.New("releaseupdate: online package publication refused")
	}
	targets := current.targets
	previous, err := p.channel(current.rollout, channel.GetRing())
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if previous != nil && channel.GetGeneration() <= previous.GetGeneration() {
		return errors.New("releaseupdate: channel generation must increase")
	}
	for name, source := range files {
		if len(name) >= 9 && name[:9] == "channels/" {
			return errors.New("releaseupdate: channel targets require typed publication")
		}
		info, err := p.importTarget(ctx, name, source)
		if err != nil {
			return err
		}
		targets.Signed.Targets[name] = info
	}
	for _, artifact := range channel.GetArtifacts() {
		if !offline {
			continue
		}
		info := targets.Signed.Targets[artifact.GetTargetPath()]
		if info == nil {
			return fmt.Errorf("releaseupdate: missing artifact %s", artifact.GetTargetPath())
		}
		info.Path = artifact.GetTargetPath()
		if err = validTarget(info, MaxTargetBytes); err != nil {
			return err
		}
		custom, err := protojson.Marshal(artifact)
		if err != nil {
			return err
		}
		value := json.RawMessage(custom)
		info.Custom = &value
		if signaturePath := artifact.GetSignatureTargetPath(); signaturePath != "" {
			signature := targets.Signed.Targets[signaturePath]
			if signature == nil {
				return fmt.Errorf("releaseupdate: missing native signature %s", signaturePath)
			}
			signature.Path = signaturePath
			if err = validTarget(signature, MaxSignatureBytes); err != nil {
				return err
			}
		}
	}
	if err = validateOfflineArtifacts(p.validator, targets, channel); err != nil {
		return err
	}
	data, err := protojson.Marshal(channel)
	if err != nil {
		return err
	}
	if int64(len(data)) > MaxCatalogBytes {
		return errors.New("releaseupdate: catalog too large")
	}
	name := "channels/" + channel.GetRing() + ".json"
	info, err := metadata.TargetFile().FromBytes(name, data, "sha256")
	if err != nil {
		return err
	}
	dir := filepath.Join(p.cfg.Directory, "targets/channels")
	if err = mkdirDurable(dir, 0700); err != nil {
		return err
	}
	if err = p.immutable("targets/"+hashPath(name, info.Hashes["sha256"]), data); err != nil {
		return err
	}
	current.rollout.Signed.Targets[name] = info
	return p.commit(ctx, root, current, offline)
}
func (p *Publisher) Publish(ctx context.Context, channel *updatev1.AgentUpdateChannel, files map[string]string) (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	lock, err := acquireLock(p.cfg.Directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	root, err := p.root()
	if err != nil {
		return err
	}
	current, err := p.current(root)
	if err != nil {
		return err
	}
	return p.publish(ctx, root, current, channel, files, true)
}

// Promote permits online policy to reference only exact offline-authorized
// artifacts; package bytes, signatures, and compatibility remain offline-owned.
func (p *Publisher) Promote(ctx context.Context, channel *updatev1.AgentUpdateChannel) (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	lock, err := acquireLock(p.cfg.Directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	root, err := p.root()
	if err != nil {
		return err
	}
	current, err := p.current(root)
	if err != nil {
		return err
	}
	return p.publish(ctx, root, current, channel, nil, false)
}
func (p *Publisher) SetRollout(ctx context.Context, ring string, paused bool, eligiblePercentage uint32) (*updatev1.AgentUpdateChannel, error) {
	return p.setRollout(ctx, ring, paused, eligiblePercentage, 0, "")
}

// SetRolloutRequest binds a durable operator intent to an exact predecessor.
// Replaying the same committed intent returns its existing signed catalog.
func (p *Publisher) SetRolloutRequest(ctx context.Context, ring string, paused bool, eligiblePercentage uint32, expectedGeneration uint64, requestID string) (*updatev1.AgentUpdateChannel, error) {
	if expectedGeneration == 0 || requestID == "" || len(requestID) > 128 {
		return nil, errors.New("releaseupdate: generation and request identity required")
	}
	return p.setRollout(ctx, ring, paused, eligiblePercentage, expectedGeneration, requestID)
}

func (p *Publisher) setRollout(ctx context.Context, ring string, paused bool, eligiblePercentage uint32, expected uint64, requestID string) (channel *updatev1.AgentUpdateChannel, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	lock, err := acquireLock(p.cfg.Directory)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	root, err := p.root()
	if err != nil {
		return nil, err
	}
	current, err := p.current(root)
	if err != nil {
		return nil, err
	}
	channel, err = p.channel(current.rollout, ring)
	if err != nil {
		return nil, err
	}
	if expected > 0 && channel.GetGeneration() != expected {
		if channel.GetGeneration() == expected+1 && channel.GetRolloutRequestId() == requestID && channel.GetPaused() == paused && channel.GetEligiblePercentage() == eligiblePercentage {
			return channel, nil
		}
		return nil, errors.New("releaseupdate: channel generation conflict")
	}
	channel.Generation++
	channel.Paused = paused
	channel.EligiblePercentage = eligiblePercentage
	channel.RolloutRequestId = requestID
	now := p.cfg.Now()
	channel.IssuedAt = timestamppb.New(now)
	channel.ExpiresAt = timestamppb.New(now.Add(7 * 24 * time.Hour))
	if err = p.publish(ctx, root, current, channel, nil, false); err != nil {
		return nil, err
	}
	return channel, nil
}

// RotateRoot requires the previous root quorum and all new role quorums. The
// versioned root is dual-signed and old root versions are retained for clients.
func (p *Publisher) RotateRoot(ctx context.Context, next RoleSigners) (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	lock, err := acquireLock(p.cfg.Directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	old, err := p.root()
	if err != nil {
		return err
	}
	current, err := p.current(old)
	if err != nil {
		return err
	}
	root, err := makeRoot(next, old.Signed.Version+1, p.cfg.Now().Add(365*24*time.Hour))
	if err != nil {
		return err
	}
	for _, signer := range p.cfg.Signers.Root {
		if _, err = root.Sign(signer); err != nil {
			return err
		}
	}
	if err = old.VerifyDelegate(metadata.ROOT, root); err != nil {
		return err
	}
	if err = root.VerifyDelegate(metadata.ROOT, root); err != nil {
		return err
	}
	data, err := root.ToBytes(false)
	if err != nil {
		return err
	}
	if err = p.immutable(fmt.Sprintf("metadata/%d.root.json", root.Signed.Version), data); err != nil {
		return err
	}
	oldSigners := p.cfg.Signers
	p.cfg.Signers = next
	if err = makeRolloutDelegation(root, current.targets, next.Rollout); err != nil {
		p.cfg.Signers = oldSigners
		return err
	}
	if err = p.commit(ctx, root, current, true); err != nil {
		p.cfg.Signers = oldSigners
		return err
	}
	return atomicWrite(filepath.Join(p.cfg.Directory, "metadata/root.json"), data, 0600)
}
