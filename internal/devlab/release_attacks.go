package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"lindm/internal/releaseupdate"
)

// ReleaseMetadataSnapshot is public, already signed repository material from one
// complete generation. It carries no role keys or execution credentials.
type ReleaseMetadataSnapshot struct {
	TimestampVersion int64
	SnapshotVersion  int64
	TargetsVersion   int64
	RolloutVersion   int64
	TimestampSHA256  string
	timestamp        []byte
	targets          []byte
	rollout          []byte
}

func releaseFixtureReplace(filename string, data []byte) (resultErr error) {
	if int64(len(data)) > releaseupdate.MaxMetadataBytes {
		return errors.New("release fixture replacement exceeds limit")
	}
	file, err := os.CreateTemp(filepath.Dir(filename), ".release-attack-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, filename); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(filename))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func (f *AuthorityFixture) CaptureReleaseMetadata(ctx context.Context) (*ReleaseMetadataSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory := filepath.Join(f.directory, "release-repository", "metadata")
	rootBytes, err := readOwned(filepath.Join(directory, "root.json"))
	if err != nil {
		return nil, err
	}
	root, err := metadata.Root().FromBytes(rootBytes)
	if err != nil {
		return nil, err
	}
	timestampBytes, err := readOwned(filepath.Join(directory, "timestamp.json"))
	if err != nil {
		return nil, err
	}
	timestamp, err := metadata.Timestamp().FromBytes(timestampBytes)
	if err != nil {
		return nil, err
	}
	if err := root.VerifyDelegate(metadata.TIMESTAMP, timestamp); err != nil {
		return nil, err
	}
	snapshotInfo := timestamp.Signed.Meta["snapshot.json"]
	if snapshotInfo == nil {
		return nil, errors.New("release fixture timestamp omits snapshot")
	}
	snapshotBytes, err := readOwned(filepath.Join(directory, fmt.Sprintf("%d.snapshot.json", snapshotInfo.Version)))
	if err != nil {
		return nil, err
	}
	if err := snapshotInfo.VerifyLengthHashes(snapshotBytes); err != nil {
		return nil, err
	}
	snapshot, err := metadata.Snapshot().FromBytes(snapshotBytes)
	if err != nil {
		return nil, err
	}
	if err := root.VerifyDelegate(metadata.SNAPSHOT, snapshot); err != nil {
		return nil, err
	}
	targetsInfo := snapshot.Signed.Meta["targets.json"]
	if targetsInfo == nil {
		return nil, errors.New("release fixture snapshot omits targets")
	}
	targetsBytes, err := readOwned(filepath.Join(directory, fmt.Sprintf("%d.targets.json", targetsInfo.Version)))
	if err != nil {
		return nil, err
	}
	if err := targetsInfo.VerifyLengthHashes(targetsBytes); err != nil {
		return nil, err
	}
	targets, err := metadata.Targets().FromBytes(targetsBytes)
	if err != nil {
		return nil, err
	}
	if err := root.VerifyDelegate(metadata.TARGETS, targets); err != nil {
		return nil, err
	}
	rolloutInfo := snapshot.Signed.Meta["rollout.json"]
	if rolloutInfo == nil {
		return nil, errors.New("release fixture snapshot omits rollout")
	}
	rolloutBytes, err := readOwned(filepath.Join(directory, fmt.Sprintf("%d.rollout.json", rolloutInfo.Version)))
	if err != nil {
		return nil, err
	}
	if err := rolloutInfo.VerifyLengthHashes(rolloutBytes); err != nil {
		return nil, err
	}
	rollout, err := metadata.Targets().FromBytes(rolloutBytes)
	if err != nil {
		return nil, err
	}
	if err := targets.VerifyDelegate("rollout", rollout); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(timestampBytes)
	return &ReleaseMetadataSnapshot{TimestampVersion: timestamp.Signed.Version, SnapshotVersion: snapshot.Signed.Version, TargetsVersion: targets.Signed.Version, RolloutVersion: rollout.Signed.Version, TimestampSHA256: hex.EncodeToString(hash[:]), timestamp: timestampBytes, targets: targetsBytes, rollout: rolloutBytes}, nil
}

// ReplayReleaseTimestamp offers an older valid signature, not corrupt JSON. The
// client must reject it using its persisted version high-water mark.
func (f *AuthorityFixture) ReplayReleaseTimestamp(ctx context.Context, old *ReleaseMetadataSnapshot) (func() error, error) {
	current, err := f.CaptureReleaseMetadata(ctx)
	if err != nil {
		return nil, err
	}
	if old == nil || old.TimestampVersion >= current.TimestampVersion {
		return nil, errors.New("rollback fixture requires an older signed timestamp")
	}
	filename := filepath.Join(f.directory, "release-repository", "metadata", "timestamp.json")
	if err := releaseFixtureReplace(filename, old.timestamp); err != nil {
		return nil, err
	}
	return sync.OnceValue(func() error { return releaseFixtureReplace(filename, current.timestamp) }), nil
}

// MixReleaseRollout substitutes an older signed rollout document under a newer
// snapshot's immutable name. Stop guest transport before advancing/publishing the
// new generation so the client cannot legitimately reuse an already cached copy.
func (f *AuthorityFixture) MixReleaseRollout(ctx context.Context, old *ReleaseMetadataSnapshot) (func() error, error) {
	current, err := f.CaptureReleaseMetadata(ctx)
	if err != nil {
		return nil, err
	}
	if old == nil || old.RolloutVersion >= current.RolloutVersion {
		return nil, errors.New("mix-and-match fixture requires older signed rollout")
	}
	filename := filepath.Join(f.directory, "release-repository", "metadata", fmt.Sprintf("%d.rollout.json", current.RolloutVersion))
	if err := releaseFixtureReplace(filename, old.rollout); err != nil {
		return nil, err
	}
	return sync.OnceValue(func() error { return releaseFixtureReplace(filename, current.rollout) }), nil
}

// TamperReleaseTarget changes one byte without allocating or copying the package.
// The native lane verifies the executor rejects its TUF hash before native apply.
func (f *AuthorityFixture) TamperReleaseTarget(ctx context.Context, logicalPath string) (func() error, error) {
	if !strings.HasPrefix(logicalPath, "packages/lindm-agent/") || path.Clean(logicalPath) != logicalPath || !filepath.IsLocal(logicalPath) {
		return nil, errors.New("tamper fixture requires an agent target")
	}
	current, err := f.CaptureReleaseMetadata(ctx)
	if err != nil {
		return nil, err
	}
	targets, err := metadata.Targets().FromBytes(current.targets)
	if err != nil {
		return nil, err
	}
	info := targets.Signed.Targets[logicalPath]
	if info == nil || len(info.Hashes["sha256"]) != sha256.Size || info.Length < 1 || info.Length > releaseupdate.MaxTargetBytes {
		return nil, errors.New("tamper fixture target is absent or invalid")
	}
	name := path.Join(path.Dir(logicalPath), hex.EncodeToString(info.Hashes["sha256"])+"."+path.Base(logicalPath))
	filename := filepath.Join(f.directory, "release-repository", "targets", filepath.FromSlash(name))
	file, err := os.OpenFile(filename, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok || !fileInfo.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || fileInfo.Mode().Perm()&0077 != 0 || fileInfo.Size() != info.Length {
		return nil, errors.Join(errors.New("tamper target must be a private owned single-link file with its signed package length"), file.Close())
	}
	var original [1]byte
	if _, err := file.ReadAt(original[:], 0); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	changed := [1]byte{original[0] ^ 1}
	if _, err := file.WriteAt(changed[:], 0); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return sync.OnceValue(func() error {
		_, writeErr := file.WriteAt(original[:], 0)
		return errors.Join(writeErr, file.Sync(), file.Close())
	}), nil
}

// BeginReleaseFreeze publishes a valid short-lived next timestamp. The native
// client first consumes it before expiry, then sees the identical bytes held
// beyond expiry. Recovery must publish a newer timestamp, not replay the old one.
func (f *AuthorityFixture) BeginReleaseFreeze(ctx context.Context, validity time.Duration) (time.Time, error) {
	if validity < 5*time.Second || validity > time.Minute {
		return time.Time{}, errors.New("freeze fixture validity must be five to sixty seconds")
	}
	current, err := f.CaptureReleaseMetadata(ctx)
	if err != nil {
		return time.Time{}, err
	}
	document, err := metadata.Timestamp().FromBytes(current.timestamp)
	if err != nil {
		return time.Time{}, err
	}
	keys, err := releaseupdate.LoadRoleSigners(filepath.Join(f.directory, "release-custody"), false)
	if err != nil {
		return time.Time{}, err
	}
	document.Signed.Version++
	document.Signed.Expires = time.Now().UTC().Add(validity).Truncate(time.Second)
	document.Signatures = nil
	for _, signer := range keys.Timestamp {
		if _, err := document.Sign(signer); err != nil {
			return time.Time{}, err
		}
	}
	data, err := document.ToBytes(false)
	if err != nil {
		return time.Time{}, err
	}
	if err := releaseFixtureReplace(filepath.Join(f.directory, "release-repository", "metadata", "timestamp.json"), data); err != nil {
		return time.Time{}, err
	}
	return document.Signed.Expires, nil
}
