// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/buildinfo"
	"lindm/internal/custody"
	"lindm/internal/releasebuild"
)

const ReleaseFeedHealthPath = "/var/lib/lindmd-operations/release-feed-health.json"
const releaseFeedStatePath = "/var/lib/lindmd-operations/release-feed-state.json"
const releaseFeedDirectory = "/var/lib/lindmd-operations/releases"

// ReleaseFeedHealth contains authenticated public discovery facts. It contains
// no bulletin free text, private bundle path or deployment credentials.
type ReleaseFeedHealth struct {
	ImportedAt       time.Time
	ExpiresAt        time.Time
	InstalledVersion string
	AvailableVersion string
	UpdateAvailable  bool
	SecurityUpdate   bool
	AdvisoryIDs      []string
	Verified         bool
}
type releaseFeedState struct {
	Directory, PublicKey, KeyID string
	ImportedAt                  time.Time
}

func ReadReleaseFeedHealth(path string) (ReleaseFeedHealth, error) {
	var health ReleaseFeedHealth
	data, err := custody.ReadRoot(path, 16<<10, false)
	if err != nil {
		return health, err
	}
	err = json.Unmarshal(data, &health)
	return health, err
}

// ImportRelease copies a customer-delivered private export, then verifies the
// complete release using an independently pinned attestation identity. Imports
// cannot replace that identity or roll the retained discovered version backward.
func ImportRelease(ctx context.Context, bundle, publicKey, keyID string) (health ReleaseFeedHealth, err error) {
	lease, err := AcquireUpgradeLease(ctx)
	if err != nil {
		return health, err
	}
	defer func() { err = errors.Join(err, lease.Close()) }()
	return importRelease(ctx, bundle, publicKey, keyID)
}

func importRelease(ctx context.Context, bundle, publicKey, keyID string) (health ReleaseFeedHealth, err error) {
	if os.Geteuid() != 0 {
		return health, errors.New("operations: root_required")
	}
	if err = os.MkdirAll(releaseFeedDirectory, 0700); err != nil {
		return health, err
	}
	if err = custody.PrivateDirectory(releaseFeedDirectory); err != nil {
		return health, err
	}
	keyBytes, err := custody.ReadRoot(publicKey, 16384, false)
	if err != nil {
		return health, err
	}
	if priorData, readErr := custody.ReadRoot(releaseFeedStatePath, 16<<10, false); readErr == nil {
		var prior releaseFeedState
		if err = json.Unmarshal(priorData, &prior); err != nil {
			return health, errors.New("operations: invalid_release_feed_state")
		}
		priorKey, readErr := custody.ReadRoot(prior.PublicKey, 16384, false)
		if readErr != nil {
			return health, readErr
		}
		if prior.KeyID != keyID || !bytes.Equal(priorKey, keyBytes) {
			return health, errors.New("operations: pinned_release_identity_changed")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return health, readErr
	}
	keyDigest := sha256.Sum256(keyBytes)
	pinnedKey := filepath.Join(releaseFeedDirectory, hex.EncodeToString(keyDigest[:])+".pub")
	if existing, readErr := custody.ReadRoot(pinnedKey, 16384, false); readErr == nil {
		if !bytes.Equal(existing, keyBytes) {
			return health, errors.New("operations: pinned_release_identity_changed")
		}
	} else if errors.Is(readErr, os.ErrNotExist) {
		if err = writeOperationBytes(pinnedKey, keyBytes, 0600); err != nil {
			return health, err
		}
	} else {
		return health, readErr
	}
	stage, err := os.MkdirTemp(releaseFeedDirectory, ".import-*")
	if err != nil {
		return health, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	if err = copyReleaseTree(bundle, stage); err != nil {
		return health, err
	}
	manifest, err := releasebuild.Verify(ctx, stage, pinnedKey, keyID)
	if err != nil {
		return health, errors.New("operations: signed_server_release_verification_failed")
	}
	if manifest.GetCustody() != "production" {
		return health, errors.New("operations: production_release_required")
	}
	var server bool
	for _, artifact := range manifest.GetArtifacts() {
		if artifact.GetProduct() == "lindmd" {
			server = true
		}
	}
	if !server {
		return health, errors.New("operations: server_release_artifact_required")
	}
	if prior, readErr := ReadReleaseFeedHealth(ReleaseFeedHealthPath); readErr == nil {
		comparison, compareErr := compareVersion(manifest.GetVersion(), prior.AvailableVersion)
		if compareErr != nil || comparison < 0 {
			return health, errors.New("operations: server_release_rollback_rejected")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return health, readErr
	}
	destination := filepath.Join(releaseFeedDirectory, manifest.GetVersion())
	if err = os.Rename(stage, destination); err != nil {
		return health, err
	}
	state := releaseFeedState{Directory: destination, PublicKey: pinnedKey, KeyID: keyID, ImportedAt: time.Now().UTC()}
	if err = writeOperationJSON(releaseFeedStatePath, state, 0600); err != nil {
		return health, err
	}
	return checkRelease(ctx)
}

// CheckRelease re-verifies the retained export and refreshes the installed
// comparison after an upgrade. It performs no public-network discovery.
func CheckRelease(ctx context.Context) (health ReleaseFeedHealth, err error) {
	lease, err := AcquireUpgradeLease(ctx)
	if err != nil {
		return health, err
	}
	defer func() { err = errors.Join(err, lease.Close()) }()
	return checkRelease(ctx)
}

func checkRelease(ctx context.Context) (health ReleaseFeedHealth, err error) {
	if os.Geteuid() != 0 {
		return health, errors.New("operations: root_required")
	}
	var state releaseFeedState
	data, err := custody.ReadRoot(releaseFeedStatePath, 16<<10, false)
	if err != nil {
		return health, err
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return health, errors.New("operations: invalid_release_feed_state")
	}
	manifest, err := releasebuild.Verify(ctx, state.Directory, state.PublicKey, state.KeyID)
	if err != nil {
		return health, errors.New("operations: signed_server_release_verification_failed")
	}
	comparison, err := compareVersion(manifest.GetVersion(), buildinfo.Current().Version)
	if err != nil {
		return health, err
	}
	health = ReleaseFeedHealth{ImportedAt: state.ImportedAt, InstalledVersion: buildinfo.Current().Version, AvailableVersion: manifest.GetVersion(), UpdateAvailable: comparison > 0, Verified: true}
	if notice := manifest.GetServerNotice(); notice != nil {
		if time.Unix(notice.GetIssuedAt(), 0).After(time.Now().Add(5 * time.Minute)) {
			return health, errors.New("operations: release_notice_clock_invalid")
		}
		health.ExpiresAt = time.Unix(notice.GetExpiresAt(), 0).UTC()
		health.SecurityUpdate = notice.GetSecurityUpdate()
		health.AdvisoryIDs = append([]string(nil), notice.GetAdvisoryIds()...)
		sort.Strings(health.AdvisoryIDs)
	}
	if err = writeOperationJSON(ReleaseFeedHealthPath, health, 0644); err != nil {
		return health, err
	}
	return health, nil
}

// ImportedRelease re-verifies the private bundle under the caller's existing
// lease, which must remain held through staging and the native installer.
func (lease *UpgradeLease) ImportedRelease(ctx context.Context) (directory, key, keyID string, err error) {
	if err = lease.Validate(); err != nil {
		return "", "", "", err
	}
	health, err := checkRelease(ctx)
	if err != nil {
		return "", "", "", err
	}
	if health.ExpiresAt.IsZero() || !health.ExpiresAt.After(time.Now()) {
		return "", "", "", errors.New("operations: current_signed_release_notice_required")
	}
	if !health.UpdateAvailable {
		return "", "", "", errors.New("operations: newer_server_release_required")
	}
	data, err := custody.ReadRoot(releaseFeedStatePath, 16<<10, false)
	if err != nil {
		return "", "", "", err
	}
	var state releaseFeedState
	if err = json.Unmarshal(data, &state); err != nil {
		return "", "", "", err
	}
	return state.Directory, state.PublicKey, state.KeyID, nil
}

func compareVersion(left, right string) (int, error) {
	parse := func(value string) ([3]uint64, error) {
		var result [3]uint64
		parts := strings.Split(value, ".")
		if len(parts) != 3 {
			return result, errors.New("operations: release_version_unavailable")
		}
		for i, part := range parts {
			number, err := strconv.ParseUint(part, 10, 64)
			if err != nil || (len(part) > 1 && part[0] == '0') {
				return result, errors.New("operations: invalid_release_version")
			}
			result[i] = number
		}
		return result, nil
	}
	l, err := parse(left)
	if err != nil {
		return 0, err
	}
	r, err := parse(right)
	if err != nil {
		return 0, err
	}
	for i := range l {
		if l[i] < r[i] {
			return -1, nil
		}
		if l[i] > r[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func writeOperationJSON(path string, value any, mode os.FileMode) (err error) {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeOperationBytes(path, data, mode)
}

func writeOperationBytes(path string, data []byte, mode os.FileMode) (err error) {
	parent, _, err := custody.OpenRoot(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	file, err := os.CreateTemp(filepath.Dir(path), ".operations-*")
	if err != nil {
		return err
	}
	defer func() {
		removeErr := os.Remove(file.Name())
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	if err = file.Chmod(mode); err != nil {
		return errors.Join(err, file.Close())
	}
	if _, err = file.Write(data); err != nil {
		return errors.Join(err, file.Close())
	}
	if err = errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	return parent.Sync()
}

func copyReleaseTree(source, destination string) (err error) {
	root, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	var total int64
	var entries int
	return fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("operations: release_symlink_rejected")
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(destination, name), 0700)
		}
		entries++
		if entries > 65536 {
			return errors.New("operations: release_inventory_capacity")
		}
		input, err := root.Open(name)
		if err != nil {
			return err
		}
		info, err := input.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return errors.Join(errors.New("operations: regular_release_file_required"), err, input.Close())
		}
		if info.Size() < 0 || info.Size() > maxArchive-total {
			return errors.Join(errors.New("operations: release_size_exceeded"), input.Close())
		}
		total += info.Size()
		output, err := os.OpenFile(filepath.Join(destination, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.Join(err, input.Close())
		}
		_, copyErr := io.Copy(&boundedWriter{output, info.Size()}, input)
		return errors.Join(copyErr, input.Close(), output.Close())
	})
}
