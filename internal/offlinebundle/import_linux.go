// SPDX-License-Identifier: Apache-2.0

//go:build linux

package offlinebundle

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"

	bundlev1 "lindm/gen/lindm/bundle/v1"
	"lindm/internal/advisory"
	"lindm/internal/auditkind"
	"lindm/internal/offlinebundle/bundledb"
	"lindm/internal/releasebuild"
	"lindm/internal/releaseupdate"
)

// importLockKey serializes imports across processes for the whole operation;
// LockBundleLedger additionally serializes ledger transactions.
const importLockKey int64 = 7340843010195847518

// ImporterConfig holds independently provisioned import authority. Paths are
// resolved server configuration; nothing here is read from a bundle.
type ImporterConfig struct {
	Pool *pgxpool.Pool
	// Directory is the server-owned private publication/staging root.
	Directory                      string
	SigningPublicKey, SigningKeyID string
	ReleasePublicKey, ReleaseKeyID string
	ReleaseRepository              string
	ReleaseSigners                 releaseupdate.RoleSigners
	ReleaseRoot                    []byte
	Advisories                     *advisory.Service
	Clock                          func() time.Time
}

// Importer admits signed offline bundles into one deployment.
type Importer struct {
	cfg      ImporterConfig
	verifier *Verifier
}

// Result is the operator-visible, nonsecret outcome of one import.
type Result struct {
	Sequence        uint64                       `json:"sequence"`
	BundleID        string                       `json:"bundle_id"`
	ManifestSHA256  string                       `json:"manifest_sha256"`
	ReleaseVersion  string                       `json:"release_version"`
	AlreadyImported bool                         `json:"already_imported"`
	Updates         *releaseupdate.OfflineImport `json:"updates,omitempty"`
	Repositories    int                          `json:"repositories"`
	Advisories      []string                     `json:"advisories"`
	ExpiresAt       time.Time                    `json:"expires_at"`
}

// NewImporter validates every dependency before any bundle is read.
func NewImporter(cfg ImporterConfig) (*Importer, error) {
	if cfg.Pool == nil || cfg.Directory == "" || cfg.ReleaseRepository == "" || len(cfg.ReleaseRoot) == 0 {
		return nil, errors.New("offlinebundle: database, directory, release repository and release root are required")
	}
	if len(cfg.ReleaseSigners.Root) != 0 || len(cfg.ReleaseSigners.Targets) != 0 || len(cfg.ReleaseSigners.Rollout) == 0 || len(cfg.ReleaseSigners.Snapshot) == 0 || len(cfg.ReleaseSigners.Timestamp) == 0 {
		return nil, errors.New("offlinebundle: online release custody only (rollout, snapshot, timestamp) is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if !filepath.IsAbs(cfg.Directory) {
		return nil, errors.New("offlinebundle: absolute bundle directory required")
	}
	info, err := os.Lstat(cfg.Directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("offlinebundle: bundle directory must be a private 0700 directory")
	}
	verifier, err := LoadVerifier(cfg.SigningPublicKey, cfg.SigningKeyID)
	if err != nil {
		return nil, err
	}
	if !keyIDPattern.MatchString(cfg.ReleaseKeyID) || cfg.ReleasePublicKey == "" {
		return nil, errors.New("offlinebundle: pinned release attestation key required")
	}
	return &Importer{cfg: cfg, verifier: verifier}, nil
}

// Import authenticates, stages, verifies and publishes one bundle. A failure
// before the final ledger commit leaves previously published data serving and
// the sequence resumable only with the identical signed manifest.
func (i *Importer) Import(ctx context.Context, directory string) (result *Result, err error) {
	bundle, err := Open(ctx, directory, i.verifier, i.cfg.Clock())
	if err != nil {
		return nil, err
	}
	manifest := bundle.Manifest
	result = &Result{Sequence: manifest.GetSequence(), BundleID: manifest.GetBundleId(), ManifestSHA256: hex.EncodeToString(bundle.ManifestSHA256[:]), ReleaseVersion: manifest.GetRelease().GetVersion(), ExpiresAt: manifest.GetExpiresAt().AsTime(), Repositories: len(manifest.GetRepositories())}
	if len(manifest.GetAdvisories()) > 0 && i.cfg.Advisories == nil {
		return nil, errors.New("offlinebundle: bundle carries advisory snapshots but no advisory service is configured")
	}
	conn, err := i.cfg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", importLockKey); err != nil {
		return nil, err
	}
	defer func() {
		unlock, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, unlockErr := conn.Exec(unlock, "SELECT pg_advisory_unlock($1)", importLockKey); unlockErr != nil {
			err = errors.Join(err, unlockErr)
		}
	}()
	already, err := i.admit(ctx, conn, bundle)
	if err != nil {
		return nil, err
	}
	if already {
		result.AlreadyImported = true
		return result, nil
	}
	staging, err := os.MkdirTemp(i.cfg.Directory, ".staging-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	staged, err := bundle.Stage(ctx, filepath.Join(staging, "bundle"))
	if err != nil {
		return nil, err
	}
	release, err := releasebuild.Verify(ctx, staged.Path(releaseDir), i.cfg.ReleasePublicKey, i.cfg.ReleaseKeyID)
	if err != nil {
		return nil, fmt.Errorf("verify staged release attestations: %w", err)
	}
	if release.GetVersion() != manifest.GetRelease().GetVersion() || release.GetAttestationKeyId() != manifest.GetRelease().GetAttestationKeyId() || int(manifest.GetRelease().GetArtifactCount()) != len(release.GetArtifacts()) || staged.files[releaseDir+"/release.json"].GetSha256() != manifest.GetRelease().GetManifestSha256() {
		return nil, fmt.Errorf("%w: release export differs from its bundle claim", ErrCorrupt)
	}
	result.Updates, err = releaseupdate.ImportOffline(ctx, releaseupdate.OfflineImportConfig{
		Directory: i.cfg.ReleaseRepository, Signers: i.cfg.ReleaseSigners, BootstrapRoot: i.cfg.ReleaseRoot,
		Source: staged.Path(updatesDir), TargetsVersion: manifest.GetUpdates().GetTargetsVersion(), Rings: manifest.GetUpdates().GetChannels(), Now: i.cfg.Clock,
	})
	if err != nil {
		return nil, fmt.Errorf("import offline TUF targets: %w", err)
	}
	for _, snapshot := range manifest.GetAdvisories() {
		if err := i.importAdvisory(ctx, staged, snapshot); err != nil {
			return nil, err
		}
		result.Advisories = append(result.Advisories, snapshot.GetSource().GetId())
	}
	for _, tree := range []string{reposDir, releaseDir} {
		if err := exchangeTree(staged.Path(tree), filepath.Join(i.cfg.Directory, tree)); err != nil {
			return nil, fmt.Errorf("publish %s: %w", tree, err)
		}
	}
	if err := i.finish(ctx, conn, bundle); err != nil {
		return nil, err
	}
	slog.Info("offline bundle imported", "sequence", manifest.GetSequence(), "bundle_id", manifest.GetBundleId(), "release", manifest.GetRelease().GetVersion(), "targets_version", result.Updates.TargetsVersion, "advisories", len(result.Advisories))
	return result, nil
}

func (i *Importer) importAdvisory(ctx context.Context, staged *Bundle, snapshot *bundlev1.AdvisorySnapshot) (err error) {
	id := snapshot.GetSource().GetId()
	input, err := os.Open(staged.Path(advisoryDir + "/" + id))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	request := advisory.Snapshot{Source: snapshot.GetSource(), Input: input, AcquiredAt: snapshot.GetAcquiredAt().AsTime(), Artifacts: snapshot.GetArtifacts()}
	if snapshot.GetSnapshotAt() != nil {
		at := snapshot.GetSnapshotAt().AsTime()
		request.SnapshotAt = &at
	}
	if err := i.cfg.Advisories.ImportSnapshot(ctx, request); err != nil {
		return fmt.Errorf("import advisory snapshot %s: %w", id, err)
	}
	return nil
}

// admit applies the replay ledger. It returns true when this exact manifest
// was already imported completely.
func (i *Importer) admit(ctx context.Context, conn *pgxpool.Conn, bundle *Bundle) (already bool, err error) {
	manifest := bundle.Manifest
	sequence := int64(manifest.GetSequence())
	bundleID, err := uuid.Parse(manifest.GetBundleId())
	if err != nil {
		return false, err
	}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		q := bundledb.New(tx)
		if err := q.LockBundleLedger(ctx); err != nil {
			return err
		}
		row, err := q.GetBundleImport(ctx, sequence)
		switch {
		case err == nil:
			if !bytes.Equal(row.ManifestSha256, bundle.ManifestSHA256[:]) || row.BundleID != bundleID {
				return ErrEquivocation
			}
			already = row.State == "imported"
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		highest, err := q.MaxBundleSequence(ctx)
		if err != nil {
			return err
		}
		if highest >= sequence {
			return ErrReplayed
		}
		return q.StartBundleImport(ctx, bundledb.StartBundleImportParams{
			Sequence: sequence, BundleID: bundleID, ManifestSha256: bundle.ManifestSHA256[:], SigningKeyID: manifest.GetSigningKeyId(),
			ReleaseVersion: manifest.GetRelease().GetVersion(),
			CreatedAt:      pgtype.Timestamptz{Time: manifest.GetCreatedAt().AsTime(), Valid: true},
			ExpiresAt:      pgtype.Timestamptz{Time: manifest.GetExpiresAt().AsTime(), Valid: true},
		})
	})
	return already, err
}

func (i *Importer) finish(ctx context.Context, conn *pgxpool.Conn, bundle *Bundle) error {
	manifest := bundle.Manifest
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		q := bundledb.New(tx)
		if err := q.LockBundleLedger(ctx); err != nil {
			return err
		}
		updated, err := q.FinishBundleImport(ctx, bundledb.FinishBundleImportParams{Sequence: int64(manifest.GetSequence()), ManifestSha256: bundle.ManifestSHA256[:]})
		if err != nil {
			return err
		}
		if updated != 1 {
			return errors.New("offlinebundle: import ledger changed during import")
		}
		return q.InsertBundleAudit(ctx, bundledb.InsertBundleAuditParams{
			ID: uuid.New(), Action: auditkind.OfflineBundleImported.String(), ResourceID: manifest.GetBundleId(),
			Sequence: fmt.Sprint(manifest.GetSequence()), Release: manifest.GetRelease().GetVersion(), Custody: manifest.GetCustody(),
		})
	})
}

// exchangeTree atomically replaces published with staged; the previous tree
// is left at the staged path for removal with the staging directory.
func exchangeTree(staged, published string) error {
	if err := os.Chmod(staged, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(published); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(staged, published); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, published, unix.RENAME_EXCHANGE); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(published))
}
