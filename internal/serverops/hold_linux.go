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
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

const restoreMarker = "/etc/lindm/restore-hold"

var ErrRestoreHold = errors.New("operations: restore_hold")

type restoreFence struct {
	Format       int
	TargetSHA256 string
	CreatedAt    time.Time
}

// Database identity intentionally excludes role, password and TLS paths; those
// change on a fresh host. Resolve the actual schema, rather than a search_path
// string, so separate private schemas do not fence each other's runtime.
func restoreTargetIdentity(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	if pool == nil {
		return "", errors.New("operations: recovery_state_unavailable")
	}
	var schema string
	if err := pool.QueryRow(ctx, "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid='server_recovery_state'::regclass").Scan(&schema); err != nil {
		return "", errors.New("operations: recovery_state_unavailable")
	}
	cfg := pool.Config().ConnConfig
	type endpoint struct {
		Host string
		Port uint16
	}
	target := struct {
		Database, Schema string
		Endpoints        []endpoint
	}{Database: cfg.Database, Schema: schema, Endpoints: []endpoint{{cfg.Host, cfg.Port}}}
	for _, fallback := range cfg.Fallbacks {
		candidate := endpoint{fallback.Host, fallback.Port}
		found := false
		for _, existing := range target.Endpoints {
			if existing == candidate {
				found = true
				break
			}
		}
		if !found {
			target.Endpoints = append(target.Endpoints, candidate)
		}
	}
	data, err := json.Marshal(target)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func readRestoreFence() (restoreFence, error) {
	var fence restoreFence
	data, err := custody.ReadRoot(restoreMarker, 4096, false)
	if err != nil {
		return fence, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&fence); err != nil {
		return fence, errors.New("operations: invalid_restore_marker")
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fence, errors.New("operations: invalid_restore_marker")
	}
	hash, err := hex.DecodeString(fence.TargetSHA256)
	if err != nil || len(hash) != sha256.Size || fence.Format != 1 || fence.CreatedAt.IsZero() {
		return fence, errors.New("operations: invalid_restore_marker")
	}
	return fence, nil
}

// CheckRestoreHoldPool is called before either listener or any background worker
// is created. A root-owned filesystem fence survives partial database restoration;
// the database fence is independent and remains authoritative on every replica.
func CheckRestoreHoldPool(ctx context.Context, pool *pgxpool.Pool) error {
	fence, markerErr := readRestoreFence()
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return markerErr
	}
	if pool == nil {
		return errors.New("operations: recovery_state_unavailable")
	}
	var hold bool
	if err := pool.QueryRow(ctx, "SELECT hold FROM server_recovery_state WHERE singleton").Scan(&hold); err != nil {
		return errors.New("operations: recovery_state_unavailable")
	}
	if hold {
		return ErrRestoreHold
	}
	if markerErr == nil {
		target, err := restoreTargetIdentity(ctx, pool)
		if err != nil {
			return err
		}
		if target == fence.TargetSHA256 {
			return ErrRestoreHold
		}
	}
	return nil
}

func enterRestoreHold(target string) (err error) {
	parent, _, err := custody.OpenRoot(filepath.Dir(restoreMarker), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(restoreMarker), unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0644)
	if errors.Is(err, unix.EEXIST) {
		fence, readErr := readRestoreFence()
		if readErr != nil {
			return readErr
		}
		if fence.TargetSHA256 != target {
			return errors.New("operations: another_target_restore_fenced")
		}
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), restoreMarker)
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := json.Marshal(restoreFence{Format: 1, TargetSHA256: target, CreatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	if err = file.Chmod(0644); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	return errors.Join(file.Sync(), parent.Sync())
}
