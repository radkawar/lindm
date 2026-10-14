// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strconv"
	"sync"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/spool/spooldb"
	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
)

//go:embed schema.sql
var schemaSQL string

// Store is the sole writer of one unprivileged spool directory. Close releases
// the flock. Methods do not log observation contents.
type Store struct {
	mu            sync.Mutex
	dir           *os.File
	db            *sql.DB
	queries       *spooldb.Queries
	validator     protovalidate.Validator
	identity      Identity
	stored        Identity
	needsSync     bool
	reason        Reason
	lossMayRemain bool
	closed        bool
	// afterCommit exercises cancellation at the durable metadata/filesystem
	// boundary. It is nil outside failure-injection tests.
	afterCommit func()
	// afterPendingPackageRead exercises cancellation after SQLite has returned
	// immutable manifest bytes, before decoding. It is nil outside tests.
	afterPendingPackageRead func()
}

// Open locks an existing 0700 directory owned by this process. An empty
// directory is an unsynchronized spool, not permission to allocate sequence 1.
// A missing or damaged database still returns a store so Synchronize can run
// after the server fence. An unsafe ancestry or mode is not recoverable here.
func Open(ctx context.Context, directory string, id Identity) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id.Deployment == uuid.Nil || id.Device == uuid.Nil || id.Generation == uuid.Nil {
		return nil, ErrInvalid
	}
	validator, err := protovalidate.New(
		protovalidate.WithMessages(&inventoryv1.NativeObservation{}, &inventoryv1.PackageBatch{}, &devicev1.PackageSnapshotManifest{}),
		protovalidate.WithDisableLazy(),
	)
	if err != nil {
		return nil, errors.New("compile observation spool schema")
	}
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		if errors.Is(err, statefs.ErrUnsafe) {
			return nil, ErrUnsafe
		}
		return nil, fmt.Errorf("open observation spool directory: %w", err)
	}
	s := &Store{dir: os.NewFile(uintptr(fd), "observation-spool"), validator: validator, identity: id}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = s.dir.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyOpen
		}
		return nil, err
	}
	if err := s.load(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) load(ctx context.Context) error {
	names, err := s.rootNames()
	if err != nil {
		return err
	}
	dbExists := false
	sidecar := false
	collectionsPresent := false
	var extra []string
	var temps []string
	for _, name := range names {
		switch {
		case name == databaseName:
			dbExists = true
		case name == databaseName+"-wal" || name == databaseName+"-shm" || name == databaseName+"-journal":
			sidecar = true
		case name == collectionsName:
			collectionsPresent = true
		case name == transportStatusName:
			if err := s.checkTransportStatus(); err != nil {
				if errors.Is(err, ErrUnrecognized) {
					s.markNeeds(ReasonUnrecognized)
					continue
				}
				return err
			}
		case isTransportTemp(name):
			temps = append(temps, name)
		default:
			extra = append(extra, name)
		}
	}
	for _, name := range temps {
		if err := s.removeTransportTemp(name); err != nil {
			if errors.Is(err, ErrUnrecognized) {
				s.markNeeds(ReasonUnrecognized)
				continue
			}
			return err
		}
	}
	if len(temps) > 0 {
		if err := s.dir.Sync(); err != nil {
			return err
		}
	}
	if len(extra) > 0 {
		s.markNeeds(ReasonUnrecognized)
	}
	if !dbExists {
		if sidecar || collectionsPresent || len(extra) > 0 || s.reason == ReasonUnrecognized {
			s.markNeeds(ReasonMissing)
		} else {
			s.markNeeds(ReasonUnsynchronized)
		}
		return nil
	}
	for _, name := range names {
		if name == collectionsName || name == transportStatusName || isTransportTemp(name) {
			continue
		}
		if _, err := s.checkFile(name); err != nil {
			if errors.Is(err, ErrUnsafe) {
				s.markNeeds(ReasonCorrupt)
				return nil
			}
			return err
		}
	}
	if err := s.connect(ctx); err != nil {
		s.closeDB()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.markNeeds(ReasonCorrupt)
		return nil
	}
	if err := s.chmodSidecars(); err != nil {
		return err
	}
	if err := s.verifyDatabase(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.closeDB()
		s.markNeeds(ReasonCorrupt)
		return nil
	}
	return s.verifyContents(ctx)
}

func (s *Store) markNeeds(reason Reason) {
	s.needsSync = true
	if reason != ReasonUnsynchronized && reason != ReasonFence {
		s.lossMayRemain = true
	}
	if s.reason == "" || reasonRank(reason) > reasonRank(s.reason) {
		s.reason = reason
	}
}

func reasonRank(reason Reason) int {
	switch reason {
	case ReasonUnrecognized:
		return 6
	case ReasonCorrupt:
		return 5
	case ReasonScopeChange:
		return 4
	case ReasonDamagedPending:
		return 3
	case ReasonMissing:
		return 2
	case ReasonUnsynchronized, ReasonFence:
		return 1
	default:
		return 0
	}
}

func (s *Store) connect(ctx context.Context) error {
	uri := url.URL{Scheme: "file", Path: "/proc/self/fd/" + strconv.Itoa(int(s.dir.Fd())) + "/" + databaseName}
	params := url.Values{
		"mode":    {"rw"},
		"_txlock": {"immediate"},
		"_pragma": {"busy_timeout(5000)", "foreign_keys(ON)", "trusted_schema(OFF)"},
	}
	uri.RawQuery = params.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return err
	}
	s.db = db
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA page_size = 4096"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA auto_vacuum = FULL"); err != nil {
		return err
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&journalMode); err != nil {
		return err
	}
	if journalMode != "wal" {
		return errors.New("observation spool journal mode rejected")
	}
	if _, err := db.ExecContext(ctx, "PRAGMA synchronous = FULL"); err != nil {
		return err
	}
	var pages int
	if err := db.QueryRowContext(ctx, "PRAGMA max_page_count = 2048").Scan(&pages); err != nil {
		return err
	}
	if pages != maxPageCount {
		return errors.New("observation spool page cap rejected")
	}
	var journalLimit int
	if err := db.QueryRowContext(ctx, "PRAGMA journal_size_limit = 4194304").Scan(&journalLimit); err != nil {
		return err
	}
	if journalLimit != journalSizeLimit {
		return errors.New("observation spool journal cap rejected")
	}
	s.queries = spooldb.New(db)
	return nil
}

func (s *Store) verifyDatabase(ctx context.Context) error {
	var version, id, page, vacuum, synchronous, foreignKeys, pages, journalLimit int
	var journalMode, integrity string
	checks := []struct {
		query string
		dest  any
	}{
		{"PRAGMA user_version", &version},
		{"PRAGMA application_id", &id},
		{"PRAGMA page_size", &page},
		{"PRAGMA auto_vacuum", &vacuum},
		{"PRAGMA synchronous", &synchronous},
		{"PRAGMA foreign_keys", &foreignKeys},
		{"PRAGMA max_page_count", &pages},
		{"PRAGMA journal_size_limit", &journalLimit},
	}
	for _, check := range checks {
		if err := s.db.QueryRowContext(ctx, check.query).Scan(check.dest); err != nil {
			return err
		}
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return err
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&integrity); err != nil {
		return err
	}
	if version != userVersion || id != applicationID || page != pageSize || vacuum != 1 || synchronous != 2 || foreignKeys != 1 || pages != maxPageCount || journalLimit != journalSizeLimit || journalMode != "wal" || integrity != "ok" {
		return errors.New("observation spool durability settings rejected")
	}
	physical, err := s.metadataPhysical()
	if err != nil {
		return err
	}
	sqliteBytes, err := s.sqlitePhysical()
	if err != nil {
		return err
	}
	if sqliteBytes > sqlitePhysicalBudget || physical > MetadataBudget {
		return errors.New("observation spool metadata budget exceeded")
	}
	return nil
}

func (s *Store) closeDB() {
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
		s.queries = nil
	}
}

// Recovery reports whether fresh allocations are allowed. It does not contact
// the server and it does not allocate a sequence.
func (s *Store) Recovery(ctx context.Context) (Recovery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return Recovery{}, err
	}
	out := Recovery{
		NeedsSync:                   s.needsSync,
		Reason:                      s.reason,
		LostAdmittedUploadMayRemain: s.lossMayRemain,
		Identity:                    s.identity,
		Stored:                      s.stored,
	}
	if s.db == nil || s.needsSync && s.reason == ReasonScopeChange {
		return out, nil
	}
	if s.db == nil {
		return out, nil
	}
	row, err := s.queries.ReadScope(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return Recovery{}, ctx.Err()
		}
		return out, nil
	}
	if row.LossRecovered != 0 {
		out.LostAdmittedUploadMayRemain = true
	}
	if s.reason == ReasonNone || s.reason == ReasonFence || s.reason == ReasonUnsynchronized || s.reason == ReasonDamagedPending || !s.needsSync {
		out.HostAllocated = uint64(row.HostAllocated)
		out.PackageAllocated = uint64(row.PackageAllocated)
		out.HostHighwater = uint64(row.HostHighwater)
		out.PackageHighwater = uint64(row.PackageHighwater)
	}
	return out, nil
}

// Synchronize applies server high-water marks obtained from GetSyncState under
// the current executor session. On a healthy same-scope spool it only raises
// counters. On loss it rebuilds metadata and does not claim the server open
// upload was reset. Unrecognized entries are left in place.
func (s *Store) Synchronize(ctx context.Context, hostHigh, packageHigh uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return err
	}
	if hostHigh > math.MaxInt64 || packageHigh > math.MaxInt64 {
		return ErrInvalid
	}
	if s.reason == ReasonUnrecognized {
		return ErrUnrecognized
	}
	if !s.needsSync || s.reason == ReasonFence || (s.reason == ReasonUnsynchronized && s.db != nil) {
		if err := s.raise(ctx, int64(hostHigh), int64(packageHigh)); err != nil {
			return err
		}
		s.needsSync = false
		s.reason = ReasonNone
		return nil
	}
	if s.reason == ReasonDamagedPending && s.db != nil && s.stored == s.identity {
		if err := s.discardPayloads(ctx); err != nil {
			return err
		}
		if err := s.queries.SetLossRecovered(ctx); err != nil {
			return dbErr(ctx, err)
		}
		if err := s.clearRecovery(ctx); err != nil {
			return err
		}
		if err := s.raise(ctx, int64(hostHigh), int64(packageHigh)); err != nil {
			return err
		}
		s.needsSync = false
		s.reason = ReasonNone
		s.lossMayRemain = true
		return s.dir.Sync()
	}
	return s.rebuild(ctx, int64(hostHigh), int64(packageHigh))
}

func (s *Store) rebuild(ctx context.Context, hostHigh, packageHigh int64) error {
	loss := s.reason != ReasonUnsynchronized || s.lossMayRemain
	if s.db != nil {
		if err := s.deleteTracked(ctx); err != nil {
			return err
		}
		names, err := s.collectionNames()
		if err != nil {
			return err
		}
		if len(names) > 0 {
			s.markNeeds(ReasonUnrecognized)
			return ErrUnrecognized
		}
		s.closeDB()
	} else if err := s.deleteUntrackedCollections(); err != nil {
		s.markNeeds(ReasonUnrecognized)
		return err
	}
	if err := s.removeSQLiteFiles(); err != nil {
		return err
	}
	if err := s.createDatabase(ctx, hostHigh, packageHigh, loss, 1); err != nil {
		s.closeDB()
		s.markNeeds(ReasonCorrupt)
		return err
	}
	s.needsSync = false
	s.reason = ReasonNone
	s.stored = s.identity
	s.lossMayRemain = loss
	return nil
}

func (s *Store) deleteUntrackedCollections() error {
	names, err := s.collectionNames()
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	for _, name := range names {
		if !canonicalUUID(name) {
			return ErrUnrecognized
		}
		if err := s.deleteCollection(name); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) createDatabase(ctx context.Context, hostHigh, packageHigh int64, loss bool, synced int64) error {
	if err := s.createEmpty(databaseName); err != nil {
		return err
	}
	if err := s.connect(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
		return errors.New("initialize observation spool schema failed")
	}
	lossBit := int64(0)
	if loss {
		lossBit = 1
	}
	if err := s.queries.WithTx(tx).InsertScope(ctx, spooldb.InsertScopeParams{
		Deployment:       s.identity.Deployment.String(),
		Device:           s.identity.Device.String(),
		Generation:       s.identity.Generation.String(),
		HostAllocated:    hostHigh,
		PackageAllocated: packageHigh,
		HostHighwater:    hostHigh,
		PackageHighwater: packageHigh,
		Synced:           synced,
		LossRecovered:    lossBit,
	}); err != nil {
		return errors.New("initialize observation spool scope failed")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("commit observation spool initialization failed")
	}
	if err := s.checkpoint(ctx); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.chmodSidecars(); err != nil {
		return err
	}
	if err := s.ensureCollections(); err != nil {
		return err
	}
	return s.dir.Sync()
}

func (s *Store) raise(ctx context.Context, hostHigh, packageHigh int64) error {
	row, err := s.queries.ReadScope(ctx)
	if err != nil {
		return dbErr(ctx, err)
	}
	next := spooldb.UpdateScopeCountersParams{
		HostAllocated:    max64(row.HostAllocated, hostHigh),
		PackageAllocated: max64(row.PackageAllocated, packageHigh),
		HostHighwater:    max64(row.HostHighwater, hostHigh),
		PackageHighwater: max64(row.PackageHighwater, packageHigh),
	}
	if next.HostAllocated == row.HostAllocated && next.PackageAllocated == row.PackageAllocated && next.HostHighwater == row.HostHighwater && next.PackageHighwater == row.PackageHighwater {
		return nil
	}
	changed, err := s.queries.UpdateScopeCounters(ctx, next)
	if err != nil {
		return dbErr(ctx, err)
	}
	if changed != 1 {
		return ErrConflict
	}
	return s.checkpoint(ctx)
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.db != nil {
		err = s.db.Close()
		s.db = nil
		s.queries = nil
	}
	if s.dir != nil {
		err = errors.Join(err, s.dir.Close())
		s.dir = nil
	}
	return err
}

func (s *Store) usable(ctx context.Context) error {
	if s.closed || s.dir == nil {
		return ErrClosed
	}
	return ctx.Err()
}

func (s *Store) ready(ctx context.Context) error {
	if err := s.usable(ctx); err != nil {
		return err
	}
	if s.needsSync || s.db == nil {
		return ErrNeedsSync
	}
	return nil
}

func (s *Store) queueable(ctx context.Context) error {
	if err := s.usable(ctx); err != nil {
		return err
	}
	switch s.reason {
	case ReasonNone, ReasonFence, ReasonUnsynchronized:
		return nil
	default:
		return ErrNeedsSync
	}
}

func (s *Store) inspectable(ctx context.Context) error {
	if err := s.usable(ctx); err != nil {
		return err
	}
	if s.db == nil {
		return ErrNeedsSync
	}
	switch s.reason {
	case ReasonNone, ReasonFence:
		return nil
	default:
		return ErrNeedsSync
	}
}

func (s *Store) ensureQueueDB(ctx context.Context) error {
	if s.db != nil {
		return nil
	}
	if s.reason != ReasonUnsynchronized {
		return ErrNeedsSync
	}
	if err := s.createDatabase(ctx, 0, 0, false, 0); err != nil {
		s.closeDB()
		_ = s.removeSQLiteFiles()
		s.needsSync = true
		s.reason = ReasonUnsynchronized
		return err
	}
	s.needsSync = true
	s.reason = ReasonUnsynchronized
	s.stored = s.identity
	return nil
}

func (s *Store) checkpoint(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	var busy, log, checkpointed int
	err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpointed)
	if err != nil {
		return dbErr(ctx, err)
	}
	return s.chmodSidecars()
}

func (s *Store) tx(ctx context.Context, fn func(*spooldb.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(s.queries.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.afterCommit != nil {
		s.afterCommit()
	}
	return nil
}

func dbErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return err
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func nextSequence(allocated int64) (int64, error) {
	if allocated < 0 || allocated == math.MaxInt64 {
		return 0, ErrCapacity
	}
	return allocated + 1, nil
}

func parseIdentity(deployment, device, generation string) (Identity, bool) {
	d, err := uuid.Parse(deployment)
	if err != nil || d == uuid.Nil || d.String() != deployment {
		return Identity{}, false
	}
	v, err := uuid.Parse(device)
	if err != nil || v == uuid.Nil || v.String() != device {
		return Identity{}, false
	}
	g, err := uuid.Parse(generation)
	if err != nil || g == uuid.Nil || g.String() != generation {
		return Identity{}, false
	}
	return Identity{Deployment: d, Device: v, Generation: g}, true
}

func (s *Store) validateObservation(obs *inventoryv1.NativeObservation) error {
	if obs == nil || obs.GetHost() == nil || obs.GetPackages() == nil {
		return ErrInvalid
	}
	if err := protodata.ValidateClosed(obs.ProtoReflect()); err != nil {
		return ErrInvalid
	}
	if err := s.validator.Validate(obs); err != nil {
		return ErrInvalid
	}
	if proto.Size(obs.GetHost()) > maxHostBytes {
		return ErrCapacity
	}
	return nil
}
