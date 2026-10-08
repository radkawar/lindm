// Package journal owns the executor's protected, single-writer authority state.
// Opening a damaged or incomplete installation never recreates it.
package journal

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal/journaldb"
	"lindm/internal/protodata"
)

const (
	markerName        = "installation"
	databaseName      = "journal.sqlite"
	maximumStateBytes = 1 << 20
	applicationID     = 1279872580
)

var (
	ErrUnprovisioned = errors.New("executor is unprovisioned")
	ErrRecoveryHold  = errors.New("executor state requires recovery")
	ErrAlreadyOpen   = errors.New("executor state already has an owner")
	ErrConflict      = errors.New("executor journal revision changed")
	ErrClosed        = errors.New("executor journal is closed")
)

//go:embed schema.sql
var schema string

// Store holds the directory lock until Close. Its caller must enforce root-only
// initialization and perform cryptographic/transition validation before Update.
// No method logs or includes serialized state in an error.
type Store struct {
	mu             sync.Mutex
	dir            *os.File
	db             *sql.DB
	queries        *journaldb.Queries
	validator      protovalidate.Validator
	installationID string
}

// Open opens an existing protected installation. The directory must already
// exist, be owned by this process's effective UID and have exactly mode 0700.
// Production executor startup separately requires effective UID zero.
func Open(ctx context.Context, directory string) (*Store, error) {
	return open(ctx, directory, nil)
}

// Initialize durably records the provisioning intent before creating the journal.
// It accepts only a previously empty installation. A partial earlier attempt is
// recovery hold, never permission to generate replacement identity authority.
func Initialize(ctx context.Context, directory string, initial *agentv1.ExecutorJournalState) (*Store, error) {
	if initial == nil {
		return nil, errors.New("missing initial executor state")
	}
	return open(ctx, directory, initial)
}

func open(ctx context.Context, directory string, initial *agentv1.ExecutorJournalState) (_ *Store, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.ExecutorJournalState{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, fmt.Errorf("compile executor state schema: %w", err)
	}
	fd, err := openProtectedDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("open protected executor directory: %w", err)
	}
	s := &Store{dir: os.NewFile(uintptr(fd), "executor-directory"), validator: validator}
	defer func() {
		if resultErr != nil {
			_ = s.Close()
		}
	}()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if info.Uid != uint32(os.Geteuid()) || info.Mode&07777 != 0700 {
		return nil, ErrRecoveryHold
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyOpen
		}
		return nil, err
	}
	marker, markerErr := s.readMarker()
	databaseExists, err := s.checkFile(databaseName)
	if err != nil {
		return nil, err
	}
	for _, sidecar := range []string{databaseName + "-wal", databaseName + "-shm", databaseName + "-journal"} {
		exists, err := s.checkFile(sidecar)
		if err != nil || exists && !databaseExists {
			return nil, ErrRecoveryHold
		}
	}
	if errors.Is(markerErr, os.ErrNotExist) && !databaseExists {
		if initial == nil {
			return nil, ErrUnprovisioned
		}
		s.installationID = initial.GetInstallationId()
		encoded, err := s.encode(initial)
		if err != nil {
			return nil, err
		}
		if err := s.createFile(markerName, []byte(s.installationID+"\n")); err != nil {
			return nil, err
		}
		// The marker is durable before any SQLite file exists. A crash at any
		// later point leaves an explicit recovery condition, never a new device.
		if err := s.dir.Sync(); err != nil {
			return nil, err
		}
		if err := s.createFile(databaseName, nil); err != nil {
			return nil, err
		}
		if err := s.connect(ctx); err != nil {
			return nil, err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return nil, errors.New("initialize executor schema failed")
		}
		if err := s.queries.WithTx(tx).InitializeState(ctx, encoded); err != nil {
			return nil, errors.New("initialize executor state failed")
		}
		if err := tx.Commit(); err != nil {
			return nil, errors.New("commit executor initialization failed")
		}
		if err := s.dir.Sync(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if markerErr != nil || !databaseExists {
		return nil, ErrRecoveryHold
	}
	if initial != nil {
		return nil, errors.New("executor is already provisioned")
	}
	s.installationID = marker
	if err := s.connect(ctx); err != nil {
		return nil, stateReadError(ctx)
	}
	if err := s.verifyDatabase(ctx); err != nil {
		return nil, err
	}
	if _, _, err := s.Load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) connect(ctx context.Context) error {
	// SQLite canonicalizes proc-fd paths back to ordinary paths. The descriptor
	// alone is NOT a filesystem boundary: openProtectedDirectory also proves
	// that an unprivileged actor cannot rename any component of this ancestry.
	// SQLite must open an existing file, never silently create one.
	uri := url.URL{Scheme: "file", Path: "/proc/self/fd/" + strconv.Itoa(int(s.dir.Fd())) + "/" + databaseName}
	params := url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"busy_timeout(5000)", "foreign_keys(ON)", "journal_mode(WAL)", "synchronous(FULL)", "trusted_schema(OFF)"}}
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
	s.queries = journaldb.New(db)
	// sqlc does not emit PRAGMA statements. These fixed connection/database
	// metadata checks are the only handwritten queries; state DML is generated.
	var journalMode string
	var synchronous int
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return err
	}
	if journalMode != "wal" || synchronous != 2 {
		return errors.New("executor durability settings rejected")
	}
	return nil
}

func (s *Store) verifyDatabase(ctx context.Context) error {
	var version, id int
	var integrity string
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return stateReadError(ctx)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&id); err != nil {
		return stateReadError(ctx)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&integrity); err != nil {
		return stateReadError(ctx)
	}
	if version != 1 || id != applicationID || integrity != "ok" {
		return ErrRecoveryHold
	}
	return nil
}

// Load returns a separately decoded state and its compare-and-swap revision.
func (s *Store) Load(ctx context.Context) (*agentv1.ExecutorJournalState, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	row, err := s.queries.ReadState(ctx)
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	if row.Revision < 1 || len(row.State) > maximumStateBytes {
		return nil, 0, ErrRecoveryHold
	}
	state := new(agentv1.ExecutorJournalState)
	if err := proto.Unmarshal(row.State, state); err != nil {
		return nil, 0, ErrRecoveryHold
	}
	if err := s.validate(state); err != nil {
		return nil, 0, ErrRecoveryHold
	}
	return state, row.Revision, nil
}

// Update commits a complete validated state at the caller's expected revision.
// Success means SQLite's FULL-synchronous transaction committed, not just that
// an in-memory object changed. Ownership/transition checks belong to executor.
func (s *Store) Update(ctx context.Context, revision int64, state *agentv1.ExecutorJournalState) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if revision < 1 || revision == math.MaxInt64 {
		return 0, ErrConflict
	}
	encoded, err := s.encode(state)
	if err != nil {
		return 0, err
	}
	changed, err := s.queries.ReplaceState(ctx, journaldb.ReplaceStateParams{State: encoded, Revision: revision})
	if err != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("commit executor state failed")
	}
	if changed != 1 {
		return 0, ErrConflict
	}
	return revision + 1, nil
}

func (s *Store) validate(state *agentv1.ExecutorJournalState) error {
	if state == nil || state.GetInstallationId() != s.installationID {
		return ErrRecoveryHold
	}
	id, err := uuid.Parse(s.installationID)
	if err != nil || id == uuid.Nil || id.String() != s.installationID {
		return ErrRecoveryHold
	}
	if err := protodata.ValidateClosed(state.ProtoReflect()); err != nil {
		return ErrRecoveryHold
	}
	if err := s.validator.Validate(state); err != nil {
		return errors.New("invalid executor state schema")
	}
	return nil
}

func (s *Store) encode(state *agentv1.ExecutorJournalState) ([]byte, error) {
	if err := s.validate(state); err != nil {
		return nil, err
	}
	if proto.Size(state) > maximumStateBytes {
		return nil, errors.New("executor state exceeds size limit")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(state)
	if err != nil {
		return nil, errors.New("encode executor state failed")
	}
	return encoded, nil
}

func (s *Store) checkFile(name string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(s.dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return false, ErrRecoveryHold
	}
	return true, nil
}

func (s *Store) readMarker() (string, error) {
	exists, err := s.checkFile(markerName)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", os.ErrNotExist
	}
	fd, err := unix.Openat(int(s.dir.Fd()), markerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "executor-marker")
	defer func() { _ = file.Close() }()
	var data [38]byte
	n, err := file.Read(data[:])
	if err != nil || n != 37 || data[36] != '\n' {
		return "", ErrRecoveryHold
	}
	id, err := uuid.ParseBytes(data[:36])
	if err != nil || id == uuid.Nil || !bytes.Equal([]byte(id.String()), data[:36]) {
		return "", ErrRecoveryHold
	}
	return id.String(), nil
}

func (s *Store) createFile(name string, data []byte) error {
	fd, err := unix.Openat(int(s.dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "executor-state")
	defer func() { _ = file.Close() }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result error
	if s.db != nil {
		result = s.db.Close()
		s.db = nil
	}
	if s.dir != nil {
		result = errors.Join(result, s.dir.Close())
		s.dir = nil
	}
	return result
}

func openProtectedDirectory(directory string) (int, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		var info unix.Stat_t
		if err := unix.Fstat(fd, &info); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		// Trusted sticky directories (notably /tmp) cannot rename an entry
		// owned by this UID/root. Every next component must itself have a
		// trusted owner, so sticky ancestry does not admit another UID's tree.
		if info.Uid != 0 && info.Uid != uint32(os.Geteuid()) ||
			info.Mode&0022 != 0 && info.Mode&unix.S_ISVTX == 0 {
			_ = unix.Close(fd)
			return -1, ErrRecoveryHold
		}
		if component == "" {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	// The caller separately requires the final directory to be current-UID
	// owned with exactly 0700 before locking it or accessing any state.
	return fd, nil
}

func stateReadError(ctx context.Context) error {
	// A request deadline or shutdown says nothing about journal integrity.
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrRecoveryHold
}
