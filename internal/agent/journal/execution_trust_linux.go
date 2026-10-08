package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal/journaldb"
	"lindm/internal/protodata"
)

// executionTrustDDL matches the execution_trust table in schema.sql. Fresh
// installations execute schema.sql; this statement is only the v1 migration.
func executionTrustDDL() string {
	return fmt.Sprintf(`CREATE TABLE execution_trust (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state BLOB NOT NULL CHECK (length(state) BETWEEN 1 AND %d)
) STRICT`, maximumTrustBytes)
}

func unconfiguredExecutionTrust(installationID string) *agentv1.ExecutionTrustState {
	return &agentv1.ExecutionTrustState{FormatVersion: 1, InstallationId: installationID}
}

// migrateSchema advances a validated v1 journal to v2 without rewriting the
// authority record. A v2 database is never repaired here.
func (s *Store) migrateSchema(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return stateReadError(ctx)
	}
	switch version {
	case priorSchemaVersion:
		return s.migrateV1(ctx)
	case schemaVersion:
		return nil
	default:
		return ErrRecoveryHold
	}
}

func (s *Store) migrateV1(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrRecoveryHold
	}
	defer func() { _ = tx.Rollback() }()
	exists, err := executionTrustTableExists(ctx, tx)
	if err != nil {
		return stateReadError(ctx)
	}
	// A v1 stamp on a database that already has the trust table is damage.
	// Do not replace that row or bless a new one.
	if exists {
		return ErrRecoveryHold
	}
	row, err := s.queries.WithTx(tx).ReadState(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if _, err := s.decodeAuthority(row.Revision, row.State); err != nil {
		return err
	}
	encoded, err := s.encodeTrust(unconfiguredExecutionTrust(s.installationID))
	if err != nil {
		return errors.New("initialize execution trust failed")
	}
	if _, err := tx.ExecContext(ctx, executionTrustDDL()); err != nil {
		return stateReadError(ctx)
	}
	if err := s.queries.WithTx(tx).InitializeExecutionTrust(ctx, encoded); err != nil {
		return stateReadError(ctx)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return stateReadError(ctx)
	}
	if err := tx.Commit(); err != nil {
		return stateReadError(ctx)
	}
	return nil
}

func executionTrustTableExists(ctx context.Context, q journaldb.DBTX) (bool, error) {
	var present int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'execution_trust'`).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// LoadExecutionTrust returns a separately decoded execution-trust record and
// its compare-and-swap revision. That revision is independent of authority state.
func (s *Store) LoadExecutionTrust(ctx context.Context) (*agentv1.ExecutionTrustState, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	return s.loadExecutionTrust(ctx, s.queries)
}

func (s *Store) loadExecutionTrust(ctx context.Context, q *journaldb.Queries) (*agentv1.ExecutionTrustState, int64, error) {
	row, err := q.ReadExecutionTrust(ctx)
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	state, err := s.decodeExecutionTrust(row.Revision, row.State)
	if err != nil {
		return nil, 0, err
	}
	return state, row.Revision, nil
}

func (s *Store) decodeExecutionTrust(revision int64, encoded []byte) (*agentv1.ExecutionTrustState, error) {
	if revision < 1 || len(encoded) == 0 || len(encoded) > maximumTrustBytes {
		return nil, ErrRecoveryHold
	}
	state := new(agentv1.ExecutionTrustState)
	if err := proto.Unmarshal(encoded, state); err != nil {
		return nil, ErrRecoveryHold
	}
	if err := s.validateTrust(state); err != nil {
		return nil, ErrRecoveryHold
	}
	return state, nil
}

// UpdateExecutionTrust commits one complete trust record at the caller's
// expected trust-row revision. Fences and a bad compare-and-swap leave both
// the trust row and authority record unchanged. Cryptographic checks belong
// to the executor. Success means the FULL-synchronous transaction committed.
func (s *Store) UpdateExecutionTrust(ctx context.Context, revision int64, state *agentv1.ExecutionTrustState) (int64, error) {
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("commit execution trust failed")
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	current, currentRevision, err := s.loadExecutionTrust(ctx, q)
	if err != nil {
		return 0, err
	}
	if currentRevision != revision {
		return 0, ErrConflict
	}
	encoded, err := s.encodeTrust(state)
	if err != nil {
		return 0, err
	}
	if err := rejectTrustTransition(current, state); err != nil {
		return 0, err
	}
	changed, err := q.ReplaceExecutionTrust(ctx, journaldb.ReplaceExecutionTrustParams{State: encoded, Revision: revision})
	if err != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("commit execution trust failed")
	}
	if changed != 1 {
		return 0, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("commit execution trust failed")
	}
	return revision + 1, nil
}

func (s *Store) validateTrust(state *agentv1.ExecutionTrustState) error {
	if state == nil || state.GetInstallationId() != s.installationID {
		return ErrTrustRejected
	}
	id, err := uuid.Parse(state.GetInstallationId())
	if err != nil || id == uuid.Nil || id.String() != state.GetInstallationId() {
		return ErrTrustRejected
	}
	if err := protodata.ValidateClosed(state.ProtoReflect()); err != nil {
		return ErrTrustRejected
	}
	if err := s.validator.Validate(state); err != nil {
		return ErrTrustRejected
	}
	return nil
}

func (s *Store) encodeTrust(state *agentv1.ExecutionTrustState) ([]byte, error) {
	if err := s.validateTrust(state); err != nil {
		return nil, err
	}
	if proto.Size(state) > maximumTrustBytes {
		return nil, ErrTrustRejected
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(state)
	if err != nil {
		return nil, errors.New("encode execution trust failed")
	}
	if len(encoded) == 0 || len(encoded) > maximumTrustBytes {
		return nil, ErrTrustRejected
	}
	return encoded, nil
}

func rejectTrustTransition(current, next *agentv1.ExecutionTrustState) error {
	if executionTrustConfigured(current) && !executionTrustConfigured(next) {
		return ErrTrustRejected
	}
	if current.GetRoot() != nil && next.GetRoot() != nil && next.GetRoot().GetVersion() < current.GetRoot().GetVersion() {
		return ErrTrustRejected
	}
	if next.GetDelegationVersion() <= current.GetDelegationVersion() {
		return ErrTrustRejected
	}
	if next.GetMinimumRecoveryEpoch() < current.GetMinimumRecoveryEpoch() {
		return ErrTrustRejected
	}
	if acceptedAtBefore(next.GetAcceptedAt(), current.GetAcceptedAt()) {
		return ErrTrustRejected
	}
	return nil
}

func executionTrustConfigured(state *agentv1.ExecutionTrustState) bool {
	return state.GetRoot() != nil && state.GetAcceptedAt() != nil && len(state.GetDelegationEnvelope()) > 0 && len(state.GetRequestSha256()) == 32 && state.GetDelegationVersion() > 0
}

func acceptedAtBefore(next, current *timestamppb.Timestamp) bool {
	if next == nil || current == nil || next.CheckValid() != nil || current.CheckValid() != nil {
		return false
	}
	return next.AsTime().Before(current.AsTime())
}
