package journal

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal/journaldb"
	"lindm/internal/protodata"
)

var (
	ErrAccountLockNotFound = errors.New("account_lock_not_found")
	ErrAccountLockRejected = errors.New("account_lock_rejected")
	ErrAccountLockCapacity = errors.New("account_lock_capacity")
)

const maximumAccountLocks = 128
const maximumAccountLockBytes = 2 << 20

func accountOwned(phase agentv1.AccountLockPhase) bool {
	return phase == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLE_PENDING || phase == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLED || phase == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING
}

// CreateAccountLock commits every exact prior/expected state and ownership claim
// before any native effect. A repeated action or overlapping name/UID is rejected,
// including an interrupted action: this journal is never a retry queue.
func (s *Store) CreateAccountLock(ctx context.Context, ledger *agentv1.AccountLockLedger) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	encoded, err := s.encodeAccountLock(ledger)
	if err != nil {
		return 0, err
	}
	for _, entry := range ledger.GetAccounts() {
		if entry.GetReleaseActionId() != "" {
			return 0, ErrAccountLockRejected
		}
		if entry.GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLE_PENDING && entry.GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED {
			return 0, ErrAccountLockRejected
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	if _, err := q.ReadAccountLock(ctx, ledger.GetLockActionId()); err == nil {
		return 0, ErrAccountLockRejected
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, stateReadError(ctx)
	}
	count, err := q.AccountLockCount(ctx)
	if err != nil {
		return 0, stateReadError(ctx)
	}
	usage, err := q.ReadAccountLockUsage(ctx)
	if err != nil || usage != count {
		return 0, ErrRecoveryHold
	}
	if count >= maximumAccountLocks {
		return 0, ErrAccountLockCapacity
	}
	if err := q.InsertAccountLock(ctx, journaldb.InsertAccountLockParams{LockActionID: ledger.GetLockActionId(), Record: encoded}); err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	for _, entry := range ledger.GetAccounts() {
		prior := entry.GetPrior()
		owners, err := q.ReadAccountLockOwner(ctx, journaldb.ReadAccountLockOwnerParams{Username: prior.GetUsername(), Uid: int64(prior.GetUid())})
		if err != nil {
			return 0, stateReadError(ctx)
		}
		if len(owners) != 0 {
			return 0, ErrAccountLockRejected
		}
		if !accountOwned(entry.GetPhase()) {
			continue
		}
		if err := q.InsertAccountLockOwner(ctx, journaldb.InsertAccountLockOwnerParams{Username: prior.GetUsername(), Uid: int64(prior.GetUid()), LockActionID: ledger.GetLockActionId()}); err != nil {
			return 0, deviceActionWriteError(ctx)
		}
	}
	if changed, err := q.IncrementAccountLockUsage(ctx, count); err != nil || changed != 1 {
		return 0, deviceActionWriteError(ctx)
	}
	if err := tx.Commit(); err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	return 1, nil
}

// LoadAccountLock returns executor-private secret state, never RPC evidence.
func (s *Store) LoadAccountLock(ctx context.Context, actionID string) (*agentv1.AccountLockLedger, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	row, err := s.queries.ReadAccountLock(ctx, actionID)
	if errors.Is(err, sql.ErrNoRows) {
		count, countErr := s.queries.AccountLockCount(ctx)
		usage, usageErr := s.queries.ReadAccountLockUsage(ctx)
		if countErr != nil || usageErr != nil || count != usage {
			return nil, 0, ErrRecoveryHold
		}
		return nil, 0, ErrAccountLockNotFound
	}
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	ledger, err := s.decodeAccountLock(row)
	return ledger, row.Revision, err
}

// UpdateAccountLock allows only phase transitions, never rewriting the snapshots.
// RELEASE_PENDING must be committed before invoking a native restore. A crash in
// either pending phase is ambiguous and never permits automatic native replay.
func (s *Store) UpdateAccountLock(ctx context.Context, revision int64, next *agentv1.AccountLockLedger) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if revision < 1 || revision == math.MaxInt64 {
		return 0, ErrConflict
	}
	encoded, err := s.encodeAccountLock(next)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	row, err := q.ReadAccountLock(ctx, next.GetLockActionId())
	if err != nil {
		return 0, stateReadError(ctx)
	}
	current, err := s.decodeAccountLock(row)
	if err != nil {
		return 0, err
	}
	if row.Revision != revision {
		return 0, ErrConflict
	}
	if len(current.GetAccounts()) != len(next.GetAccounts()) {
		return 0, ErrAccountLockRejected
	}
	for i, old := range current.GetAccounts() {
		n := next.GetAccounts()[i]
		if !proto.Equal(old.GetPrior(), n.GetPrior()) || !proto.Equal(old.GetExpected(), n.GetExpected()) || !accountPhaseTransition(old.GetPhase(), n.GetPhase()) {
			return 0, ErrAccountLockRejected
		}
		if old.GetReleaseActionId() != n.GetReleaseActionId() && n.GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING {
			return 0, ErrAccountLockRejected
		}
		if accountOwned(old.GetPhase()) && !accountOwned(n.GetPhase()) {
			changed, err := q.DeleteAccountLockOwner(ctx, journaldb.DeleteAccountLockOwnerParams{Username: old.GetPrior().GetUsername(), LockActionID: next.GetLockActionId()})
			if err != nil || changed != 1 {
				return 0, ErrRecoveryHold
			}
		}
	}
	changed, err := q.ReplaceAccountLock(ctx, journaldb.ReplaceAccountLockParams{Record: encoded, LockActionID: next.GetLockActionId(), Revision: revision})
	if err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	if changed != 1 {
		return 0, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	return revision + 1, nil
}

func accountPhaseTransition(old, next agentv1.AccountLockPhase) bool {
	if old == next {
		return true
	}
	switch old {
	case agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLE_PENDING:
		return next == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLED || next == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING || next == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED
	case agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLED:
		return next == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING || next == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED
	case agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING:
		return next == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED || next == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED
	default:
		return false
	}
}

func (s *Store) encodeAccountLock(ledger *agentv1.AccountLockLedger) ([]byte, error) {
	if ledger == nil || !canonicalServiceID(ledger.GetLockActionId()) || proto.Size(ledger) > maximumAccountLockBytes || protodata.ValidateClosed(ledger.ProtoReflect()) != nil || s.validator.Validate(ledger) != nil {
		return nil, ErrAccountLockRejected
	}
	for _, entry := range ledger.GetAccounts() {
		if (entry.GetPhase() == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING || entry.GetPhase() == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED) && !canonicalServiceID(entry.GetReleaseActionId()) {
			return nil, ErrAccountLockRejected
		}
		prior, expected := entry.GetPrior(), entry.GetExpected()
		if prior.GetPasswdEntry() != expected.GetPasswdEntry() || strings.ContainsAny(prior.GetPasswdEntry()+prior.GetShadowEntry()+expected.GetShadowEntry(), "\n\r\x00") {
			return nil, ErrAccountLockRejected
		}
		before, after := strings.Split(prior.GetShadowEntry(), ":"), strings.Split(expected.GetShadowEntry(), ":")
		if len(before) != 9 || len(after) != 9 || before[0] != prior.GetUsername() || after[0] != prior.GetUsername() {
			return nil, ErrAccountLockRejected
		}
		if proto.Equal(prior, expected) {
			if entry.GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED {
				return nil, ErrAccountLockRejected
			}
			continue
		}
		password := before[1]
		if !strings.HasPrefix(password, "!") {
			password = "!" + password
		}
		if after[1] != password || after[7] != "1" {
			return nil, ErrAccountLockRejected
		}
		before[1], before[7] = after[1], after[7]
		if strings.Join(before, ":") != expected.GetShadowEntry() {
			return nil, ErrAccountLockRejected
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(ledger)
	if err != nil {
		return nil, ErrAccountLockRejected
	}
	return encoded, nil
}

func (s *Store) decodeAccountLock(row journaldb.AccountLock) (*agentv1.AccountLockLedger, error) {
	ledger := new(agentv1.AccountLockLedger)
	if row.Revision < 1 || len(row.Record) > maximumAccountLockBytes || proto.Unmarshal(row.Record, ledger) != nil || ledger.GetLockActionId() != row.LockActionID {
		return nil, ErrRecoveryHold
	}
	if _, err := s.encodeAccountLock(ledger); err != nil {
		return nil, ErrRecoveryHold
	}
	return ledger, nil
}

func (s *Store) validateAccountLocks(ctx context.Context) error {
	count, err := s.queries.AccountLockCount(ctx)
	if err != nil || count > maximumAccountLocks {
		return ErrRecoveryHold
	}
	usage, err := s.queries.ReadAccountLockUsage(ctx)
	if err != nil || usage != count {
		return ErrRecoveryHold
	}
	var after string
	var seen, owned int64
	for {
		row, err := s.queries.NextAccountLock(ctx, after)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return stateReadError(ctx)
		}
		ledger, err := s.decodeAccountLock(row)
		if err != nil {
			return err
		}
		for _, entry := range ledger.GetAccounts() {
			if !accountOwned(entry.GetPhase()) {
				continue
			}
			prior := entry.GetPrior()
			owners, err := s.queries.ReadAccountLockOwner(ctx, journaldb.ReadAccountLockOwnerParams{Username: prior.GetUsername(), Uid: int64(prior.GetUid())})
			if err != nil || len(owners) != 1 || owners[0].Username != prior.GetUsername() || owners[0].Uid != int64(prior.GetUid()) || owners[0].LockActionID != ledger.GetLockActionId() {
				return ErrRecoveryHold
			}
			owned++
		}
		seen++
		after = row.LockActionID
	}
	owners, err := s.queries.AccountLockOwnerCount(ctx)
	if err != nil || seen != count || owned != owners {
		return ErrRecoveryHold
	}
	return nil
}
