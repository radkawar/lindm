// Package executionauthority persists quorum-authorized public execution trust.
// It never holds signing keys or treats administrator/device hints as signatures.
package executionauthority

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/executionauthority/authoritydb"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

const (
	maxRoots         = 4097
	maxUpdates       = 65536
	maxRetainedBytes = 64 << 20
	maxRequestBytes  = 278656
	maxRootBytes     = 65536
	maxEnvelopeBytes = 16384
	maxTransitions   = 8
)

var (
	ErrRejected       = errors.New("execution authority: rejected update")
	ErrIncompatible   = errors.New("execution authority: incompatible trust")
	ErrServerBehind   = errors.New("execution authority: server behind device")
	ErrReprovisioning = errors.New("execution authority: owner reprovisioning required")
	ErrCapacity       = errors.New("execution authority: retained history capacity exhausted")
	ErrCorrupt        = errors.New("execution authority: corrupt durable state")
	ErrConfigured     = errors.New("execution authority: bootstrap required for configured authority")
)

// Snapshot is one coherent public authority revision. AcceptedAt is zero until
// the first delegation; initialization alone confers no online authority.
type Snapshot struct {
	Root               *agentv1.ExecutionRoot
	Delegation         *agentv1.ExecutionDelegation
	DelegationEnvelope []byte
	AcceptedAt         time.Time
	Revision           uint64
}

// Config contains exact protected public bootstrap source bytes, never keys used
// for signing. Retaining these bytes permits genuine historical re-verification
// after an operator advances the configured pin to an authenticated newer root.
type Config struct {
	RootJSON          []byte
	BootstrapEnvelope []byte
	TLSPublicKey      crypto.PublicKey
}

// Store contains immutable public verification configuration, not cached state.
// Each replica reads the same database and serializes mutations on its singleton.
type Store struct {
	pool         *pgxpool.Pool
	verifier     *trust.ExecutionVerifier
	deploymentID uuid.UUID
	domain       [sha256.Size]byte
}

// New pins only the root on first initialization. Later configuration must name
// an already authenticated root in the same deployment and public trust domain.
func New(ctx context.Context, pool *pgxpool.Pool, cfg Config) (*Store, error) {
	if pool == nil || cfg.TLSPublicKey == nil || len(cfg.RootJSON) == 0 || len(cfg.RootJSON) > maxRootBytes || len(cfg.BootstrapEnvelope) == 0 || len(cfg.BootstrapEnvelope) > 512<<10 {
		return nil, ErrIncompatible
	}
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := authoritydb.New(tx)
	row, err := q.LockAuthority(ctx)
	if err != nil {
		return nil, stateError(err)
	}
	now, err := readClock(ctx, q)
	if err != nil {
		return nil, err
	}
	bootstrap, err := authority.VerifyBootstrap(ctx, cfg.RootJSON, cfg.BootstrapEnvelope, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIncompatible, err)
	}
	verifier, err := authority.NewExecutionVerifier(bootstrap, cfg.TLSPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIncompatible, err)
	}
	deploymentID, err := uuid.Parse(bootstrap.Root.GetDeploymentId())
	if err != nil || deploymentID == uuid.Nil {
		return nil, ErrIncompatible
	}
	s := &Store{pool: pool, verifier: verifier, deploymentID: deploymentID, domain: verifier.TrustDomainDigest()}
	size, err := q.GetHistorySize(ctx)
	if err != nil {
		return nil, err
	}
	if size.RootCount != int64(row.RootCount) || size.UpdateCount != int64(row.UpdateCount) || size.RetainedBytes != row.RetainedBytes || size.UpdateAudits != size.UpdateCount {
		return nil, ErrCorrupt
	}
	if row.DeploymentID == nil {
		if row.Revision != 0 || size.RootCount != 0 || size.UpdateCount != 0 || size.InitializationAudits != 0 {
			return nil, ErrCorrupt
		}
		if err := s.initialize(ctx, q, cfg, bootstrap.Root, now); err != nil {
			return nil, err
		}
	} else {
		if size.InitializationAudits != 1 || !row.InitializedAt.Valid || row.InitializedAt.InfinityModifier != pgtype.Finite {
			return nil, ErrCorrupt
		}
		original, err := authority.VerifyBootstrap(ctx, row.InitialRootJson, row.InitialBootstrapEnvelope, row.InitializedAt.Time)
		if err != nil {
			return nil, ErrCorrupt
		}
		historical, err := authority.NewExecutionVerifier(original, cfg.TLSPublicKey)
		if err != nil {
			return nil, ErrIncompatible
		}
		if historical.TrustDomainDigest() != s.domain || original.Root.GetDeploymentId() != bootstrap.Root.GetDeploymentId() {
			return nil, ErrIncompatible
		}
		s.verifier = historical
		snapshot, err := s.snapshot(ctx, q, row)
		if err != nil {
			return nil, err
		}
		if bootstrap.Root.GetVersion() > snapshot.Root.GetVersion() {
			return nil, ErrIncompatible
		}
		pin, err := q.GetRoot(ctx, counter(bootstrap.Root.GetVersion()))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrIncompatible
		}
		if err != nil {
			return nil, err
		}
		digest, err := trust.ExecutionRootDigest(bootstrap.Root)
		if err != nil || !bytes.Equal(pin.RootDigest, digest[:]) {
			return nil, ErrIncompatible
		}
		if err := s.checkHistory(ctx, q, row, snapshot, original.Root); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// CheckUnconfigured prevents removing the public bootstrap configuration from
// silently hiding authority that was previously provisioned in this deployment.
func CheckUnconfigured(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return ErrCorrupt
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := authoritydb.New(tx)
	row, err := q.LockAuthority(ctx)
	if err != nil {
		return stateError(err)
	}
	if row.DeploymentID != nil {
		return ErrConfigured
	}
	size, err := q.GetHistorySize(ctx)
	if err != nil {
		return err
	}
	if row.Revision != 0 || size.RootCount != 0 || size.UpdateCount != 0 || size.RetainedBytes != 0 || size.InitializationAudits != 0 || size.UpdateAudits != 0 {
		return ErrCorrupt
	}
	return tx.Commit(ctx)
}

func (s *Store) initialize(ctx context.Context, q *authoritydb.Queries, cfg Config, root *agentv1.ExecutionRoot, now time.Time) error {
	encoded, err := marshal(root)
	if err != nil || len(encoded) == 0 || len(encoded) > maxRootBytes {
		return ErrIncompatible
	}
	digest, err := trust.ExecutionRootDigest(root)
	if err != nil {
		return ErrIncompatible
	}
	stamp := timestamp(now)
	if err := q.InsertRoot(ctx, authoritydb.InsertRootParams{
		Position: 1, RootVersion: counter(root.GetVersion()), RootDigest: digest[:],
		RootDocument: encoded, TransitionDocument: []byte{}, AcceptedAt: stamp,
	}); err != nil {
		return err
	}
	if err := q.SetInitialBootstrap(ctx, authoritydb.SetInitialBootstrapParams{
		InitialRootJson: cfg.RootJSON, InitialBootstrapEnvelope: cfg.BootstrapEnvelope, InitializedAt: stamp,
		DeploymentID: &s.deploymentID, TrustDomainDigest: s.domain[:], RootDocument: encoded,
		RetainedBytes: int64(len(encoded) + len(cfg.RootJSON) + len(cfg.BootstrapEnvelope)),
	}); err != nil {
		return err
	}
	return q.InsertAudit(ctx, authoritydb.InsertAuditParams{
		ID: uuid.New(), OccurredAt: stamp, Action: "execution_authority.initialize",
		ResourceID: s.deploymentID.String(), Context: "verified public bootstrap root pin",
	})
}

// Get does not apply today's validity window to historical accepted authority.
// It re-verifies the stored delegation at its original database acceptance time.
func (s *Store) Get(ctx context.Context) (*Snapshot, error) {
	q := authoritydb.New(s.pool)
	row, err := q.GetAuthority(ctx)
	if err != nil {
		return nil, stateError(err)
	}
	return s.snapshot(ctx, q, row)
}

// CurrentInTransaction holds the authority share lock until the caller commits.
// Call after the actor fence and before locking the device. The verifier accepts
// only this authenticated snapshot, never a caller-supplied root or delegation.
func (s *Store) CurrentInTransaction(ctx context.Context, tx pgx.Tx) (*Snapshot, *trust.ExecutionVerifier, error) {
	if tx == nil {
		return nil, nil, ErrRejected
	}
	q := authoritydb.New(tx)
	row, err := q.ShareAuthority(ctx)
	if err != nil {
		return nil, nil, stateError(err)
	}
	snapshot, err := s.snapshot(ctx, q, row)
	return snapshot, s.verifier, err
}

func (s *Store) snapshot(ctx context.Context, q *authoritydb.Queries, row authoritydb.ExecutionAuthority) (*Snapshot, error) {
	if row.DeploymentID == nil || row.Revision < 1 || row.RootCount < 1 || row.Revision != int64(row.UpdateCount)+1 || !row.AcceptedAt.Valid || row.AcceptedAt.InfinityModifier != pgtype.Finite {
		return nil, ErrCorrupt
	}
	if *row.DeploymentID != s.deploymentID || !bytes.Equal(row.TrustDomainDigest, s.domain[:]) {
		return nil, ErrIncompatible
	}
	root := new(agentv1.ExecutionRoot)
	if err := unmarshal(row.RootDocument, root); err != nil || root.GetDeploymentId() != s.deploymentID.String() || root.GetVersion() == 0 {
		return nil, ErrCorrupt
	}
	if _, err := trust.ExecutionRootDigest(root); err != nil {
		return nil, ErrCorrupt
	}
	known, err := q.GetRoot(ctx, counter(root.GetVersion()))
	if err != nil {
		return nil, stateError(err)
	}
	acceptedRoot, err := decodeRoot(known)
	if err != nil || known.Position != row.RootCount || known.AcceptedAt.Time.After(row.AcceptedAt.Time) || !proto.Equal(acceptedRoot, root) {
		return nil, ErrCorrupt
	}
	// Root-only state is already pinned authority: the first delegation must
	// not establish a new quorum from a damaged mutable singleton.
	snapshot := &Snapshot{Root: root, Revision: uint64(row.Revision)}
	if len(row.DelegationEnvelope) == 0 {
		if row.UpdateCount != 0 || known.Position != 1 || row.RootCount != 1 || !row.InitializedAt.Valid || row.InitializedAt.InfinityModifier != pgtype.Finite || !known.AcceptedAt.Time.Equal(row.InitializedAt.Time) || !row.AcceptedAt.Time.Equal(row.InitializedAt.Time) {
			return nil, ErrCorrupt
		}
		return snapshot, nil
	}
	if row.UpdateCount == 0 {
		return nil, ErrCorrupt
	}
	// Bind the captured singleton to its immutable admission, not to whichever
	// revision happens to be current when this later query executes. This both
	// fences partial live-state rollback and preserves lock-free coherent reads
	// while another replica commits a newer revision.
	admission, err := q.GetLatestUpdate(ctx, row.Revision)
	if err != nil {
		return nil, stateError(err)
	}
	request, receipt, err := admissionDocuments(admission)
	if err != nil || admission.Revision != row.Revision || !admission.AcceptedAt.Time.Equal(row.AcceptedAt.Time) || !bytes.Equal(request.GetDelegationEnvelope(), row.DelegationEnvelope) || receipt.GetRootVersion() != root.GetVersion() {
		return nil, ErrCorrupt
	}
	delegation, err := s.verifier.VerifyDelegation(ctx, root, row.DelegationEnvelope, receipt.GetDelegationVersion()-1, receipt.GetMinimumRecoveryEpoch(), row.AcceptedAt.Time)
	if err != nil || !proto.Equal(receipt, executionReceipt(root, delegation)) {
		return nil, rejectContext(ctx, ErrCorrupt)
	}
	snapshot.Delegation = delegation
	snapshot.DelegationEnvelope = row.DelegationEnvelope
	snapshot.AcceptedAt = row.AcceptedAt.Time
	return snapshot, nil
}

func readClock(ctx context.Context, q *authoritydb.Queries) (time.Time, error) {
	stamp, err := q.ReadClock(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if !stamp.Valid || stamp.InfinityModifier != pgtype.Finite {
		return time.Time{}, ErrCorrupt
	}
	return stamp.Time, nil
}

func timestamp(at time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: at, Valid: true} }
func counter(value uint64) string               { return strconv.FormatUint(value, 10) }
func marshal(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}
func unmarshal(encoded []byte, message proto.Message) error {
	if len(encoded) == 0 {
		return ErrCorrupt
	}
	if err := proto.Unmarshal(encoded, message); err != nil {
		return ErrCorrupt
	}
	return protodata.ValidateClosed(message.ProtoReflect())
}
func stateError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCorrupt
	}
	return err
}
