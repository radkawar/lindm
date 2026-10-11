package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

// The signed-action core is the one server authority path for device-executed
// work signed under the execution delegation: resource executions and device
// actions. It owns the order of the fences every kind shares. For a start: the
// device-signed challenge, fresh actor authority, device/session/certificate
// fences, exact replay of an issued grant, release compatibility, device clock
// skew, current intent authority on server time and a start window of at most
// 30 s. For a result: a registered, unrevoked certificate, exact replay of
// admitted evidence, a one-use nonce, attestation binding, monotonic revisions
// and start evidence only under an issued grant. Kinds contribute row access,
// their admission rules and side effects, never a weaker fence.

// reason is a refusal a kind names for a shared fence.
type reason struct {
	code connect.Code
	text string
}

func (r reason) err() error { return rpcreason.Error(r.code, r.text) }

// signedRow is the durable start and result state of a signed-action row.
type signedRow struct {
	id                     uuid.UUID
	deviceID, generationID uuid.UUID
	intentEnvelope         []byte
	challengeProof         []byte
	startGrant             []byte
	resultNonce            []byte
	nonceExpiresAt         pgtype.Timestamptz
	revision               pgtype.Numeric
	attestation            []byte
	attestationCertificate []byte
	closed                 bool
}

func (r signedRow) boundTo(p devicePrincipal) bool {
	return r.deviceID == p.DeviceID && r.generationID == p.GenerationID
}

// signedReasons names a kind's refusals at shared fences and its audit action.
type signedReasons struct {
	invalidStart, invalidResult, resultAudit                         string
	binding, challenge, challengeBinding, startConflict, startWindow reason
	nonce, attestation, resultConflict, ungranted                    reason
}

type signedChallenge interface {
	proto.Message
	GetIssuedAt() *timestamppb.Timestamp
	GetExpiresAt() *timestamppb.Timestamp
}

type signedStartRequest interface {
	proto.Message
	GetSessionEpoch() uint64
	GetActionId() string
	GetChallengeProof() []byte
}

// startState carries one start authorization through the shared fences.
type startState[C signedChallenge] struct {
	principal devicePrincipal
	epoch     uint64
	id        uuid.UUID
	proof     []byte
	challenge C
	tx        pgx.Tx
	q         *devicedb.Queries
	snapshot  *executionauthority.Snapshot
	verifier  *trust.ExecutionVerifier
	now       time.Time
}

// startKind is one kind's half of start authorization. Implementations hold
// per-request state: the captured row, decoded intent and fresh authority.
type startKind[C signedChallenge] interface {
	reasons() signedReasons
	// capture reads the action outside any transaction.
	capture(ctx context.Context, s *Service, id uuid.UUID) (signedRow, error)
	// decode reads the captured intent and refuses actions that belong to
	// another endpoint.
	decode() error
	// binds reports whether the device challenge describes the captured intent.
	binds(challenge C, intentSHA256 []byte) bool
	// authorize takes fresh actor authority outside the transaction; it runs
	// only while no grant exists.
	authorize(ctx context.Context, s *Service) error
	// lock takes the kind's authority locks before the device row, in its lock
	// order, and loads the current execution snapshot when admissible.
	lock(ctx context.Context, s *Service, st *startState[C]) error
	// lockAction locks the action row and the rows ordered with it.
	lockAction(ctx context.Context, s *Service, st *startState[C]) (signedRow, error)
	// admit applies the kind's refusals; commit records a refusal durably.
	admit(ctx context.Context, s *Service, st *startState[C]) (commit bool, err error)
	// verifyIntent rechecks the intent against current authority on server time.
	verifyIntent(ctx context.Context, st *startState[C]) error
	// limits are kind upper bounds on the grant window (fresh authority, intent).
	limits(st *startState[C], issued time.Time) []time.Time
	grant(st *startState[C], expires time.Time) proto.Message
	signFailed(err error) error
	verifyGrant(ctx context.Context, st *startState[C], envelope []byte) error
	// persist stores the grant with its side effects, audit and final relocks.
	persist(ctx context.Context, s *Service, st *startState[C], envelope []byte) error
}

// authorizeSignedStart issues, or exactly replays, the start grant for one
// device-signed challenge.
func authorizeSignedStart[C signedChallenge](ctx context.Context, s *Service, msg signedStartRequest, challenge C, k startKind[C]) ([]byte, error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	reasons := k.reasons()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if !msg.ProtoReflect().IsValid() || s.rules.Validate(msg) != nil {
		return nil, invalid(reasons.invalidStart)
	}
	if s.identity == nil || s.signing == nil || s.execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	id, err := uuid.Parse(msg.GetActionId())
	if err != nil {
		return nil, invalid(reasons.invalidStart)
	}
	st := &startState[C]{principal: principal, epoch: msg.GetSessionEpoch(), id: id, proof: msg.GetChallengeProof(), challenge: challenge}
	captured, err := k.capture(ctx, s, id)
	if err != nil {
		return nil, mapErr(err)
	}
	if !captured.boundTo(principal) {
		return nil, reasons.binding.err()
	}
	if err := k.decode(); err != nil {
		return nil, err
	}
	if err := s.authority.Verify(ctx, st.proof, challenge, 1, principal.PublicKey); err != nil {
		return nil, reasons.challenge.err()
	}
	digest := sha256.Sum256(captured.intentEnvelope)
	if !k.binds(challenge, digest[:]) {
		return nil, reasons.challengeBinding.err()
	}
	if len(captured.startGrant) == 0 {
		if err := k.authorize(ctx, s); err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st.tx, st.q = tx, devicedb.New(tx)
	if err := k.lock(ctx, s, st); err != nil {
		return nil, err
	}
	if err := s.lockSignedDevice(ctx, st.q, principal, st.epoch, &st.now); err != nil {
		return nil, err
	}
	action, err := k.lockAction(ctx, s, st)
	if err != nil {
		return nil, err
	}
	// A grant is issued once; only the exact challenge proof reads it back,
	// even after expiry or revocation.
	if len(action.startGrant) != 0 {
		if !bytes.Equal(action.challengeProof, st.proof) {
			return nil, reasons.startConflict.err()
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return action.startGrant, nil
	}
	if err := s.requireReleaseCompatibility(ctx, st.q, principal.GenerationID, st.epoch); err != nil {
		return nil, mapErr(err)
	}
	if commit, err := k.admit(ctx, s, st); err != nil {
		if commit {
			if err := tx.Commit(ctx); err != nil {
				return nil, mapErr(err)
			}
		}
		return nil, err
	}
	if st.snapshot == nil || st.snapshot.Delegation == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	issued, expires := challenge.GetIssuedAt().AsTime(), challenge.GetExpiresAt().AsTime()
	if issued.After(st.now.Add(trust.MaxDeviceClockSkew)) || !st.now.Add(-trust.MaxDeviceClockSkew).Before(expires) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_clock_skew")
	}
	// Current authority and lease must hold on server time, independently of
	// the bounded device-clock interval of the challenge and grant.
	if err := k.verifyIntent(ctx, st); err != nil {
		return nil, err
	}
	for _, limit := range append([]time.Time{issued.Add(30 * time.Second), st.snapshot.Delegation.GetExpiresAt().AsTime()}, k.limits(st, issued)...) {
		if limit.Before(expires) {
			expires = limit
		}
	}
	if !expires.After(issued) {
		return nil, reasons.startWindow.err()
	}
	envelope, err := s.authority.Sign(ctx, k.grant(st, expires), s.signing.StartKey)
	if err != nil {
		return nil, k.signFailed(err)
	}
	if err := k.verifyGrant(ctx, st, envelope); err != nil {
		return nil, err
	}
	if err := k.persist(ctx, s, st, envelope); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return envelope, nil
}

// lockSignedDevice holds the device row under the current session epoch and a
// resumable certificate, and reads the dispatch clock.
func (s *Service) lockSignedDevice(ctx context.Context, q *devicedb.Queries, principal devicePrincipal, epoch uint64, now *time.Time) error {
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != epoch {
		return mapErr(errSessionFenced)
	}
	if *now, err = dispatchClock(ctx, q); err != nil {
		return mapErr(err)
	}
	if !enrollmentIssuanceResumable(device.certificate, *now) {
		return mapErr(errCertificateRejected)
	}
	return nil
}

type signedResultRequest interface {
	proto.Message
	GetSessionEpoch() uint64
	GetActionId() string
	GetAttestationEnvelope() []byte
	GetCertificatePem() []byte
}

// signedStatus is the start evidence every attested status carries.
type signedStatus interface {
	proto.Message
	GetStartedAt() *timestamppb.Timestamp
}

type signedAttestation[S signedStatus] interface {
	proto.Message
	GetSessionEpoch() uint64
	GetActionRevision() uint64
	GetIssuedAt() *timestamppb.Timestamp
	GetStatus() S
}

// resultState carries one result report through the shared fences.
type resultState[S signedStatus, A signedAttestation[S]] struct {
	principal   devicePrincipal
	epoch       uint64
	id          uuid.UUID
	envelope    []byte
	certificate []byte
	tx          pgx.Tx
	q           *devicedb.Queries
	now         time.Time
	row         signedRow
	attestation A
	closed      bool
}

// resultKind is one kind's half of result admission.
type resultKind[S signedStatus, A signedAttestation[S]] interface {
	reasons() signedReasons
	// lockAction locks the action row and the rows ordered with it.
	lockAction(ctx context.Context, s *Service, st *resultState[S, A]) (signedRow, error)
	newAttestation() A
	verifyAttestation(ctx context.Context, s *Service, st *resultState[S, A], binding *trust.ResourceAttestationBinding) (A, error)
	// admit applies the kind's result binding and refusals.
	admit(ctx context.Context, s *Service, st *resultState[S, A]) error
	// persist stores the result and its side effects; it sets st.closed.
	persist(ctx context.Context, s *Service, st *resultState[S, A], status []byte) error
}

// Optional result hooks. resultLocker takes a kind's locks before the device
// row; resultPreflight handles a non-attestation report (handled ends the
// request); resultRepeat admits an attestation repeating the stored revision.
type (
	resultLocker[S signedStatus, A signedAttestation[S]] interface {
		lock(ctx context.Context, s *Service, st *resultState[S, A]) error
	}
	resultPreflight[S signedStatus, A signedAttestation[S]] interface {
		preflight(ctx context.Context, s *Service, st *resultState[S, A]) (handled bool, err error)
	}
	resultRepeat[S signedStatus, A signedAttestation[S]] interface {
		sameRevision(st *resultState[S, A]) (bool, error)
	}
)

// reportSignedResult admits device-attested result evidence. It returns
// whether the action is closed.
func reportSignedResult[S signedStatus, A signedAttestation[S]](ctx context.Context, s *Service, msg signedResultRequest, k resultKind[S, A]) (*resultState[S, A], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	reasons := k.reasons()
	if !msg.ProtoReflect().IsValid() || s.rules.Validate(msg) != nil {
		return nil, invalid(reasons.invalidResult)
	}
	id, err := uuid.Parse(msg.GetActionId())
	if err != nil {
		return nil, invalid(reasons.invalidResult)
	}
	st := &resultState[S, A]{principal: principal, epoch: msg.GetSessionEpoch(), id: id, envelope: msg.GetAttestationEnvelope(), certificate: msg.GetCertificatePem()}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st.tx, st.q = tx, devicedb.New(tx)
	if l, ok := k.(resultLocker[S, A]); ok {
		if err := l.lock(ctx, s, st); err != nil {
			return nil, err
		}
	}
	if err := s.lockSignedDevice(ctx, st.q, principal, st.epoch, &st.now); err != nil {
		return nil, err
	}
	if st.row, err = k.lockAction(ctx, s, st); err != nil {
		return nil, err
	}
	if !st.row.boundTo(principal) {
		return nil, reasons.binding.err()
	}
	if p, ok := k.(resultPreflight[S, A]); ok {
		if handled, err := p.preflight(ctx, s, st); handled || err != nil {
			return st, err
		}
	}
	leaf, err := s.attestationCertificate(ctx, st.q, principal, st.certificate, st.now)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(st.row.attestation, st.envelope) && bytes.Equal(st.row.attestationCertificate, st.certificate) {
		// This exact evidence was already cryptographically admitted. A consumed
		// nonce and later wall-clock expiry cannot make a lost response non-idempotent.
		public, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, mapErr(errCertificateRejected)
		}
		accepted := k.newAttestation()
		if err := s.authority.Verify(ctx, st.row.attestation, accepted, 1, public); err != nil || accepted.GetSessionEpoch() != st.epoch {
			return nil, reasons.attestation.err()
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		st.closed = st.row.closed
		return st, nil
	}
	if len(st.row.resultNonce) != 32 || !st.row.nonceExpiresAt.Valid || !st.now.Before(st.row.nonceExpiresAt.Time) {
		return nil, reasons.nonce.err()
	}
	binding := &trust.ResourceAttestationBinding{DeploymentID: s.deploymentID, DeviceID: principal.DeviceID, EnrollmentGeneration: principal.GenerationID, SessionEpoch: st.epoch, ActionID: id, IntentSHA256: sha256.Sum256(st.row.intentEnvelope)}
	copy(binding.Nonce[:], st.row.resultNonce)
	st.attestation, err = k.verifyAttestation(ctx, s, st, binding)
	if errors.Is(err, trust.ErrDeviceClockSkew) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_clock_skew")
	}
	if err != nil {
		return nil, reasons.attestation.err()
	}
	previous, err := signedRevision(st.row.revision)
	if err != nil {
		return nil, mapErr(err)
	}
	if revision := st.attestation.GetActionRevision(); revision < previous {
		return nil, reasons.resultConflict.err()
	} else if revision == previous {
		repeat, ok := k.(resultRepeat[S, A])
		if !ok {
			return nil, reasons.resultConflict.err()
		}
		if same, err := repeat.sameRevision(st); err != nil {
			return nil, err
		} else if !same {
			return nil, reasons.resultConflict.err()
		}
	}
	// Start evidence exists only under an issued grant.
	if st.attestation.GetStatus().GetStartedAt() != nil && len(st.row.startGrant) == 0 {
		return nil, reasons.ungranted.err()
	}
	if err := k.admit(ctx, s, st); err != nil {
		return nil, err
	}
	status, err := proto.Marshal(st.attestation.GetStatus())
	if err != nil {
		return nil, mapErr(err)
	}
	if err := k.persist(ctx, s, st, status); err != nil {
		return nil, err
	}
	if err := dispatchSystemAudit(ctx, st.q, nil, reasons.resultAudit, id, "proof", "verified_device_attestation"); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return st, nil
}

// attestationCertificate admits only a registered, unrevoked certificate of
// this generation; the CA signature alone is insufficient, including during
// renewal overlap.
func (s *Service) attestationCertificate(ctx context.Context, q *devicedb.Queries, principal devicePrincipal, certificatePEM []byte, now time.Time) (*x509.Certificate, error) {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, mapErr(errCertificateRejected)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, mapErr(errCertificateRejected)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	certificate, err := q.GetCertificateByFingerprint(ctx, fingerprint[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(errCertificateRejected)
	}
	if err != nil {
		return nil, mapErr(err)
	}
	if certificate.DeviceID != principal.DeviceID || certificate.GenerationID != principal.GenerationID || now.Before(certificate.NotBefore.Time) || !now.Before(certificate.NotAfter.Time) || (certificate.Status != "active" && (certificate.Status != "overlapping" || !certificate.OverlapUntil.Valid || !now.Before(certificate.OverlapUntil.Time))) {
		return nil, mapErr(errCertificateRejected)
	}
	return leaf, nil
}

// message is a request's message, nil for a nil request.
func message[T any](req *connect.Request[T]) *T {
	if req == nil {
		return nil
	}
	return req.Msg
}

func actionRevision(revision uint64) pgtype.Numeric {
	return pgtype.Numeric{Int: new(big.Int).SetUint64(revision), Valid: true}
}
