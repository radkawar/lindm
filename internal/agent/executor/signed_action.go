//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/pki"
	"lindm/internal/trust"
)

// signedIntent is the target surface every root-delegated plan-role intent
// shares: resource executions and device actions.
type signedIntent interface {
	proto.Message
	GetDeploymentId() string
	GetDeviceId() string
	GetEnrollmentGeneration() string
	GetActionId() string
	GetActorId() string
	GetExpiresAt() *timestamppb.Timestamp
}

// signedChallenge is the executor-signed start challenge surface.
type signedChallenge interface {
	proto.Message
	GetBootId() string
	GetExecutorIncarnation() string
	GetIssuedAt() *timestamppb.Timestamp
	GetExpiresAt() *timestamppb.Timestamp
}

// signedGrant is the start-role grant surface.
type signedGrant interface {
	proto.Message
	GetNotBefore() *timestamppb.Timestamp
	GetExpiresAt() *timestamppb.Timestamp
}

// signedRecord is the protected journal record of one signed action.
type signedRecord[I signedIntent, C signedChallenge] interface {
	proto.Message
	GetIntent() I
	GetIntentEnvelope() []byte
	GetChallenge() C
	GetChallengeProof() []byte
	GetChallengeBoottimeNs() uint64
	GetChallengeCertificatePem() []byte
}

// signedAction is the one lifecycle core for root-authorized actions:
// bounded routing lookup, current-authority and target fences, the
// executor-signed start challenge with its CLOCK_BOOTTIME deadline, start-grant
// verification, expiry of unconsumed work and protected journal access. A kind
// supplies only its wire types, trust verifiers, journal accessors and the
// identifiers it additionally fences. Callers hold Service.mu.
type signedAction[I signedIntent, C signedChallenge, G signedGrant, R signedRecord[I, C]] struct {
	payloadType string
	maxIntent   int
	newIntent   func() I
	// targetIDs are kind-specific identifiers that must be canonical UUIDs.
	targetIDs    func(I) []string
	verifyIntent func(*trust.ExecutionVerifier, context.Context, *agentv1.ExecutionRoot, *agentv1.ExecutionDelegation, []byte, time.Time) (I, error)
	verifyStart  func(*trust.ExecutionVerifier, context.Context, *agentv1.ExecutionRoot, *agentv1.ExecutionDelegation, []byte, I, C, time.Time) (G, error)
	// verifyRecord authenticates a whole protected record (historical evidence).
	verifyRecord func(*Service, context.Context, *bound, R) error
	load         func(*journal.Store, context.Context, string) (R, int64, error)
	store        func(*journal.Store, context.Context, int64, int64, int64, R) (int64, error)
}

// lookup extracts a bounded routing key only. Neither this payload nor its
// envelope is authority until current or historical verification.
func (k *signedAction[I, C, G, R]) lookup(s *Service, encoded []byte) (string, error) {
	if len(encoded) == 0 || len(encoded) > k.maxIntent {
		return "", errInvalid
	}
	var envelope dsse.Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || envelope.PayloadType != k.payloadType || len(envelope.Signatures) == 0 || len(envelope.Signatures) > 16 {
		return "", errInvalid
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > k.maxIntent {
		return "", errInvalid
	}
	intent := k.newIntent()
	if proto.Unmarshal(payload, intent) != nil || s.admit(intent) != nil {
		return "", errInvalid
	}
	if _, err := canonicalUUID(intent.GetActionId()); err != nil {
		return "", errInvalid
	}
	return intent.GetActionId(), nil
}

// current verifies an intent against the current identity, session, execution
// delegation and target. It is the admission gate for every new transition.
func (k *signedAction[I, C, G, R]) current(ctx context.Context, s *Service, loaded *bound, envelope []byte) (I, error) {
	var zero I
	if err := s.actionIdentitySession(loaded); err != nil {
		return zero, err
	}
	if loaded.execution.delegation == nil || s.now().Before(loaded.execution.state.GetAcceptedAt().AsTime()) {
		return zero, errResourceRejected
	}
	intent, err := k.verifyIntent(loaded.execution.verifier, ctx, loaded.execution.root, loaded.execution.delegation, envelope, s.now())
	if err != nil {
		return zero, signedAuthorityError(ctx)
	}
	if !signedTarget(loaded, intent, k.targetIDs(intent)...) {
		return zero, errResourceRejected
	}
	return intent, nil
}

// signedTarget fences an intent to this deployment, device and enrollment
// generation; every identifier, including kind-specific extra ones, must be a
// canonical UUID.
func signedTarget(loaded *bound, intent signedIntent, extra ...string) bool {
	if intent.GetDeploymentId() != loaded.bootstrap.Root.GetDeploymentId() || intent.GetDeviceId() != loaded.state.GetDeviceId() || intent.GetEnrollmentGeneration() != loaded.state.GetEnrollmentGeneration() {
		return false
	}
	for _, ids := range [][]string{{intent.GetDeploymentId(), intent.GetDeviceId(), intent.GetEnrollmentGeneration(), intent.GetActionId(), intent.GetActorId()}, extra} {
		for _, id := range ids {
			if _, err := canonicalUUID(id); err != nil {
				return false
			}
		}
	}
	return true
}

// authorizeStart verifies a start grant against current authority, the
// unexpired executor challenge and the agent self-update interlock. It neither
// consumes nor records the grant.
func (k *signedAction[I, C, G, R]) authorizeStart(ctx context.Context, s *Service, loaded *bound, record R, grant []byte) (G, error) {
	var zero G
	if s.agentUpdateBusy() {
		return zero, errResourceRejected
	}
	if _, err := k.current(ctx, s, loaded, record.GetIntentEnvelope()); err != nil {
		return zero, err
	}
	if err := s.challengeDeadline(record.GetChallenge(), record.GetChallengeBoottimeNs()); err != nil {
		return zero, err
	}
	verified, err := k.verifyStart(loaded.execution.verifier, ctx, loaded.execution.root, loaded.execution.delegation, grant, record.GetIntent(), record.GetChallenge(), s.now())
	if err != nil {
		return zero, signedAuthorityError(ctx)
	}
	return verified, nil
}

// consumedInWindow re-checks after the durable consume commit that neither the
// commit nor anything before it outlasted the request, the challenge deadline,
// the grant or the identity. A rejection here leaves consumed evidence but
// permits no native effect.
func (s *Service) consumedInWindow(ctx context.Context, loaded *bound, challenge signedChallenge, deadline uint64, grant signedGrant) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.challengeDeadline(challenge, deadline); err != nil {
		return err
	}
	now := s.now()
	if now.Before(grant.GetNotBefore().AsTime()) || !now.Before(grant.GetExpiresAt().AsTime()) {
		return errResourceExpired
	}
	if !certUsable(loaded.cert, now) {
		return errIdentityExpired
	}
	return nil
}

// expire durably ends unconsumed work whose challenge deadline passed; mark
// sets the kind's terminal state on the clone. record is replaced in place.
func (k *signedAction[I, C, G, R]) expire(ctx context.Context, s *Service, loaded *bound, record R, revision int64, mark func(R)) error {
	if err := s.challengeDeadline(record.GetChallenge(), record.GetChallengeBoottimeNs()); err == nil {
		return nil
	} else if !errors.Is(err, errResourceExpired) {
		return err
	}
	next := proto.CloneOf(record)
	mark(next)
	if err := k.update(ctx, s, loaded, revision, next); err != nil {
		return err
	}
	proto.Reset(record)
	proto.Merge(record, next)
	return nil
}

// loadAction returns only records that still authenticate as historical
// evidence; any damage holds the executor.
func (k *signedAction[I, C, G, R]) loadAction(ctx context.Context, s *Service, loaded *bound, actionID string) (R, int64, error) {
	var zero R
	record, revision, err := k.load(s.store, ctx, actionID)
	if err != nil {
		return zero, 0, s.resourceStoreError(err)
	}
	if record.GetIntent().GetActionId() != actionID {
		s.noteTrustDamage()
		return zero, 0, errRecoveryHold
	}
	if err := k.verifyRecord(s, ctx, loaded, record); err != nil {
		if errors.Is(err, errRecoveryHold) {
			s.noteTrustDamage()
		}
		return zero, 0, err
	}
	return record, revision, nil
}

// update journals next only if it authenticates as evidence first.
func (k *signedAction[I, C, G, R]) update(ctx context.Context, s *Service, loaded *bound, revision int64, next R) error {
	if err := k.verifyRecord(s, ctx, loaded, next); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errInternal
	}
	_, err := k.store(s.store, ctx, revision, loaded.revision, loaded.execution.revision, next)
	return s.resourceStoreError(err)
}

// verifyChallengeCustody authenticates a retained challenge as evidence: its
// identifiers, its boottime deadline and window inside the intent, and the
// proof by the enrollment certificate that was current at issuance. It returns
// that certificate's key. verified receives the decoded proof. This is a
// function, not a signedAction method: kind descriptors refer to the record
// verifiers that call it.
func verifyChallengeCustody[I signedIntent, C signedChallenge, R signedRecord[I, C]](ctx context.Context, s *Service, loaded *bound, record R, verified C) (ed25519.PublicKey, error) {
	challenge, intent := record.GetChallenge(), record.GetIntent()
	if challenge.GetExpiresAt().AsTime().After(intent.GetExpiresAt().AsTime()) {
		return nil, errRecoveryHold
	}
	if _, err := canonicalUUID(challenge.GetBootId()); err != nil {
		return nil, errRecoveryHold
	}
	if _, err := canonicalUUID(challenge.GetExecutorIncarnation()); err != nil {
		return nil, errRecoveryHold
	}
	if record.GetChallengeBoottimeNs() < uint64(challenge.GetExpiresAt().AsTime().Sub(challenge.GetIssuedAt().AsTime())) {
		return nil, errRecoveryHold
	}
	block, rest := pem.Decode(record.GetChallengeCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errRecoveryHold
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errRecoveryHold
	}
	public, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errRecoveryHold
	}
	deployment, device, generation, err := enrollmentIDs(intent.GetDeploymentId(), intent.GetDeviceId(), intent.GetEnrollmentGeneration())
	if err != nil {
		return nil, errRecoveryHold
	}
	if _, err := pki.VerifyDeviceCertificatePEM(record.GetChallengeCertificatePem(), public, loaded.bootstrap.DeviceCA, deployment, device, generation, challenge.GetIssuedAt().AsTime()); err != nil {
		return nil, errRecoveryHold
	}
	if err := s.authority.Verify(ctx, record.GetChallengeProof(), verified, 1, public); err != nil || !proto.Equal(verified, challenge) {
		return nil, historicalResourceError(ctx)
	}
	return public, nil
}

// actionIdentitySession requires a usable identity with a committed session
// for the current boot and no renewal or session change in flight.
func (s *Service) actionIdentitySession(loaded *bound) error {
	if !certUsable(loaded.cert, s.now()) {
		return errIdentityExpired
	}
	if loaded.renewal != nil {
		return errRenewalPending
	}
	if loaded.state.GetPendingSession() != nil {
		return errSessionPending
	}
	boot, err := s.bootID()
	if err != nil {
		return err
	}
	if _, err := canonicalUUID(boot); err != nil {
		return errInternal
	}
	if loaded.state.GetSessionEpoch() == 0 || loaded.state.GetSessionBootId() != boot {
		return errSessionRequired
	}
	return nil
}

// challengeWindow is an executor-issued start window: at most 30 s from
// issuance, never beyond the signed intent or a kind-specific limit, and
// pinned to this boot's CLOCK_BOOTTIME so suspend or wall-clock changes cannot
// extend it.
type challengeWindow struct {
	boot            string
	issued, expires time.Time
	nonce           []byte
	boottime        uint64
}

// openChallenge requires the current boot to equal both the committed session
// boot and the boot the native plan was observed in.
func (s *Service) openChallenge(loaded *bound, issued time.Time, planBoot string, limits ...time.Time) (challengeWindow, error) {
	boot, err := s.bootID()
	if err != nil {
		return challengeWindow{}, err
	}
	if boot != loaded.state.GetSessionBootId() {
		return challengeWindow{}, errSessionRequired
	}
	if boot != planBoot {
		return challengeWindow{}, errResourceRejected
	}
	ns, err := s.boottime()
	if err != nil {
		return challengeWindow{}, err
	}
	expires := issued.Add(30 * time.Second)
	for _, limit := range limits {
		if limit.Before(expires) {
			expires = limit
		}
	}
	lifetime := expires.Sub(issued)
	if lifetime <= 0 || ns > math.MaxInt64-uint64(lifetime) {
		return challengeWindow{}, errResourceExpired
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(s.entropy, nonce); err != nil {
		return challengeWindow{}, err
	}
	return challengeWindow{boot: boot, issued: issued, expires: expires, nonce: nonce, boottime: ns + uint64(lifetime)}, nil
}

// challengeDeadline is the durable start deadline: same executor incarnation
// and boot, inside the wall-clock window, and inside the CLOCK_BOOTTIME window
// that suspend or clock changes cannot extend.
func (s *Service) challengeDeadline(challenge signedChallenge, deadline uint64) error {
	now := s.now()
	if !challenge.ProtoReflect().IsValid() || challenge.GetExecutorIncarnation() != s.incarnation || now.Before(challenge.GetIssuedAt().AsTime()) || !now.Before(challenge.GetExpiresAt().AsTime()) {
		return errResourceExpired
	}
	boot, err := s.bootID()
	if err != nil {
		return err
	}
	if boot != challenge.GetBootId() {
		return errResourceExpired
	}
	ns, err := s.boottime()
	if err != nil {
		return err
	}
	lifetime := uint64(challenge.GetExpiresAt().AsTime().Sub(challenge.GetIssuedAt().AsTime()))
	if deadline < lifetime || ns < deadline-lifetime || ns >= deadline {
		return errResourceExpired
	}
	return nil
}

// attestationHeader is the identity, session and freshness every history
// attestation signs around a kind's status.
type attestationHeader struct {
	deploymentID, deviceID, generation string
	sessionEpoch, revision             uint64
	nonce                              []byte
	issued, expires                    *timestamppb.Timestamp
}

// attest signs a protected record for the relay's fresh nonce. The relay
// selects only an existing action and opaque nonce; every signed fact, the
// identity, session and key come from protected state. Historical validation
// can outlast the current credential, so it is rechecked at issuance; an
// expired execution delegation does not invalidate history.
func (k *signedAction[I, C, G, R]) attest(ctx context.Context, s *Service, loaded *bound, actionID string, nonce []byte, build func(attestationHeader, R) proto.Message) (envelope, certificate []byte, err error) {
	if err := s.actionIdentitySession(loaded); err != nil {
		return nil, nil, err
	}
	record, revision, err := k.loadAction(ctx, s, loaded, actionID)
	if err != nil {
		return nil, nil, err
	}
	if revision <= 0 {
		s.noteTrustDamage()
		return nil, nil, errRecoveryHold
	}
	now := s.now()
	if !certUsable(loaded.cert, now) {
		return nil, nil, errIdentityExpired
	}
	expires := now.Add(30 * time.Second)
	if loaded.cert.NotAfter.Before(expires) {
		expires = loaded.cert.NotAfter
	}
	header := attestationHeader{
		deploymentID: loaded.bootstrap.Root.GetDeploymentId(), deviceID: loaded.state.GetDeviceId(), generation: loaded.state.GetEnrollmentGeneration(),
		sessionEpoch: loaded.state.GetSessionEpoch(), revision: uint64(revision), nonce: bytes.Clone(nonce),
		issued: protoTimestamp(now), expires: protoTimestamp(expires),
	}
	envelope, err = s.authority.Sign(ctx, build(header, record), loaded.identityKey)
	if err != nil {
		return nil, nil, err
	}
	return envelope, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: loaded.cert.Raw}), nil
}

func signedAuthorityError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errResourceRejected
}
