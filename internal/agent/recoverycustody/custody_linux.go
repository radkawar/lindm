// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package recoverycustody anchors one signed recovery action in a TPM2 persistent
// sealed object and synchronous NV counter/checkpoint. It owns no execution
// authority: callers still verify the original signed handoff, fresh grant and
// authenticated server checkpoint before effects. Missing/corrupt/stale state
// never reopens an already consumed action. It never clears occupied TPM slots.
package recoverycustody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
)

const (
	PersistentHandle    uint32 = 0x81004c4d
	CounterIndex        uint32 = 0x01804c4d
	CheckpointIndex     uint32 = 0x01804c4e
	nvBytes                    = 512
	maximumJournalBytes        = 1 << 20
	operationTimeout           = 90 * time.Second
)

var (
	ErrUnsupported = errors.New("tpm_recovery_unsupported")
	ErrOccupied    = errors.New("tpm_recovery_reservation_occupied")
	ErrUnknown     = errors.New("tpm_recovery_outcome_unknown")
	ErrConsumed    = errors.New("tpm_recovery_effect_consumed")
	ErrClosed      = errors.New("tpm_recovery_custody_closed")
)

type nativeState struct {
	name, policy, data []byte
	counter            uint64
}

type backend interface {
	check(context.Context) ([]byte, error)
	reserve(context.Context, []byte, []byte, []byte, func([]byte, uint64) ([]byte, error)) (nativeState, error)
	open(context.Context) ([]byte, nativeState, error)
	read(context.Context, []byte) (nativeState, error)
	advance(context.Context, []byte, uint64, func(uint64) ([]byte, error)) (nativeState, error)
}

// Pending retains only locked anonymous secret pages until Commit seals them.
// A process restart before Seal loses this pending action; there is no disk key.
type Pending struct {
	mu        sync.Mutex
	secret    []byte // Ed25519 private key (64), followed by independent NV auth (32).
	backend   backend
	validator protovalidate.Validator
}

// Store is a StateStore for recovery.Runtime. Its full journal is nonsecret RAM;
// the current exact digest and consumed marker persist independently in TPM NV.
// A caller must retain Close until all users of the borrowed Signer finish.
type Store struct {
	mu        sync.Mutex
	secret    []byte
	journal   []byte
	action    *agentv1.DeviceActionSpec
	anchor    *agentv1.TPMRecoveryCheckpoint
	backend   backend
	validator protovalidate.Validator
}

func validator() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(&agentv1.TPMRecoveryCheckpoint{}, &agentv1.RecoveryJournal{}), protovalidate.WithDisableLazy())
}

func locked(size int) ([]byte, error) {
	memory, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, err
	}
	if err := unix.Mlock(memory); err != nil {
		return nil, errors.Join(err, unix.Munmap(memory))
	}
	if err := unix.Madvise(memory, unix.MADV_DONTDUMP); err != nil {
		return nil, errors.Join(err, unix.Munlock(memory), unix.Munmap(memory))
	}
	return memory, nil
}

func erase(memory []byte) error {
	if memory == nil {
		return nil
	}
	clear(memory)
	return errors.Join(unix.Munlock(memory), unix.Munmap(memory))
}

// TPM session codecs and Ed25519 contain transient Go-heap copies that cannot be
// individually pinned. Lock the process before generating or unsealing a secret.
// Do not Munlockall on Close: other in-process custody may still own locked keys.
func lockProcessMemory() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return errors.Join(ErrUnsupported, err)
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return errors.Join(ErrUnsupported, err)
	}
	return nil
}

func Generate() (_ *Pending, err error) {
	if err := lockProcessMemory(); err != nil {
		return nil, err
	}
	validate, err := validator()
	if err != nil {
		return nil, err
	}
	secret, err := locked(ed25519.PrivateKeySize + 32)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, erase(secret))
		}
	}()
	if _, err := rand.Read(secret[:ed25519.SeedSize]); err != nil {
		return nil, err
	}
	key := ed25519.NewKeyFromSeed(secret[:ed25519.SeedSize])
	copy(secret, key)
	clear(key)
	if _, err := rand.Read(secret[ed25519.PrivateKeySize:]); err != nil {
		return nil, err
	}
	return &Pending{secret: secret, backend: nativeTPM{}, validator: validate}, nil
}

func (p *Pending) PublicKey() ed25519.PublicKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.secret == nil {
		return nil
	}
	return bytes.Clone(p.secret[ed25519.SeedSize:ed25519.PrivateKeySize])
}

// Signer is borrowed locked memory, never an owned copy. Do not retain past Close.
func (p *Pending) Signer() ed25519.PrivateKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.secret == nil {
		return nil
	}
	return ed25519.PrivateKey(p.secret[:ed25519.PrivateKeySize])
}

func (p *Pending) Check(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.secret == nil {
		return ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	_, err := p.backend.check(ctx)
	return err
}

func (p *Pending) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := erase(p.secret)
	p.secret = nil
	return err
}

func (p *Pending) Seal(ctx context.Context, handoff *agentv1.DeviceActionRecoveryHandoff, pcr11 []byte, initial *agentv1.RecoveryJournal) (_ *Store, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.secret == nil {
		return nil, ErrClosed
	}
	if handoff == nil || handoff.GetCustody() != agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM || len(pcr11) != sha256.Size || !bytes.Equal(handoff.GetRecoveryPublicKey(), p.secret[32:64]) || initial == nil || !proto.Equal(initial.GetHandoff(), handoff) || initial.GetCheckpoint() != nil {
		return nil, ErrUnsupported
	}
	if err := p.validator.Validate(initial); err != nil {
		return nil, err
	}
	journal, err := marshalJournal(initial)
	if err != nil {
		return nil, err
	}
	handoffBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(handoff)
	if err != nil {
		return nil, err
	}
	handoffHash, journalHash := sha256.Sum256(handoffBytes), sha256.Sum256(journal)
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	pcr7, err := p.backend.check(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := recoveryPolicy(pcr7, pcr11)
	if err != nil {
		return nil, err
	}
	payload, err := locked(64)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, erase(payload)) }()
	copy(payload[:32], p.secret[:32])
	copy(payload[32:], p.secret[64:])
	var anchor *agentv1.TPMRecoveryCheckpoint
	state, err := p.backend.reserve(ctx, payload, policy, p.secret[64:], func(name []byte, counter uint64) ([]byte, error) {
		anchor = &agentv1.TPMRecoveryCheckpoint{FormatVersion: 1, HandoffSha256: handoffHash[:], ImageSha256: bytes.Clone(handoff.GetRecoveryImageSha256()), RecoveryPublicKey: bytes.Clone(p.secret[32:64]), ObjectName: bytes.Clone(name), PolicySha256: bytes.Clone(policy), NvCounter: counter, JournalSha256: journalHash[:], InitialCapsuleSha256: bytes.Clone(journalHash[:])}
		return encodeCheckpoint(p.validator, anchor)
	})
	if err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}
	if err := validateNativeState(state, anchor); err != nil {
		return nil, err
	}
	store := &Store{secret: p.secret, journal: journal, action: proto.CloneOf(handoff.GetIntent().GetSpec()), anchor: anchor, backend: p.backend, validator: p.validator}
	p.secret = nil
	return store, nil
}

// SnapshotLoader retrieves an authenticated server snapshot using the borrowed
// recovery key and the already TPM-authenticated original capsule. It must not
// retain or modify the key. Returned bytes remain untrusted until their exact
// digest matches the current NV anchor. No loader runs for a consumed action.
type SnapshotLoader func(context.Context, ed25519.PrivateKey, *agentv1.RecoveryJournal, []byte) ([]byte, error)

// Open authenticates the opaque capsule digest against NV before parsing any of
// its protobuf fields. PCR policy must already match the exact approved UKI.
func Open(ctx context.Context, capsule []byte) (*Store, error) {
	return openWithBackend(ctx, capsule, nativeTPM{}, nil)
}

// OpenWithSnapshot additionally reconstructs an unconsumed newer journal from
// the server when only the original ESP capsule survived. Missing, stale or
// mismatched snapshots remain UNKNOWN, not permission to retry an effect.
func OpenWithSnapshot(ctx context.Context, capsule []byte, load SnapshotLoader) (*Store, error) {
	return openWithBackend(ctx, capsule, nativeTPM{}, load)
}

func openWithBackend(ctx context.Context, capsule []byte, native backend, load SnapshotLoader) (_ *Store, err error) {
	if len(capsule) == 0 || len(capsule) > maximumJournalBytes {
		return nil, ErrUnsupported
	}
	validate, err := validator()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	payload, state, err := native.open(ctx)
	if err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}
	defer clear(payload)
	if len(payload) != 64 {
		return nil, ErrUnknown
	}
	anchor, err := decodeCheckpoint(validate, state.data)
	if err != nil {
		return nil, err
	}
	if err := validateNativeState(state, anchor); err != nil {
		return nil, err
	}
	// A spent action never becomes a new execution even with an older capsule.
	if anchor.GetConsumed() {
		return nil, ErrConsumed
	}
	digest := sha256.Sum256(capsule)
	current := bytes.Equal(digest[:], anchor.GetJournalSha256())
	if !current && !bytes.Equal(digest[:], anchor.GetInitialCapsuleSha256()) {
		return nil, ErrUnknown
	}
	journal, err := parseAuthenticatedJournal(validate, capsule, anchor)
	if err != nil {
		return nil, err
	}
	secret, err := locked(96)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, erase(secret))
		}
	}()
	key := ed25519.NewKeyFromSeed(payload[:32])
	copy(secret, key)
	clear(key)
	copy(secret[64:], payload[32:])
	if !bytes.Equal(secret[32:64], anchor.GetRecoveryPublicKey()) || !bytes.Equal(secret[32:64], journal.GetHandoff().GetRecoveryPublicKey()) {
		return nil, ErrUnknown
	}
	if !current {
		if load == nil {
			return nil, ErrUnknown
		}
		capsule, err = load(ctx, ed25519.PrivateKey(secret[:64]), journal, bytes.Clone(anchor.GetJournalSha256()))
		if err != nil {
			return nil, errors.Join(ErrUnknown, err)
		}
		digest = sha256.Sum256(capsule)
		if len(capsule) == 0 || len(capsule) > maximumJournalBytes || !bytes.Equal(digest[:], anchor.GetJournalSha256()) {
			return nil, ErrUnknown
		}
		journal, err = parseAuthenticatedJournal(validate, capsule, anchor)
		if err != nil {
			return nil, err
		}
	}
	if journal.GetCheckpoint().GetPhase() != anchor.GetPhase() {
		return nil, ErrUnknown
	}
	// A network reconstruction must not conceal a concurrent counter advance.
	state, err = native.read(ctx, secret[64:])
	if err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}
	if err := validateNativeState(state, anchor); err != nil {
		return nil, err
	}
	return &Store{secret: secret, journal: bytes.Clone(capsule), action: proto.CloneOf(journal.GetHandoff().GetIntent().GetSpec()), anchor: anchor, backend: native, validator: validate}, nil
}

func parseAuthenticatedJournal(validate protovalidate.Validator, data []byte, anchor *agentv1.TPMRecoveryCheckpoint) (*agentv1.RecoveryJournal, error) {
	var journal agentv1.RecoveryJournal
	if err := proto.Unmarshal(data, &journal); err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}
	if err := protodata.ValidateClosed(journal.ProtoReflect()); err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}
	if err := validate.Validate(&journal); err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}
	handoffBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(journal.GetHandoff())
	if err != nil {
		return nil, err
	}
	handoffHash := sha256.Sum256(handoffBytes)
	if !bytes.Equal(handoffHash[:], anchor.GetHandoffSha256()) || !bytes.Equal(journal.GetHandoff().GetRecoveryImageSha256(), anchor.GetImageSha256()) || journal.GetHandoff().GetCustody() != agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM || !bytes.Equal(journal.GetHandoff().GetRecoveryPublicKey(), anchor.GetRecoveryPublicKey()) {
		return nil, ErrUnknown
	}
	return &journal, nil
}

func (s *Store) PublicKey() ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret == nil {
		return nil
	}
	return bytes.Clone(s.secret[32:64])
}
func (s *Store) Signer() ed25519.PrivateKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret == nil {
		return nil
	}
	return ed25519.PrivateKey(s.secret[:64])
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := erase(s.secret)
	s.secret = nil
	s.journal = nil
	return err
}

func (s *Store) Check(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.check(ctx)
}

// CheckAction is the actionprovider TrustedRecoveryCustody callback. It proves
// both durable TPM state and the exact immutable signed recovery sanitize spec;
// it is not an execution grant and does not bypass offline target qualification.
func (s *Store) CheckAction(ctx context.Context, spec *agentv1.DeviceActionSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if spec.GetSanitize().GetRecovery() == nil || !proto.Equal(spec, s.action) {
		return ErrUnsupported
	}
	return s.check(ctx)
}

func (s *Store) check(ctx context.Context) error {
	if s.secret == nil {
		return ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	state, err := s.backend.read(ctx, s.secret[64:])
	if err != nil {
		return errors.Join(ErrUnknown, err)
	}
	return validateNativeState(state, s.anchor)
}

func (s *Store) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret == nil {
		return nil, ErrClosed
	}
	return bytes.Clone(s.journal), nil
}

func (s *Store) Load(destination proto.Message) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(context.Background()); err != nil {
		return true, err
	}
	if err := proto.Unmarshal(s.journal, destination); err != nil {
		return true, err
	}
	return true, protodata.ValidateClosed(destination.ProtoReflect())
}

func (s *Store) Save(message proto.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	journal, ok := message.(*agentv1.RecoveryJournal)
	if !ok || journal == nil {
		return ErrUnsupported
	}
	if err := s.validator.Validate(journal); err != nil {
		return err
	}
	data, err := marshalJournal(journal)
	if err != nil {
		return err
	}
	handoff, err := proto.MarshalOptions{Deterministic: true}.Marshal(journal.GetHandoff())
	if err != nil {
		return err
	}
	digest := sha256.Sum256(handoff)
	if !bytes.Equal(digest[:], s.anchor.GetHandoffSha256()) {
		return ErrUnknown
	}
	phase := journal.GetCheckpoint().GetPhase()
	if phase < s.anchor.GetPhase() || phase == agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED && !s.anchor.GetConsumed() {
		return ErrUnknown
	}
	updated := proto.CloneOf(s.anchor)
	updated.Phase = phase
	journalHash := sha256.Sum256(data)
	updated.JournalSha256 = journalHash[:]
	if err := s.commit(updated); err != nil {
		return err
	}
	s.journal = data
	return nil
}

func (s *Store) Consumed() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(context.Background()); err != nil {
		return true, err
	}
	return s.anchor.GetConsumed(), nil
}

func (s *Store) Consume() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.anchor.GetConsumed() {
		return ErrConsumed
	}
	updated := proto.CloneOf(s.anchor)
	updated.Consumed = true
	return s.commit(updated)
}

func (s *Store) commit(updated *agentv1.TPMRecoveryCheckpoint) error {
	if s.secret == nil {
		return ErrClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	if err := s.check(ctx); err != nil {
		return err
	}
	state, err := s.backend.advance(ctx, s.secret[64:], s.anchor.GetNvCounter(), func(counter uint64) ([]byte, error) {
		updated.NvCounter = counter
		return encodeCheckpoint(s.validator, updated)
	})
	if err != nil {
		return errors.Join(ErrUnknown, err)
	}
	if err := validateNativeState(state, updated); err != nil {
		return err
	}
	s.anchor = updated
	return nil
}

func marshalJournal(message *agentv1.RecoveryJournal) ([]byte, error) {
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return nil, err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maximumJournalBytes {
		return nil, ErrUnsupported
	}
	return data, nil
}

func encodeCheckpoint(validate protovalidate.Validator, record *agentv1.TPMRecoveryCheckpoint) ([]byte, error) {
	if err := protodata.ValidateClosed(record.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := validate.Validate(record); err != nil {
		return nil, err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > nvBytes-4 {
		return nil, ErrUnsupported
	}
	framed := make([]byte, nvBytes)
	binary.BigEndian.PutUint32(framed[:4], uint32(len(data)))
	copy(framed[4:], data)
	return framed, nil
}

func decodeCheckpoint(validate protovalidate.Validator, data []byte) (*agentv1.TPMRecoveryCheckpoint, error) {
	if len(data) != nvBytes {
		return nil, ErrUnknown
	}
	length := int(binary.BigEndian.Uint32(data[:4]))
	if length == 0 || length > nvBytes-4 {
		return nil, ErrUnknown
	}
	for _, value := range data[4+length:] {
		if value != 0 {
			return nil, ErrUnknown
		}
	}
	var record agentv1.TPMRecoveryCheckpoint
	if err := proto.Unmarshal(data[4:4+length], &record); err != nil {
		return nil, errors.Join(ErrUnknown, err)
	}
	if err := protodata.ValidateClosed(record.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := validate.Validate(&record); err != nil {
		return nil, err
	}
	return &record, nil
}

func validateNativeState(state nativeState, anchor *agentv1.TPMRecoveryCheckpoint) error {
	if anchor == nil || state.counter != anchor.GetNvCounter() || !bytes.Equal(state.name, anchor.GetObjectName()) || !bytes.Equal(state.policy, anchor.GetPolicySha256()) {
		return ErrUnknown
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(anchor)
	if err != nil {
		return err
	}
	if len(encoded) > nvBytes-4 || len(state.data) != nvBytes || binary.BigEndian.Uint32(state.data[:4]) != uint32(len(encoded)) || !bytes.Equal(state.data[4:4+len(encoded)], encoded) {
		return ErrUnknown
	}
	for _, value := range state.data[4+len(encoded):] {
		if value != 0 {
			return ErrUnknown
		}
	}
	return nil
}

func (p *Pending) String() string { return "TPM recovery pending custody (redacted)" }
func (s *Store) String() string   { return "TPM recovery custody (redacted)" }
func (p *Pending) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("%w: private custody cannot be serialized", ErrUnsupported)
}
func (s *Store) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("%w: private custody cannot be serialized", ErrUnsupported)
}
