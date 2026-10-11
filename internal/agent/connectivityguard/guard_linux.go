//go:build linux

package connectivityguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

// Config is constructor-only custody, never a remotely deserialized override.
// Origin/TransportTLS come from authenticated enrollment and the executor's
// existing device certificate crypto.Signer. The key is never copied to disk.
// New must run in the dedicated native helper: the supervisor may kill its PID.
type Config struct {
	Directory            string
	Policy               *agentv1.ConnectivityGuardConfig
	Native               *agentv1.NativeFirewallProviderConfig
	Origin               string
	TransportTLS         *tls.Config
	DeploymentID         string
	DeviceID             string
	EnrollmentGeneration string
	SessionEpoch         uint64
	// RetainConfirmation fsyncs the controller receipt into protected per-action
	// custody before the bounded active slot can become replaceable. Verification
	// does not require this callback; production ARM and COMMITTED do.
	RetainConfirmation func(context.Context, *agentv1.NativeResourceTransactionRequest, []byte) error
}
type Guard struct {
	store     *store
	config    Config
	authority *trust.Authority
}

func New(config Config) (*Guard, error) {
	s, err := openStore(config.Directory)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Guard, error) { return nil, errors.Join(err, s.close()) }
	if config.Policy == nil || config.Native == nil {
		return fail(ErrConflict)
	}
	if err := s.validate(config.Policy); err != nil {
		return fail(err)
	}
	if err := s.validate(config.Native); err != nil {
		return fail(err)
	}
	if config.TransportTLS == nil || config.TransportTLS.InsecureSkipVerify || config.TransportTLS.RootCAs == nil || config.SessionEpoch == 0 {
		return fail(ErrConflict)
	}
	if config.TransportTLS.GetClientCertificate == nil && (len(config.TransportTLS.Certificates) != 1 || config.TransportTLS.Certificates[0].PrivateKey == nil) {
		return fail(ErrConflict)
	}
	if _, err := controllerAddress(config.Origin); err != nil {
		return fail(err)
	}
	authority, err := trust.New()
	if err != nil {
		return fail(err)
	}
	config.Policy = proto.CloneOf(config.Policy)
	config.Native = proto.CloneOf(config.Native)
	config.TransportTLS = config.TransportTLS.Clone()
	if config.Policy.TimeoutSeconds == nil {
		config.Policy.TimeoutSeconds = proto.Uint32(120)
	}
	return &Guard{store: s, config: config, authority: authority}, nil
}
func (g *Guard) Close() error { return g.store.close() }
func (g *Guard) Arm(ctx context.Context, request *agentv1.NativeResourceTransactionRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if request.GetPlan().GetRef().GetKind() != 8 || g.config.RetainConfirmation == nil {
		return ErrConflict
	}
	lock, err := g.store.lockWorker(ctx, "record.lock")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	// Readiness is checked under the record lock: shutdown withdraws readiness
	// first, then drains this same lock, so no ARM can escape the stop boundary.
	supervisor, err := g.store.open("supervisor.lock", false)
	if err != nil {
		return err
	}
	defer func() { _ = supervisor.Close() }()
	if err := unix.Flock(int(supervisor.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		return errors.Join(ErrUnconfirmed, err)
	}
	policy, err := io.ReadAll(io.LimitReader(supervisor, 65537))
	if err != nil {
		return err
	}
	expected, err := proto.MarshalOptions{Deterministic: true}.Marshal(g.config.Native)
	if err != nil {
		return err
	}
	if len(policy) > 65536 || !bytes.Equal(policy, expected) {
		return ErrConflict
	}
	old, err := g.store.load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if old != nil && (!terminal(old.GetPhase()) || old.GetPhase() == agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_CONFLICT) {
		return ErrConflict
	}
	now, err := bootTime()
	if err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	start, err := processStart(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	return g.store.save(&agentv1.ConnectivityGuardRecord{Version: 1, Request: proto.CloneOf(request), BootId: boot, DeadlineBoottimeNs: now + uint64(time.Duration(g.config.Policy.GetTimeoutSeconds())*time.Second), Phase: agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_ARMED, Nonce: nonce, WorkerPid: uint32(os.Getpid()), WorkerStartTicks: start})
}
func (g *Guard) bound(request *agentv1.NativeResourceTransactionRequest) (*agentv1.ConnectivityGuardRecord, error) {
	r, err := g.store.load()
	if err != nil {
		return nil, err
	}
	if !proto.Equal(r.GetRequest(), request) || r.GetWorkerPid() != uint32(os.Getpid()) {
		return nil, ErrConflict
	}
	if _, err := remaining(r); err != nil {
		return nil, err
	}
	return r, nil
}
func (g *Guard) Applied(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, applied *agentv1.ResourceOwnershipSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lock, err := g.store.lockWorker(ctx, "record.lock")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	r, err := g.bound(request)
	if err != nil {
		return err
	}
	if r.GetPhase() != agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_ARMED || applied.GetFirewall() == nil {
		return ErrConflict
	}
	r.Applied = proto.CloneOf(applied)
	r.Phase = agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_APPLIED
	return g.store.save(r)
}
func (g *Guard) Confirm(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, applied *agentv1.ResourceOwnershipSnapshot) error {
	// Network work holds no root record lock, and runs only on the native worker.
	lock, err := g.store.lockWorker(ctx, "record.lock")
	if err != nil {
		return err
	}
	r, loadErr := g.bound(request)
	closeErr := lock.Close()
	if err := errors.Join(loadErr, closeErr); err != nil {
		return err
	}
	if r.GetPhase() != agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_APPLIED || !proto.Equal(r.GetApplied(), applied) {
		return ErrConflict
	}
	duration, err := remaining(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	probes, err := g.probe(ctx, request.GetActionId(), applied)
	if err != nil {
		return err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(applied)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	generation := request.GetTarget().GetFirewall().GetPersistent().GetGeneration()
	if generation == "" {
		generation = request.GetActionId()
	}
	confirmation := &agentv1.ConnectivityConfirmation{DeploymentId: g.config.DeploymentID, DeviceId: g.config.DeviceID, EnrollmentGeneration: g.config.EnrollmentGeneration, ActionId: request.GetActionId(), Ref: proto.CloneOf(request.GetPlan().GetRef()), AppliedGeneration: generation, AppliedSha256: sum[:], Nonce: bytes.Clone(r.GetNonce()), SessionEpoch: g.config.SessionEpoch, Probes: probes}
	receipt, err := g.confirm(ctx, confirmation)
	if err != nil {
		return err
	}
	lock, err = g.store.lockWorker(ctx, "record.lock")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	current, err := g.bound(request)
	if err != nil {
		return err
	}
	if !proto.Equal(current, r) {
		return ErrConflict
	}
	current.ConfirmationReceipt = receipt
	current.Phase = agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_CONFIRMED
	return g.store.save(current)
}
func (g *Guard) Committed(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, applied *agentv1.ResourceOwnershipSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.config.RetainConfirmation == nil {
		return ErrConflict
	}
	lock, err := g.store.lockWorker(ctx, "record.lock")
	if err != nil {
		return err
	}
	r, loadErr := g.bound(request)
	closeErr := lock.Close()
	if err := errors.Join(loadErr, closeErr); err != nil {
		return err
	}
	if r.GetPhase() != agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_CONFIRMED || len(r.GetConfirmationReceipt()) == 0 || applied.GetFirewall() == nil {
		return ErrConflict
	}
	duration, err := remaining(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	if err := g.validateRetainedConfirmation(ctx, r); err != nil {
		return err
	}
	// The provider has completed exact read-back and its durable native COMMITTED
	// replacement. Retain historical proof outside the guard lock: timeout recovery
	// must still be able to kill a stalled worker and apply the exact inverse.
	if err := g.config.RetainConfirmation(ctx, request, r.GetConfirmationReceipt()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lock, err = g.store.lockWorker(ctx, "record.lock")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	current, err := g.bound(request)
	if err != nil {
		return err
	}
	if !proto.Equal(current, r) {
		return ErrConflict
	}
	current.Phase = agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_COMMITTED
	return g.store.save(current)
}

// Status is read-only polling, never a network operation or wait for confirmation.
func Status(directory string) (*agentv1.ConnectivityGuardRecord, error) {
	s, err := openStore(directory)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.close() }()
	lock, err := s.lock("record.lock")
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.Close() }()
	return s.load()
}

// Outcome reads the retained record without the record lock, so the executor
// can read it through its read-only view of /var. It is evidence for resolving
// an interrupted effect's local ownership, never admission or replay authority.
func Outcome(directory string) (*agentv1.ConnectivityGuardRecord, error) {
	s, err := openStore(directory)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.close() }()
	return s.load()
}
