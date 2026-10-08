//go:build linux

package executor

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/localrpc"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

const rpcTimeout = 15 * time.Second

var (
	// ErrBusy means another process holds the executor state lock.
	ErrBusy = errors.New("executor state already has an owner")

	errRecoveryHold           = errors.New("recovery_hold")
	errUnprovisioned          = errors.New("unprovisioned")
	errPendingEnrollment      = errors.New("pending_enrollment")
	errAlreadyEnrolled        = errors.New("already_enrolled")
	errTrustReplacement       = errors.New("trust_replacement_rejected")
	errExecutionTrustRejected = errors.New("execution_trust_rejected")
	errGrantMismatch          = errors.New("grant_mismatch")
	errBootstrapRejected      = errors.New("bootstrap_rejected")
	errIdentityExpired        = errors.New("identity_expired")
	errRenewalNotDue          = errors.New("renewal_not_due")
	errRenewalPending         = errors.New("renewal_pending")
	errSessionPending         = errors.New("session_pending")
	errSessionRequired        = errors.New("session_required")
	errEpochRejected          = errors.New("epoch_rejected")
	errCertificateRejected    = errors.New("certificate_rejected")
	errSigningRejected        = errors.New("signing_rejected")
	errIdempotencyConflict    = errors.New("idempotency_conflict")
	errNotPending             = errors.New("not_pending")
	errInvalid                = errors.New("invalid_request")
	errInternal               = errors.New("internal")
	errClosed                 = errors.New("executor_closed")
	errServiceRejected        = errors.New("service_execution_rejected")
	errServiceExpired         = errors.New("service_execution_expired")
)

// Option configures process-local test seams. RPC callers cannot set them.
type Option func(*Service)

// WithClock replaces the process clock. Production uses time.Now.
func WithClock(clock func() time.Time) Option {
	return func(s *Service) {
		if clock != nil {
			s.clock = clock
		}
	}
}

// WithBootID replaces the /proc boot identity reader.
func WithBootID(read func() (string, error)) Option {
	return func(s *Service) {
		if read != nil {
			s.bootID = read
		}
	}
}

// WithEntropy replaces key and jitter entropy. It cannot select epochs.
func WithEntropy(r io.Reader) Option {
	return func(s *Service) {
		if r != nil {
			s.entropy = r
		}
	}
}

// Service is the protected executor state machine. It implements the local
// ExecutorService handler. Private keys never leave its methods.
type Service struct {
	mu            sync.Mutex
	directory     string
	stateLock     *os.File
	store         *journal.Store
	authority     *trust.Authority
	validator     protovalidate.Validator
	clock         func() time.Time
	bootID        func() (string, error)
	entropy       io.Reader
	hold          bool
	holdReason    agentv1.HoldReason
	closed        bool
	closeDone     chan struct{}
	closeErr      error
	operations    sync.WaitGroup
	worker        sync.WaitGroup
	workerContext context.Context
	workerCancel  context.CancelFunc
	workerWake    chan struct{}
	incarnation   string
	boottime      func() (uint64, error)
	openService   func(context.Context) (nativeService, error)
}

var _ agentv1connect.ExecutorServiceHandler = (*Service)(nil)

// Config is resolved runtime configuration, not a serialized document.
type Config struct {
	StateDirectory   string
	RuntimeDirectory string
	SocketName       string
	NetworkUID       uint32
	NetworkGID       uint32
	RequireRoot      bool
}

// Run serves the executor until ctx is canceled. Cancellation exits without
// deleting state. RequireRoot is for the production command, not library tests.
func Run(ctx context.Context, cfg Config) error {
	if cfg.RequireRoot && os.Geteuid() != 0 {
		return errors.New("executor requires root")
	}
	svc, err := New(ctx, cfg.StateDirectory)
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()
	return localrpc.Serve(ctx, localrpc.ListenConfig{
		Directory:  cfg.RuntimeDirectory,
		SocketName: cfg.SocketName,
		NetworkUID: cfg.NetworkUID,
		NetworkGID: cfg.NetworkGID,
	}, svc)
}

// New locks the state directory and opens an existing journal, or remains
// unprovisioned until PrepareBootstrap. Corrupt state becomes recovery hold.
func New(ctx context.Context, directory string, opts ...Option) (*Service, error) {
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(
		&agentv1.PrepareBootstrapRequest{}, &agentv1.InstallEnrollmentRequest{},
		&agentv1.GetConnectionRequest{}, &agentv1.SignTLSClientMessageRequest{},
		&agentv1.PrepareSessionRequest{}, &agentv1.CommitSessionRequest{},
		&agentv1.PrepareRenewalRequest{}, &agentv1.CommitRenewalRequest{},
		&agentv1.UpdateExecutionTrustRequest{}, &agentv1.StatusRequest{},
		&agentv1.PrepareServiceExecutionRequest{}, &agentv1.StartServiceExecutionRequest{},
		&agentv1.GetServiceExecutionRequest{}, &agentv1.ServiceExecutionRecord{},
		&agentv1.ServiceExecutionIntent{}, &agentv1.ServiceExecutionChallenge{},
	), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, err
	}
	svc := &Service{
		directory:   directory,
		stateLock:   os.NewFile(uintptr(fd), "executor-state-lock"),
		authority:   authority,
		validator:   validator,
		clock:       time.Now,
		bootID:      readBootID,
		entropy:     rand.Reader,
		closeDone:   make(chan struct{}),
		workerWake:  make(chan struct{}, 1),
		boottime:    readBoottime,
		openService: openNativeService,
	}
	for _, opt := range opts {
		opt(svc)
	}
	svc.workerContext, svc.workerCancel = context.WithCancel(context.Background())
	svc.incarnation, err = newID()
	if err != nil {
		_ = svc.Close()
		return nil, err
	}
	store, err := journal.OpenLocked(ctx, directory, svc.stateLock)
	switch {
	case err == nil:
		svc.store = store
		if _, loadErr := svc.load(ctx); loadErr != nil && !errors.Is(loadErr, errRecoveryHold) && ctx.Err() == nil {
			_ = svc.Close()
			return nil, loadErr
		}
	case errors.Is(err, journal.ErrUnprovisioned):
	case errors.Is(err, journal.ErrRecoveryHold):
		svc.hold = true
		svc.holdReason = agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT
	case errors.Is(err, journal.ErrAlreadyOpen):
		_ = svc.Close()
		return nil, ErrBusy
	default:
		_ = svc.Close()
		return nil, err
	}
	if err := svc.recoverServiceActions(ctx); err != nil && !errors.Is(err, errRecoveryHold) {
		_ = svc.Close()
		return nil, err
	}
	svc.worker.Add(1)
	go svc.serviceWorker()
	return svc, nil
}

// Close prevents admission, cancels native work and joins outside the authority
// mutex. Completion evidence is persisted before storage or its lock is closed.
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return s.closeErr
	}
	s.closed = true
	if s.workerCancel != nil {
		s.workerCancel()
	}
	s.mu.Unlock()
	s.operations.Wait()
	s.worker.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		s.closeErr = s.store.Close()
		s.store = nil
	}
	if s.stateLock != nil {
		s.closeErr = errors.Join(s.closeErr, s.stateLock.Close())
		s.stateLock = nil
	}
	close(s.closeDone)
	return s.closeErr
}

func (s *Service) now() time.Time { return s.clock().UTC() }

func (s *Service) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errClosed
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *Service) load(ctx context.Context) (*bound, error) {
	if s.hold {
		return nil, errRecoveryHold
	}
	if s.store == nil {
		return nil, errUnprovisioned
	}
	state, revision, err := s.store.Load(ctx)
	if err != nil {
		if errors.Is(err, journal.ErrRecoveryHold) {
			s.hold = true
			s.holdReason = agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT
			return nil, errRecoveryHold
		}
		return nil, err
	}
	now := s.now()
	loaded, err := bind(ctx, s.authority, state, now)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.hold = true
		s.holdReason = agentv1.HoldReason_HOLD_REASON_IDENTITY_BINDING
		return nil, errRecoveryHold
	}
	if err := bindExecutionTrust(ctx, s.authority, s.store, loaded); err != nil {
		if errors.Is(err, errRecoveryHold) {
			s.noteTrustDamage()
		}
		return nil, err
	}
	if loaded.prior != nil && !now.Before(loaded.prior.retain) {
		// Validate all bindings before retirement, then durably remove the old
		// private key before returning authority to any caller.
		state.PriorCredential = nil
		revision, err = s.store.Update(ctx, revision, state)
		if err != nil {
			if errors.Is(err, journal.ErrConflict) {
				return nil, errInternal
			}
			return nil, err
		}
		loaded.prior = nil
	}
	loaded.revision = revision
	return loaded, nil
}

func (s *Service) commit(ctx context.Context, revision int64, state *agentv1.ExecutorJournalState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := bind(ctx, s.authority, state, s.now()); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errInternal
	}
	if _, err := s.store.Update(ctx, revision, state); err != nil {
		if errors.Is(err, journal.ErrConflict) {
			return errInternal
		}
		return err
	}
	return nil
}

func (s *Service) admit(msg proto.Message) error {
	if msg == nil || !msg.ProtoReflect().IsValid() {
		return errInvalid
	}
	if err := protodata.ValidateClosed(msg.ProtoReflect()); err != nil || s.validator.Validate(msg) != nil {
		return errInvalid
	}
	return nil
}

func (s *Service) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, rpcTimeout)
}

func (s *Service) noteInitFailure(ctx context.Context) {
	store, err := journal.OpenLocked(ctx, s.directory, s.stateLock)
	if err == nil {
		_ = store.Close()
		s.hold = true
		s.holdReason = agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT
		return
	}
	if errors.Is(err, journal.ErrRecoveryHold) {
		s.hold = true
		s.holdReason = agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT
	}
}

func cloneState(state *agentv1.ExecutorJournalState) *agentv1.ExecutorJournalState {
	return proto.CloneOf(state)
}

func newID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil || id == uuid.Nil {
		return "", errInternal
	}
	return id.String(), nil
}

func grantsMatch(stored, supplied string) bool {
	return len(stored) == len(supplied) && subtleCompare(stored, supplied)
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range len(a) {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func validGrant(grant string) bool {
	return len(grant) >= 32 && len(grant) <= 256 && !strings.ContainsRune(grant, 0)
}

func readBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	text := strings.TrimRight(string(data), "\n")
	id, err := canonicalUUID(text)
	if err != nil {
		return "", errors.New("invalid boot id")
	}
	return id.String(), nil
}

func noStore[T any](msg *T) *connect.Response[T] {
	res := connect.NewResponse(msg)
	res.Header().Set("Cache-Control", "no-store")
	return res
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return err
	}
	code := connect.CodeInternal
	reason := "internal"
	switch {
	case errors.Is(err, context.Canceled):
		code, reason = connect.CodeCanceled, "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		code, reason = connect.CodeDeadlineExceeded, "deadline_exceeded"
	case errors.Is(err, errClosed):
		code, reason = connect.CodeUnavailable, "executor_closed"
	case errors.Is(err, errServiceRejected):
		code, reason = connect.CodePermissionDenied, "service_execution_rejected"
	case errors.Is(err, errServiceExpired):
		code, reason = connect.CodeFailedPrecondition, "service_execution_expired"
	case errors.Is(err, journal.ErrServiceActionNotFound):
		code, reason = connect.CodeNotFound, "service_execution_not_found"
	case errors.Is(err, journal.ErrServiceActionCapacity):
		code, reason = connect.CodeResourceExhausted, "service_execution_capacity"
	case errors.Is(err, journal.ErrServiceActionBusy), errors.Is(err, journal.ErrServiceActionRejected), errors.Is(err, journal.ErrConflict):
		code, reason = connect.CodeFailedPrecondition, "service_execution_conflict"
	case errors.Is(err, serviceprovider.ErrUnsupported):
		code, reason = connect.CodeFailedPrecondition, "service_provider_unsupported"
	case errors.Is(err, serviceprovider.ErrConflict), errors.Is(err, serviceprovider.ErrNotConverged):
		code, reason = connect.CodeFailedPrecondition, "service_provider_precondition"
	case errors.Is(err, errRecoveryHold):
		code, reason = connect.CodeFailedPrecondition, "recovery_hold"
	case errors.Is(err, errUnprovisioned):
		code, reason = connect.CodeFailedPrecondition, "unprovisioned"
	case errors.Is(err, errPendingEnrollment):
		code, reason = connect.CodeFailedPrecondition, "pending_enrollment"
	case errors.Is(err, errAlreadyEnrolled):
		code, reason = connect.CodeFailedPrecondition, "already_enrolled"
	case errors.Is(err, errTrustReplacement):
		code, reason = connect.CodeFailedPrecondition, "trust_replacement_rejected"
	case errors.Is(err, errGrantMismatch), errors.Is(err, errInvalid), errors.Is(err, errBootstrapRejected), errors.Is(err, errCertificateRejected):
		code, reason = connect.CodeInvalidArgument, reasonOf(err)
	case errors.Is(err, errExecutionTrustRejected):
		code, reason = connect.CodePermissionDenied, "execution_trust_rejected"
	case errors.Is(err, errIdentityExpired), errors.Is(err, errRenewalNotDue), errors.Is(err, errRenewalPending), errors.Is(err, errSessionPending), errors.Is(err, errSessionRequired), errors.Is(err, errEpochRejected), errors.Is(err, errNotPending):
		code, reason = connect.CodeFailedPrecondition, reasonOf(err)
	case errors.Is(err, errSigningRejected):
		code, reason = connect.CodePermissionDenied, "signing_rejected"
	case errors.Is(err, errIdempotencyConflict):
		code, reason = connect.CodeAlreadyExists, "idempotency_conflict"
	}
	out := connect.NewError(code, errors.New(reason))
	out.Meta().Set("Lindm-Reason", reason)
	return out
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, errGrantMismatch):
		return "grant_mismatch"
	case errors.Is(err, errBootstrapRejected):
		return "bootstrap_rejected"
	case errors.Is(err, errCertificateRejected):
		return "certificate_rejected"
	case errors.Is(err, errExecutionTrustRejected):
		return "execution_trust_rejected"
	case errors.Is(err, errIdentityExpired):
		return "identity_expired"
	case errors.Is(err, errRenewalNotDue):
		return "renewal_not_due"
	case errors.Is(err, errRenewalPending):
		return "renewal_pending"
	case errors.Is(err, errSessionPending):
		return "session_pending"
	case errors.Is(err, errSessionRequired):
		return "session_required"
	case errors.Is(err, errEpochRejected):
		return "epoch_rejected"
	case errors.Is(err, errNotPending):
		return "not_pending"
	default:
		return "invalid_request"
	}
}

func (s *Service) scheduleRenewal(notBefore, notAfter time.Time) (time.Time, error) {
	earliest := notBefore.Add(10 * 24 * time.Hour)
	latest := notAfter.Add(-time.Hour)
	if !latest.After(notBefore) {
		latest = notBefore
	}
	if earliest.After(latest) {
		earliest = latest
	}
	window := latest.Sub(earliest)
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}
	jitter, err := s.jitter(window)
	if err != nil {
		return time.Time{}, err
	}
	return earliest.Add(jitter), nil
}

func (s *Service) jitter(max time.Duration) (time.Duration, error) {
	if max <= 0 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := io.ReadFull(s.entropy, buf[:]); err != nil {
		return 0, err
	}
	n := uint64(buf[0])<<56 | uint64(buf[1])<<48 | uint64(buf[2])<<40 | uint64(buf[3])<<32 | uint64(buf[4])<<24 | uint64(buf[5])<<16 | uint64(buf[6])<<8 | uint64(buf[7])
	return time.Duration(n % uint64(max)), nil
}

func mutationEpoch(b *bound) (uint64, bool) {
	if b == nil || b.renewal != nil || b.state.GetSessionEpoch() == 0 {
		return 0, false
	}
	return b.state.GetSessionEpoch(), true
}

func describe(b *bound, now time.Time, hold bool, reason agentv1.HoldReason) *agentv1.StatusResponse {
	out := &agentv1.StatusResponse{HoldReason: agentv1.HoldReason_HOLD_REASON_NONE}
	if hold || b == nil {
		if reason == agentv1.HoldReason_HOLD_REASON_UNSPECIFIED {
			reason = agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT
		}
		out.Lifecycle = agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD
		out.HoldReason = reason
		return out
	}
	out.InstallationId = b.state.GetInstallationId()
	out.DeploymentId = b.bootstrap.Root.GetDeploymentId()
	out.BootstrapVerifiedAt = timestamppb.New(b.admission)
	if b.cert == nil {
		out.Lifecycle = agentv1.Lifecycle_LIFECYCLE_PENDING_ENROLLMENT
		return out
	}
	out.Lifecycle = agentv1.Lifecycle_LIFECYCLE_ENROLLED
	out.DeviceId = b.state.GetDeviceId()
	out.EnrollmentGeneration = b.state.GetEnrollmentGeneration()
	out.CertificateNotAfter = timestamppb.New(b.cert.NotAfter)
	out.RenewAfter = b.state.GetRenewAfter()
	out.IdentityExpired = !certUsable(b.cert, now)
	out.TlsUsable = certUsable(b.cert, now)
	out.SessionPending = b.state.GetPendingSession() != nil
	out.RenewalPending = b.renewal != nil
	if b.renewal != nil {
		out.PendingIssuanceRequestId = b.renewal.id
	}
	if b.prior != nil {
		out.PriorRetainUntil = timestamppb.New(b.prior.retain)
	}
	if epoch, ok := mutationEpoch(b); ok {
		out.SessionEpochUsable = true
		out.CommittedSessionEpoch = epoch
		out.CommittedBootId = b.state.GetSessionBootId()
	}
	return out
}
