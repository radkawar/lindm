//go:build linux

// Package transport runs the unprivileged observation process. It cannot enroll,
// reset protected identity or read device private keys.
package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/inventory"
	"lindm/internal/agent/localrpc"
	"lindm/internal/agent/spool"
)

const heartbeatInterval = time.Minute
const collectionInterval = 10 * time.Minute

// Run uses the fixed service account and sole-writer spool. Cancellation stops
// cleanly without deleting identity, pending uploads, or replaceable evidence.
func Run(ctx context.Context, document *config.Document) (resultErr error) {
	if document == nil || os.Geteuid() == 0 || uint32(os.Geteuid()) != document.NetworkUID {
		return errors.New("run requires the configured unprivileged network account")
	}
	executor, cleanup, err := localrpc.Dial(document.SocketPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanup()) }()
	r := &runner{document: document, executor: executor, status: &agentv1.TransportStatus{}, authorityGate: make(authorityGate, 1)}
	defer r.cache.Close()
	defer func() {
		if r.store != nil {
			resultErr = errors.Join(resultErr, r.store.Close())
		}
	}()
	if previous, err := ReadStatus(document); err == nil {
		r.status = previous
	} else if !errors.Is(err, os.ErrNotExist) {
		slog.Warn("previous transport status is unreadable", "error", err)
	}
	r.status.LastAttempt = agentv1.TransportOutcome_TRANSPORT_OUTCOME_STARTING
	if err := r.report(ctx); err != nil {
		return err
	}
	stopManagement := startExecutionTrustLoop(ctx, executor, r.authorityGate)
	defer stopManagement()
	for {
		if err := ctx.Err(); err != nil {
			return r.stopped()
		}
		err := r.cycle(ctx)
		if ctx.Err() != nil {
			return r.stopped()
		}
		r.status.LastAttempt = outcome(err)
		if err != nil {
			slog.Warn("device synchronization incomplete", "error", err)
		}
		if err := r.report(ctx); err != nil {
			return err
		}
		// Jitter affects scheduling only, never authority, sequence or expiry.
		delay := heartbeatDelay()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return r.stopped()
		case <-timer.C:
		}
	}
}

func heartbeatDelay() time.Duration {
	return heartbeatInterval - heartbeatInterval/10 + time.Duration(rand.Int64N(int64(heartbeatInterval/5)))
}

type runner struct {
	document       *config.Document
	executor       agentv1connect.ExecutorServiceClient
	cache          connectionCache
	authorityGate  authorityGate
	store          *spool.Store
	identity       spool.Identity
	status         *agentv1.TransportStatus
	nextCollection time.Time
	waiting        *inventoryv1.NativeObservation
}

func (r *runner) cycle(ctx context.Context) error {
	connection, connectionErr := rpc(ctx, r.executor.GetConnection, &agentv1.GetConnectionRequest{})
	if connectionErr == nil {
		if err := r.bind(ctx, connection); err != nil {
			return err
		}
	}
	var collectionErr error
	// Existing same-scope evidence can coalesce while the executor or server is
	// unavailable. A new process never guesses a binding from untrusted status.
	if r.store != nil && !time.Now().Before(r.nextCollection) {
		collectionErr = r.collect(ctx)
	}
	if connectionErr != nil {
		return errors.Join(connectionErr, collectionErr)
	}
	authority, err := synchronize(ctx, r.executor, &r.cache, r.authorityGate)
	if err != nil {
		return errors.Join(err, collectionErr)
	}
	if err := r.bind(ctx, authority.connection); err != nil {
		return errors.Join(err, collectionErr)
	}
	if err := recordContact(r.status, authority.state.GetServerTime()); err != nil {
		return errors.Join(err, collectionErr)
	}
	r.status.HostHighWater = max(r.status.GetHostHighWater(), authority.state.GetHostSequence())
	r.status.PackageHighWater = max(r.status.GetPackageHighWater(), authority.state.GetPackageSequence())
	if err := r.store.Synchronize(ctx, authority.state.GetHostSequence(), authority.state.GetPackageSequence()); err != nil {
		return errors.Join(err, collectionErr)
	}
	if r.waiting != nil {
		if err := r.queue(ctx, r.waiting); err != nil {
			return errors.Join(err, collectionErr)
		}
		r.waiting = nil
	}
	return errors.Join(flush(ctx, r.store, authority.authorized, r.status), collectionErr)
}

func (r *runner) bind(ctx context.Context, connection *agentv1.GetConnectionResponse) error {
	identity, err := connectionIdentity(connection)
	if err != nil {
		return err
	}
	if r.store != nil && r.identity == identity {
		return nil
	}
	if r.store != nil {
		if err := r.store.Close(); err != nil {
			return err
		}
		r.store = nil
	}
	store, err := spool.Open(ctx, r.document.SpoolDirectory, identity)
	if err != nil {
		return fmt.Errorf("open observation spool: %w", err)
	}
	r.store = store
	r.identity = identity
	r.waiting = nil
	r.nextCollection = time.Time{}
	if r.status.GetDeploymentId() != identity.Deployment.String() || r.status.GetDeviceId() != identity.Device.String() || r.status.GetEnrollmentGeneration() != identity.Generation.String() {
		r.status = &agentv1.TransportStatus{DeploymentId: proto.String(identity.Deployment.String()), DeviceId: proto.String(identity.Device.String()), EnrollmentGeneration: proto.String(identity.Generation.String())}
	}
	return nil
}

func (r *runner) collect(ctx context.Context) error {
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	observation, err := inventory.Collect(call)
	r.nextCollection = time.Now().Add(collectionInterval)
	if err != nil {
		return fmt.Errorf("collect native observation: %w", err)
	}
	r.status.LastCollectionFinishedAt = observation.GetPackages().GetFinishedAt()
	if err := r.queue(ctx, observation); err != nil {
		if errors.Is(err, spool.ErrNeedsSync) {
			r.waiting = observation
			return nil
		}
		return err
	}
	r.waiting = nil
	return nil
}

func (r *runner) queue(ctx context.Context, observation *inventoryv1.NativeObservation) error {
	err := r.store.Queue(ctx, observation)
	if !errors.Is(err, spool.ErrCapacity) {
		return err
	}
	// Capacity is a complete failed attempt, never a successful prefix. The
	// collector result is solely owned here; release its rows without copying.
	observation.Packages.Packages = nil
	observation.Packages.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_CAPACITY_EXCEEDED
	return r.store.Queue(ctx, observation)
}

func (r *runner) report(ctx context.Context) error {
	if r.store != nil {
		recovery, err := r.store.Recovery(ctx)
		if err != nil {
			return err
		}
		r.status.SpoolNeedsSync = recovery.NeedsSync
		r.status.SpoolRecoveryReason = string(recovery.Reason)
		r.status.LostUploadMayRemain = recovery.LostAdmittedUploadMayRemain
	}
	r.status.RecordedAt = timestamppb.Now()
	return writeStatus(ctx, r.document.SpoolDirectory, r.status)
}

func (r *runner) stopped() error {
	r.status.LastAttempt = agentv1.TransportOutcome_TRANSPORT_OUTCOME_STOPPED
	r.status.RecordedAt = timestamppb.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return writeStatus(ctx, r.document.SpoolDirectory, r.status)
}

func connectionIdentity(connection *agentv1.GetConnectionResponse) (spool.Identity, error) {
	var identity spool.Identity
	fields := []struct {
		value  string
		target *uuid.UUID
	}{{connection.GetDeploymentId(), &identity.Deployment}, {connection.GetDeviceId(), &identity.Device}, {connection.GetEnrollmentGeneration(), &identity.Generation}}
	for _, field := range fields {
		parsed, err := uuid.Parse(field.value)
		if err != nil || parsed == uuid.Nil || parsed.String() != field.value {
			return identity, errors.New("executor returned an invalid spool identity")
		}
		*field.target = parsed
	}
	return identity, nil
}

func outcome(err error) agentv1.TransportOutcome {
	if err == nil {
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_SYNCHRONIZED
	}
	if errors.Is(err, ErrIdentityExpired) {
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_IDENTITY_EXPIRED
	}
	if errors.Is(err, spool.ErrNeedsSync) || errors.Is(err, spool.ErrUnsafe) || errors.Is(err, spool.ErrUnrecognized) {
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_LOCAL_RECOVERY_REQUIRED
	}
	switch rpcReason(err) {
	case "unprovisioned", "pending_enrollment":
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_WAITING_FOR_ENROLLMENT
	case "recovery_hold", "device_revoked", "generation_mismatch", "session_fenced", "authority_rejected", "authority_receipt_capacity":
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_AUTHORITY_REJECTED
	case "identity_expired":
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_IDENTITY_EXPIRED
	case "open_upload", "rate_limited", "inventory_budget", "snapshot_capacity":
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_SERVER_ADMISSION_DEFERRED
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated, connect.CodePermissionDenied:
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_AUTHORITY_REJECTED
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded:
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_UNREACHABLE
	default:
		return agentv1.TransportOutcome_TRANSPORT_OUTCOME_LOCAL_FAILURE
	}
}
