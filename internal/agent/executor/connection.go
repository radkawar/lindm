//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/statefs"
	"lindm/internal/trust"
)

func (s *Service) GetConnection(ctx context.Context, req *connect.Request[agentv1.GetConnectionRequest]) (*connect.Response[agentv1.GetConnectionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.getConnection(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) getConnection(ctx context.Context, req *agentv1.GetConnectionRequest) (*agentv1.GetConnectionResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.reportIdentity(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := &agentv1.GetConnectionResponse{
		DeploymentId: loaded.bootstrap.Root.GetDeploymentId(), DeviceId: loaded.state.GetDeviceId(),
		EnrollmentGeneration: loaded.state.GetEnrollmentGeneration(), EnrollmentOrigin: loaded.bootstrap.Bundle.GetEnrollmentOrigin(),
		DeviceOrigin: loaded.bootstrap.Bundle.GetDeviceOrigin(), TransportCaPem: bytes.Clone(loaded.bootstrap.Bundle.GetTransportCaPem()),
		CredentialKind:      agentv1.TLSCredentialKind_TLS_CREDENTIAL_KIND_ED25519,
		CertificateNotAfter: protoTimestamp(loaded.cert.NotAfter), RenewAfter: loaded.state.GetRenewAfter(),
		IdentityExpired: !certUsable(loaded.cert, now), RenewalPending: loaded.renewal != nil,
	}
	out.DeviceActionReportOnly = s.liveRoot != nil
	if boot, err := s.bootID(); err == nil {
		if _, idErr := canonicalUUID(boot); idErr == nil {
			out.ObservedBootId = boot
		}
	}
	if epoch, ok := mutationEpoch(loaded); ok {
		out.SessionEpoch = epoch
		out.SessionEpochUsable = true
	}
	if certUsable(loaded.cert, now) {
		keyID, err := trust.KeyID(loaded.identityPublic)
		if err != nil {
			return nil, errInternal
		}
		out.CertificatePem = bytes.Clone(loaded.state.GetCertificatePem())
		out.CertificateSha256 = append([]byte(nil), fingerprint(loaded.cert)...)
		out.KeyId = keyID
	}
	if loaded.prior != nil && now.Before(loaded.prior.retain) && certUsable(loaded.prior.cert, now) {
		keyID, err := trust.KeyID(loaded.prior.public)
		if err != nil {
			return nil, errInternal
		}
		out.Prior = &agentv1.PriorTLSCredential{
			CertificatePem: bytes.Clone(loaded.prior.pem), CertificateSha256: append([]byte(nil), loaded.prior.fingerprint[:]...),
			KeyId: keyID, RetainUntil: protoTimestamp(loaded.prior.retain),
		}
	}
	if loaded.renewal != nil {
		keyID, err := trust.KeyID(loaded.renewal.public)
		if err != nil {
			return nil, errInternal
		}
		out.Retrieval = &agentv1.RetrievalPublicData{IssuanceRequestId: loaded.renewal.id, RetrievalProof: bytes.Clone(loaded.renewal.retrieval), NextKeyId: keyID}
	}
	return out, nil
}

func (s *Service) SignTLSClientMessage(ctx context.Context, req *connect.Request[agentv1.SignTLSClientMessageRequest]) (*connect.Response[agentv1.SignTLSClientMessageResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.signTLS(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) signTLS(ctx context.Context, req *agentv1.SignTLSClientMessageRequest) (*agentv1.SignTLSClientMessageResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.reportIdentity(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var key ed25519.PrivateKey
	switch {
	case certUsable(loaded.cert, now) && bytes.Equal(req.GetCertificateSha256(), fingerprint(loaded.cert)):
		key = loaded.identityKey
	case loaded.prior != nil && now.Before(loaded.prior.retain) && certUsable(loaded.prior.cert, now) && bytes.Equal(req.GetCertificateSha256(), loaded.prior.fingerprint[:]):
		key = loaded.prior.key
	default:
		return nil, errSigningRejected
	}
	signature, err := trust.SignTLSClientMessage(key, req.GetMessage())
	if err != nil {
		return nil, errSigningRejected
	}
	return &agentv1.SignTLSClientMessageResponse{Signature: signature}, nil
}

func (s *Service) Status(ctx context.Context, req *connect.Request[agentv1.StatusRequest]) (*connect.Response[agentv1.StatusResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.status(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) status(ctx context.Context, req *agentv1.StatusRequest) (*agentv1.StatusResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.hold {
		return describe(nil, s.now(), true, s.holdReason), nil
	}
	if s.store == nil {
		return &agentv1.StatusResponse{Lifecycle: agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED, HoldReason: agentv1.HoldReason_HOLD_REASON_NONE}, nil
	}
	loaded, err := s.load(ctx)
	if err != nil {
		if errors.Is(err, errRecoveryHold) {
			return describe(nil, s.now(), true, s.holdReason), nil
		}
		return nil, err
	}
	return describe(loaded, s.now(), false, agentv1.HoldReason_HOLD_REASON_NONE), nil
}

// Inspect reads durable status when this process does not own the listener.
// ErrBusy means the running executor must be queried over its socket.
func Inspect(ctx context.Context, directory string) (*agentv1.StatusResponse, error) {
	store, err := journal.Open(ctx, directory)
	if err != nil {
		switch {
		case errors.Is(err, journal.ErrUnprovisioned):
			return &agentv1.StatusResponse{Lifecycle: agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED, HoldReason: agentv1.HoldReason_HOLD_REASON_NONE}, nil
		case errors.Is(err, journal.ErrAlreadyOpen):
			return nil, ErrBusy
		case errors.Is(err, journal.ErrRecoveryHold), errors.Is(err, statefs.ErrUnsafe):
			return describe(nil, time.Now(), true, agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT), nil
		default:
			return nil, err
		}
	}
	defer func() { _ = store.Close() }()
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	state, _, err := store.Load(ctx)
	if err != nil {
		return describe(nil, time.Now(), true, agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT), nil
	}
	loaded, err := bind(ctx, authority, state, time.Now().UTC())
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return describe(nil, time.Now(), true, agentv1.HoldReason_HOLD_REASON_IDENTITY_BINDING), nil
	}
	if err := bindExecutionTrust(ctx, authority, store, loaded); err != nil {
		if errors.Is(err, errRecoveryHold) {
			return describe(nil, time.Now(), true, agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT), nil
		}
		return nil, err
	}
	return describe(loaded, time.Now().UTC(), false, agentv1.HoldReason_HOLD_REASON_NONE), nil
}
