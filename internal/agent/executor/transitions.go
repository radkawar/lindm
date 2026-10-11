//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"math"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/agent/journal"
	"lindm/internal/pki"
	"lindm/internal/secretseal"
	"lindm/internal/trust"
)

func (s *Service) PrepareBootstrap(ctx context.Context, req *connect.Request[agentv1.PrepareBootstrapRequest]) (*connect.Response[agentv1.PrepareBootstrapResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.prepareBootstrap(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) prepareBootstrap(ctx context.Context, req *agentv1.PrepareBootstrapRequest) (*agentv1.PrepareBootstrapResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if req.GetPendingGrant() != "" && !validGrant(req.GetPendingGrant()) {
		return nil, errInvalid
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.hold {
		return nil, errRecoveryHold
	}
	if s.store == nil {
		if req.GetResume() {
			return nil, errUnprovisioned
		}
		return s.createBootstrap(ctx, req)
	}
	loaded, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.cert != nil {
		return nil, errAlreadyEnrolled
	}
	if len(req.GetExecutionRootJson()) > 0 && (!bytes.Equal(req.GetExecutionRootJson(), loaded.state.GetExecutionRootJson()) || !bytes.Equal(req.GetBootstrapEnvelope(), loaded.state.GetBootstrapEnvelope())) {
		return nil, errTrustReplacement
	}
	if req.GetPendingGrant() != "" && !grantsMatch(loaded.state.GetPendingGrant(), req.GetPendingGrant()) {
		return nil, errGrantMismatch
	}
	if (!req.GetResume() && req.GetProvisioningToken() != loaded.state.GetProvisioningToken()) || (req.GetOfflineAuthorization() != nil && !proto.Equal(req.GetOfflineAuthorization(), loaded.state.GetOfflineAuthorization())) {
		return nil, errGrantMismatch
	}
	return s.enrollmentMaterial(ctx, loaded, true)
}

func (s *Service) createBootstrap(ctx context.Context, req *agentv1.PrepareBootstrapRequest) (*agentv1.PrepareBootstrapResponse, error) {
	now := s.now()
	bootstrap, err := s.authority.VerifyBootstrap(ctx, req.GetExecutionRootJson(), req.GetBootstrapEnvelope(), now)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errBootstrapRejected
	}
	if req.GetOfflineAuthorization() != nil {
		if _, err := s.verifyOfflineAuthorization(ctx, bootstrap, req.GetOfflineAuthorization(), now); err != nil {
			return nil, errBootstrapRejected
		}
	}
	key, csr, err := newSoftwareKey(s.entropy)
	if err != nil {
		return nil, err
	}
	encryption, err := secretseal.GenerateKey(s.entropy)
	if err != nil {
		return nil, err
	}
	installation, err := newID()
	if err != nil {
		return nil, err
	}
	transaction, err := newID()
	if err != nil {
		return nil, err
	}
	state := &agentv1.ExecutorJournalState{
		FormatVersion: 1, InstallationId: installation,
		ExecutionRootJson: bytes.Clone(req.GetExecutionRootJson()), BootstrapEnvelope: bytes.Clone(req.GetBootstrapEnvelope()),
		BootstrapVerifiedAt: protoTimestamp(now), EnrollmentTransactionId: transaction,
		IdentityPrivateKey: bytes.Clone(key), EnrollmentCsrPem: csr, PendingGrant: req.GetPendingGrant(),
		ProvisioningToken: req.GetProvisioningToken(), OfflineAuthorization: proto.CloneOf(req.GetOfflineAuthorization()),
		EncryptionPrivateKey: encryption,
	}
	store, err := journal.InitializeLocked(ctx, s.directory, s.stateLock, state)
	if err != nil {
		s.noteInitFailure(ctx)
		if s.hold {
			return nil, errRecoveryHold
		}
		return nil, err
	}
	s.store = store
	if err := s.initializeActionProvider(); err != nil {
		s.hold = true
		s.holdReason = agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT
		return nil, errRecoveryHold
	}
	loaded, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	return s.enrollmentMaterial(ctx, loaded, false)
}

func bootstrapResponse(b *bound, resumed bool) *agentv1.PrepareBootstrapResponse {
	return &agentv1.PrepareBootstrapResponse{
		InstallationId: b.state.GetInstallationId(), EnrollmentTransactionId: b.state.GetEnrollmentTransactionId(),
		CsrPem: bytes.Clone(b.state.GetEnrollmentCsrPem()), PendingGrant: b.state.GetPendingGrant(),
		DeploymentId: b.bootstrap.Root.GetDeploymentId(), EnrollmentOrigin: b.bootstrap.Bundle.GetEnrollmentOrigin(),
		DeviceOrigin: b.bootstrap.Bundle.GetDeviceOrigin(), TransportCaPem: bytes.Clone(b.bootstrap.Bundle.GetTransportCaPem()),
		Resumed: resumed,
	}
}

func (s *Service) InstallEnrollment(ctx context.Context, req *connect.Request[agentv1.InstallEnrollmentRequest]) (*connect.Response[agentv1.InstallEnrollmentResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.installEnrollment(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) installEnrollment(ctx context.Context, req *agentv1.InstallEnrollmentRequest) (*agentv1.InstallEnrollmentResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.state.GetOfflineAuthorization() != nil {
		return nil, errCertificateRejected
	}
	return s.installEnrollmentLocked(ctx, loaded, req)
}

func (s *Service) installEnrollmentLocked(ctx context.Context, loaded *bound, req *agentv1.InstallEnrollmentRequest) (*agentv1.InstallEnrollmentResponse, error) {
	if loaded.cert != nil {
		if sameInstalled(loaded, req) {
			return installResponse(loaded, true), nil
		}
		return nil, errAlreadyEnrolled
	}
	now := s.now()
	deployment, device, generation, err := enrollmentIDs(loaded.bootstrap.Root.GetDeploymentId(), req.GetDeviceId(), req.GetEnrollmentGeneration())
	if err != nil {
		return nil, errCertificateRejected
	}
	cert, err := pki.VerifyDeviceCertificatePEM(req.GetCertificatePem(), loaded.identityPublic, loaded.bootstrap.DeviceCA, deployment, device, generation, now)
	if err != nil || acceptableLifetime(cert, now) != nil {
		return nil, errCertificateRejected
	}
	renewAt, err := s.scheduleRenewal(cert.NotBefore, cert.NotAfter)
	if err != nil {
		return nil, err
	}
	next := cloneState(loaded.state)
	next.CertificatePem = bytes.Clone(req.GetCertificatePem())
	next.DeviceId = proto.String(device.String())
	next.EnrollmentGeneration = proto.String(generation.String())
	next.PendingGrant = ""
	next.RenewAfter = protoTimestamp(renewAt)
	if err := s.commit(ctx, loaded.revision, next); err != nil {
		return nil, err
	}
	loaded.state = next
	loaded.cert = cert
	return installResponse(loaded, false), nil
}

func sameInstalled(b *bound, req *agentv1.InstallEnrollmentRequest) bool {
	if b.state.GetDeviceId() != req.GetDeviceId() || b.state.GetEnrollmentGeneration() != req.GetEnrollmentGeneration() {
		return false
	}
	deployment, device, generation, err := enrollmentIDs(b.bootstrap.Root.GetDeploymentId(), b.state.GetDeviceId(), b.state.GetEnrollmentGeneration())
	if err != nil {
		return false
	}
	got, err := parsePinnedCert(req.GetCertificatePem(), b.identityPublic, b.bootstrap.DeviceCA, deployment, device, generation)
	return err == nil && bytes.Equal(got.Raw, b.cert.Raw)
}

func installResponse(b *bound, replayed bool) *agentv1.InstallEnrollmentResponse {
	return &agentv1.InstallEnrollmentResponse{
		DeviceId: b.state.GetDeviceId(), EnrollmentGeneration: b.state.GetEnrollmentGeneration(),
		CertificateSha256: append([]byte(nil), fingerprint(b.cert)...), NotAfter: protoTimestamp(b.cert.NotAfter),
		RenewAfter: b.state.GetRenewAfter(), Replayed: replayed,
	}
}

func (s *Service) PrepareSession(ctx context.Context, req *connect.Request[agentv1.PrepareSessionRequest]) (*connect.Response[agentv1.PrepareSessionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.prepareSession(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) prepareSession(ctx context.Context, req *agentv1.PrepareSessionRequest) (*agentv1.PrepareSessionResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.renewal != nil {
		return nil, errRenewalPending
	}
	if loaded.state.GetPendingSession() != nil {
		return pendingSessionResponse(loaded), nil
	}
	boot, err := s.bootID()
	if err != nil {
		return nil, err
	}
	if _, err := canonicalUUID(boot); err != nil {
		return nil, errInternal
	}
	if loaded.state.GetSessionEpoch() > 0 && loaded.state.GetSessionBootId() == boot && loaded.state.GetSessionReceipt().GetAgentRelease() == buildinfo.Current().Version && loaded.state.GetSessionReceipt().GetAgentProtocolVersion() == buildinfo.ProtocolVersion {
		return &agentv1.PrepareSessionResponse{Result: &agentv1.PrepareSessionResponse_Accepted{Accepted: &agentv1.AcceptedSession{SessionEpoch: loaded.state.GetSessionEpoch(), BootId: boot}}}, nil
	}
	if !certUsable(loaded.cert, s.now()) {
		return nil, errIdentityExpired
	}
	requestID, err := newID()
	if err != nil {
		return nil, err
	}
	incarnation, err := newID()
	if err != nil {
		return nil, err
	}
	claim := &agentv1.SessionAcquisition{
		DeploymentId: loaded.bootstrap.Root.GetDeploymentId(), DeviceId: loaded.state.GetDeviceId(),
		EnrollmentGeneration: loaded.state.GetEnrollmentGeneration(), RequestId: requestID,
		PredecessorEpoch: loaded.state.GetSessionEpoch(), Incarnation: incarnation, BootId: boot,
		AgentRelease: buildinfo.Current().Version, AgentProtocolVersion: buildinfo.ProtocolVersion,
		InstallationId: loaded.state.GetInstallationId(),
	}
	proof, err := s.authority.Sign(ctx, claim, loaded.identityKey)
	if err != nil {
		return nil, err
	}
	next := cloneState(loaded.state)
	next.PendingSession = claim
	next.PendingSessionProof = proof
	if err := s.commit(ctx, loaded.revision, next); err != nil {
		return nil, err
	}
	loaded.state = next
	return pendingSessionResponse(loaded), nil
}

func pendingSessionResponse(b *bound) *agentv1.PrepareSessionResponse {
	pending := b.state.GetPendingSession()
	return &agentv1.PrepareSessionResponse{Result: &agentv1.PrepareSessionResponse_Pending{Pending: &agentv1.PendingSessionClaim{
		AuthorityProof: bytes.Clone(b.state.GetPendingSessionProof()), RequestId: pending.GetRequestId(),
		PredecessorEpoch: pending.GetPredecessorEpoch(), Incarnation: pending.GetIncarnation(), BootId: pending.GetBootId(),
		DeploymentId: pending.GetDeploymentId(), DeviceId: pending.GetDeviceId(), EnrollmentGeneration: pending.GetEnrollmentGeneration(),
	}}}
}

func (s *Service) CommitSession(ctx context.Context, req *connect.Request[agentv1.CommitSessionRequest]) (*connect.Response[agentv1.CommitSessionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.commitSession(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) commitSession(ctx context.Context, req *agentv1.CommitSessionRequest) (*agentv1.CommitSessionResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.renewal != nil {
		return nil, errRenewalPending
	}
	if pending := loaded.state.GetPendingSession(); pending != nil {
		if pending.GetRequestId() != req.GetRequestId() || pending.GetPredecessorEpoch() >= uint64(math.MaxInt64) || req.GetServerEpoch() != pending.GetPredecessorEpoch()+1 {
			return nil, errEpochRejected
		}
		next := cloneState(loaded.state)
		next.SessionEpoch = req.GetServerEpoch()
		next.SessionBootId = proto.String(pending.GetBootId())
		next.PendingSession = nil
		next.PendingSessionProof = nil
		next.SessionReceipt = &agentv1.SessionCommitReceipt{RequestId: req.GetRequestId(), SessionEpoch: req.GetServerEpoch(), AgentRelease: pending.GetAgentRelease(), AgentProtocolVersion: pending.GetAgentProtocolVersion()}
		if err := s.commit(ctx, loaded.revision, next); err != nil {
			return nil, err
		}
		return &agentv1.CommitSessionResponse{SessionEpoch: req.GetServerEpoch(), BootId: pending.GetBootId()}, nil
	}
	receipt := loaded.state.GetSessionReceipt()
	if receipt != nil && receipt.GetRequestId() == req.GetRequestId() && receipt.GetSessionEpoch() == req.GetServerEpoch() && receipt.GetSessionEpoch() == loaded.state.GetSessionEpoch() {
		return &agentv1.CommitSessionResponse{SessionEpoch: loaded.state.GetSessionEpoch(), BootId: loaded.state.GetSessionBootId(), Replayed: true}, nil
	}
	return nil, errEpochRejected
}

func (s *Service) PrepareRenewal(ctx context.Context, req *connect.Request[agentv1.PrepareRenewalRequest]) (*connect.Response[agentv1.PrepareRenewalResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.prepareRenewal(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) prepareRenewal(ctx context.Context, req *agentv1.PrepareRenewalRequest) (*agentv1.PrepareRenewalResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.state.GetPendingSession() != nil {
		return nil, errSessionPending
	}
	if loaded.renewal != nil {
		return renewalResponse(loaded, true), nil
	}
	if loaded.state.GetSessionEpoch() == 0 {
		return nil, errSessionRequired
	}
	now := s.now()
	if !certUsable(loaded.cert, now) {
		return nil, errIdentityExpired
	}
	if loaded.state.GetRenewAfter() != nil && now.Before(loaded.state.GetRenewAfter().AsTime()) {
		return nil, errRenewalNotDue
	}
	key, csr, err := newSoftwareKey(s.entropy)
	if err != nil {
		return nil, err
	}
	encryption, err := secretseal.GenerateKey(s.entropy)
	if err != nil {
		return nil, err
	}
	issuance, err := newID()
	if err != nil {
		return nil, err
	}
	intent := &agentv1.RenewalIntent{
		DeploymentId: loaded.bootstrap.Root.GetDeploymentId(), DeviceId: loaded.state.GetDeviceId(),
		EnrollmentGeneration: loaded.state.GetEnrollmentGeneration(), IssuanceRequestId: issuance,
		PresentedCertificateSha256: fingerprint(loaded.cert), CsrSha256: sha256Sum(csr), SessionEpoch: loaded.state.GetSessionEpoch(),
	}
	retrieval := &agentv1.IssuanceRetrieval{
		DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), IssuanceRequestId: issuance,
	}
	authorityProof, err := s.authority.Sign(ctx, intent, loaded.identityKey)
	if err != nil {
		return nil, err
	}
	retrievalProof, err := s.authority.Sign(ctx, retrieval, key)
	if err != nil {
		return nil, err
	}
	next := cloneState(loaded.state)
	next.PendingRenewal = &agentv1.PendingIdentityRenewal{
		IssuanceRequestId: issuance, PrivateKey: bytes.Clone(key), CsrPem: csr,
		AuthorityProof: authorityProof, RetrievalProof: retrievalProof, SessionEpoch: loaded.state.GetSessionEpoch(),
		EncryptionPrivateKey: encryption,
	}
	if err := s.commit(ctx, loaded.revision, next); err != nil {
		return nil, err
	}
	loaded.state = next
	loaded.renewal = &boundRenewal{
		id: issuance, key: key, public: ed25519.PublicKey(bytes.Clone(key[ed25519.SeedSize:])),
		csr: csr, authority: authorityProof, retrieval: retrievalProof, epoch: loaded.state.GetSessionEpoch(),
	}
	return renewalResponse(loaded, false), nil
}

func renewalResponse(b *bound, resumed bool) *agentv1.PrepareRenewalResponse {
	id, err := trust.KeyID(b.renewal.public)
	if err != nil {
		id = ""
	}
	return &agentv1.PrepareRenewalResponse{
		IssuanceRequestId: b.renewal.id, CsrPem: bytes.Clone(b.renewal.csr), AuthorityProof: bytes.Clone(b.renewal.authority),
		RetrievalProof: bytes.Clone(b.renewal.retrieval), PresentedCertificateSha256: append([]byte(nil), fingerprint(b.cert)...),
		FencedSessionEpoch: b.renewal.epoch, NextKeyId: id, Resumed: resumed,
	}
}

func (s *Service) CommitRenewal(ctx context.Context, req *connect.Request[agentv1.CommitRenewalRequest]) (*connect.Response[agentv1.CommitRenewalResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.commitRenewal(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) commitRenewal(ctx context.Context, req *agentv1.CommitRenewalRequest) (*agentv1.CommitRenewalResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.renewal != nil {
		if req.GetIssuanceRequestId() != loaded.renewal.id {
			if loaded.state.GetRenewalReceipt().GetIssuanceRequestId() == req.GetIssuanceRequestId() {
				return nil, errIdempotencyConflict
			}
			return nil, errNotPending
		}
		return s.installRenewal(ctx, loaded, req.GetCertificatePem())
	}
	receipt := loaded.state.GetRenewalReceipt()
	if receipt == nil || receipt.GetIssuanceRequestId() != req.GetIssuanceRequestId() {
		return nil, errNotPending
	}
	got, err := parsePinnedCert(req.GetCertificatePem(), loaded.identityPublic, loaded.bootstrap.DeviceCA, idOrNil(loaded.bootstrap.Root.GetDeploymentId()), idOrNil(loaded.state.GetDeviceId()), idOrNil(loaded.state.GetEnrollmentGeneration()))
	if err != nil || !bytes.Equal(fingerprint(got), receipt.GetCertificateSha256()) || !bytes.Equal(got.Raw, loaded.cert.Raw) {
		return nil, errIdempotencyConflict
	}
	return renewalCommitResponse(loaded, req.GetIssuanceRequestId(), true), nil
}

func (s *Service) installRenewal(ctx context.Context, loaded *bound, pemBytes []byte) (*agentv1.CommitRenewalResponse, error) {
	now := s.now()
	cert, err := pki.VerifyDeviceCertificatePEM(pemBytes, loaded.renewal.public, loaded.bootstrap.DeviceCA, idOrNil(loaded.bootstrap.Root.GetDeploymentId()), idOrNil(loaded.state.GetDeviceId()), idOrNil(loaded.state.GetEnrollmentGeneration()), now)
	if err != nil || acceptableLifetime(cert, now) != nil {
		return nil, errCertificateRejected
	}
	renewAt, err := s.scheduleRenewal(cert.NotBefore, cert.NotAfter)
	if err != nil {
		return nil, err
	}
	retain := now.Add(15 * time.Minute)
	if loaded.cert.NotAfter.Before(retain) {
		retain = loaded.cert.NotAfter
	}
	issuance := loaded.renewal.id
	next := cloneState(loaded.state)
	next.PriorCredential = nil
	if now.Before(retain) {
		// The prior recipient scalar shares the prior identity's retention so
		// deliveries sealed before the new key registers still open.
		next.PriorCredential = &agentv1.PriorIdentityCredential{
			PrivateKey: bytes.Clone(loaded.identityKey), CertificatePem: bytes.Clone(loaded.state.GetCertificatePem()), RetainUntil: protoTimestamp(retain),
			EncryptionPrivateKey: bytes.Clone(loaded.state.GetEncryptionPrivateKey()),
		}
	}
	next.IdentityPrivateKey = bytes.Clone(loaded.renewal.key)
	next.EnrollmentCsrPem = bytes.Clone(loaded.renewal.csr)
	next.CertificatePem = bytes.Clone(pemBytes)
	// A renewal staged before secret delivery has no scalar; PrepareEncryptionKey
	// then generates one. Either way the new certificate must register anew.
	next.EncryptionPrivateKey = bytes.Clone(loaded.state.GetPendingRenewal().GetEncryptionPrivateKey())
	next.EncryptionKeyAcknowledgedSha256 = nil
	next.PendingRenewal = nil
	next.RenewAfter = protoTimestamp(renewAt)
	next.RenewalReceipt = &agentv1.RenewalCommitReceipt{IssuanceRequestId: issuance, CertificateSha256: fingerprint(cert)}
	if err := s.commit(ctx, loaded.revision, next); err != nil {
		return nil, err
	}
	loaded.state = next
	loaded.cert = cert
	loaded.prior = nil
	return renewalCommitResponse(loaded, issuance, false), nil
}

func renewalCommitResponse(b *bound, id string, replayed bool) *agentv1.CommitRenewalResponse {
	return &agentv1.CommitRenewalResponse{
		IssuanceRequestId: id, CertificateSha256: append([]byte(nil), fingerprint(b.cert)...),
		NotAfter: protoTimestamp(b.cert.NotAfter), RenewAfter: b.state.GetRenewAfter(), Replayed: replayed,
		PriorRetainUntil: b.state.GetPriorCredential().GetRetainUntil(),
	}
}

func (s *Service) enrolled(ctx context.Context) (*bound, error) {
	loaded, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if loaded.cert == nil {
		return nil, errPendingEnrollment
	}
	return loaded, nil
}

func enrollmentIDs(deployment, device, generation string) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	dep, err := canonicalUUID(deployment)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	dev, err := canonicalUUID(device)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	gen, err := canonicalUUID(generation)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	return dep, dev, gen, nil
}

func idOrNil(text string) uuid.UUID {
	id, err := canonicalUUID(text)
	if err != nil {
		return uuid.Nil
	}
	return id
}

func sha256Sum(in []byte) []byte {
	sum := sha256.Sum256(in)
	return sum[:]
}

func protoTimestamp(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}
