//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
)

// liveRootAction is protected by Service.mu. It is never marshaled into the
// journal. The current identity, consumed authority and proof remain pinned in
// executor memory until the independently owned forced-poweroff deadline.
type liveRootAction struct {
	identity *bound
	record   *agentv1.DeviceActionRecord
	status   *agentv1.DeviceActionStatus
	revision uint64
	deadline time.Time
}

// closeLiveRootJournal runs under the authority mutex after the durable effect
// consumption. Closing SQLite BEFORE any header mutation prevents checkpoint,
// completion, credential-retirement and shutdown writes onto the erased root.
// The nonnil closed store also prevents accidental bootstrap/reprovisioning.
func (s *Service) closeLiveRootJournal(ctx context.Context, loaded *bound, next *agentv1.DeviceActionRecord) error {
	record, revision, err := s.store.LoadDeviceAction(ctx, next.GetIntent().GetActionId())
	if err != nil || revision <= 0 || !proto.Equal(record, next) {
		return errors.Join(errInternal, err)
	}
	memory := &liveRootAction{identity: loaded, record: record, status: deviceActionStatus(record), revision: uint64(revision), deadline: s.now().Add(actionprovider.LiveRootPoweroffDelay)}
	memory.status.ReportOnly = true
	if err := s.store.Close(); err != nil {
		// No effect is allowed after a close failure. Still retain consumed
		// authority in memory; a duplicate start cannot reopen or replay it.
		s.liveRoot = memory
		return err
	}
	s.liveRoot = memory
	return nil
}

func (s *Service) liveRootStatus(actionID string) (*agentv1.DeviceActionStatus, error) {
	if s.liveRoot == nil || s.liveRoot.record.GetIntent().GetActionId() != actionID {
		return nil, errResourceRejected
	}
	return proto.CloneOf(s.liveRoot.status), nil
}

func (s *Service) finishLiveRoot(result *agentv1.DeviceActionVerification, operationErr error) {
	memory := s.liveRoot
	if result != nil && s.admit(result) != nil {
		result, operationErr = nil, errInternal
	}
	memory.status.Verification = result
	memory.status.CompletedAt = protoTimestamp(s.now())
	memory.status.VolatileResult = true
	memory.status.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	memory.status.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_OBSERVATION
	if operationErr == nil && liveRootComplete(memory.record.GetNativePlan(), result) {
		memory.status.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
		memory.status.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE
	}
	// A terminal memory revision must supersede the durable RUNNING revision,
	// but is never misrepresented as a committed disk revision.
	memory.revision++
}

func liveRootComplete(plan *agentv1.DeviceActionPlan, result *agentv1.DeviceActionVerification) bool {
	if !result.GetVerified() || len(plan.GetCryptoEraseTargets()) == 0 || len(plan.GetCryptoEraseTargets()) != len(result.GetCryptoEraseResults()) {
		return false
	}
	for index, expected := range plan.GetCryptoEraseTargets() {
		actual := result.GetCryptoEraseResults()[index]
		if !proto.Equal(expected.GetTarget(), actual.GetTarget()) || expected.GetLuksHeaderBytes() != actual.GetHeaderBytes() || !actual.GetNativeLuksErase() || !actual.GetRawZeroVerified() || !actual.GetMetadataAbsent() {
			return false
		}
	}
	return true
}

func (s *Service) attestLiveRoot(ctx context.Context, req *agentv1.AttestDeviceActionRequest) (*connect.Response[agentv1.AttestDeviceActionResponse], error) {
	status, err := s.liveRootStatus(req.GetActionId())
	if err != nil {
		return nil, mapError(err)
	}
	memory, now := s.liveRoot, s.now()
	loaded := memory.identity
	if !certUsable(loaded.cert, now) || !now.Before(memory.deadline) {
		return nil, mapError(errIdentityExpired)
	}
	expires := now.Add(30 * time.Second)
	if memory.deadline.Before(expires) {
		expires = memory.deadline
	}
	if loaded.cert.NotAfter.Before(expires) {
		expires = loaded.cert.NotAfter
	}
	attestation := &agentv1.DeviceActionAttestation{DeploymentId: loaded.bootstrap.Root.GetDeploymentId(), DeviceId: loaded.state.GetDeviceId(), EnrollmentGeneration: loaded.state.GetEnrollmentGeneration(), SessionEpoch: loaded.state.GetSessionEpoch(), ActionRevision: memory.revision, Nonce: bytes.Clone(req.GetNonce()), IssuedAt: protoTimestamp(now), ExpiresAt: protoTimestamp(expires), Status: status}
	envelope, err := s.authority.Sign(ctx, attestation, loaded.identityKey)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.AttestDeviceActionResponse{AttestationEnvelope: envelope, CertificatePem: bytes.Clone(loaded.state.GetCertificatePem())}), nil
}

// Only connection/TLS report paths can use the retained identity. All mutating
// operations keep using enrolled/loadBound, which rejects in report-only mode.
func (s *Service) reportIdentity(ctx context.Context) (*bound, error) {
	if s.liveRoot != nil {
		return s.liveRoot.identity, nil
	}
	return s.enrolled(ctx)
}
