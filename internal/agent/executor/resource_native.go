// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/nativehelper"
)

func (s *Service) resourceNativeTransaction(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
	if request == nil || beforeEffect == nil {
		return nil, errResourceRejected
	}
	return nativehelper.LaunchResource(ctx, s.directory, request, func(ctx context.Context) (*agentv1.NativeEffectPermit, error) {
		if err := beforeEffect(ctx); err != nil {
			return nil, err
		}
		return s.nativeEffectPermit(ctx, request.GetActionId())
	})
}

func (s *Service) resourceNativeApply(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) error {
	_, err := s.resourceNativeTransaction(ctx, request, beforeEffect)
	return err
}

func (s *Service) observeNativeResource(ctx context.Context, desired *resourcev1.ResourceDesiredState, platform *resourcev1.PlatformProduct, backend *resourcev1.BackendSelection) (*agentv1.NativeHelperResult, error) {
	return nativehelper.ObserveResource(ctx, s.directory, &agentv1.NativeResourceObservationRequest{Desired: proto.CloneOf(desired), Platform: proto.CloneOf(platform), ExecutorIncarnation: s.incarnation, Backend: proto.CloneOf(backend)})
}

func (s *Service) authenticatedResourceEscrow(ctx context.Context, actionID string) (*agentv1.DeviceActionRecord, error) {
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	// The existing history loader authenticates preserved trust, intent, native
	// plan, start grant and escrow receipt at their accepted historical times.
	// Its target binding also requires the current enrollment generation.
	record, _, err := s.loadDeviceAction(ctx, loaded, actionID)
	if err != nil {
		return nil, err
	}
	return proto.CloneOf(record), nil
}

func rootEncryptionEvidence(result *agentv1.NativeHelperResult) (*actionprovider.RootEncryptionEvidence, error) {
	evidence := result.GetEncryption()
	if evidence == nil {
		return nil, errors.New("native_root_encryption_evidence_missing")
	}
	observed := &actionprovider.RootEncryptionEvidence{LUKSRoot: evidence.GetLuksRoot(), Target: proto.CloneOf(evidence.GetTarget()), NativeSHA256: append([]byte(nil), evidence.GetNativeSha256()...), MetadataSHA256: append([]byte(nil), evidence.GetMetadataSha256()...), TPMBound: evidence.GetTpmBound(), Reason: evidence.GetReason()}
	for _, recovery := range evidence.GetRecovery() {
		observed.Recovery = append(observed.Recovery, actionprovider.RootRecoveryEvidence{ActionID: recovery.GetActionId(), Keyslot: recovery.GetKeyslot(), KeySHA256: append([]byte(nil), recovery.GetKeySha256()...)})
	}
	return observed, nil
}
