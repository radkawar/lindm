//go:build linux

package executor

import (
	"context"
	"math"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/nativehelper"
)

func (s *Service) packageNativeStage(ctx context.Context, request *agentv1.NativePackageTransactionRequest) (bool, error) {
	return nativehelper.Stage(ctx, s.directory, request)
}

func (s *Service) packageNativeCancel(ctx context.Context, actionID string) error {
	return nativehelper.CancelStage(ctx, s.directory, actionID)
}

func (s *Service) packageNativeTransaction(ctx context.Context, request *agentv1.NativePackageTransactionRequest, beforeEffect func(context.Context) error) error {
	if beforeEffect == nil || request.GetOperation() != agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_APPLY {
		return errResourceRejected
	}
	return nativehelper.Launch(ctx, s.directory, request.GetActionId(), request, func(gateContext context.Context) (*agentv1.NativeEffectPermit, error) {
		if err := beforeEffect(gateContext); err != nil {
			return nil, err
		}
		return s.nativeEffectPermit(gateContext, request.GetActionId())
	})
}

// nativeEffectPermit clips helper authority to the same consumed journal record,
// suspend-aware challenge deadline and current grant. The transfer cannot widen
// the native start window. It is not a second signed execution protocol.
func (s *Service) nativeEffectPermit(ctx context.Context, actionID string) (*agentv1.NativeEffectPermit, error) {
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	record, _, err := s.loadResourceAction(ctx, loaded, actionID)
	if err != nil {
		return nil, err
	}
	if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
		return nil, errResourceRejected
	}
	if err := s.challengeDeadline(record.GetChallenge(), record.GetChallengeBoottimeNs()); err != nil {
		return nil, err
	}
	grant, err := resourceAction.authorizeStart(ctx, s, loaded, record, record.GetStartGrantEnvelope())
	if err != nil {
		return nil, err
	}
	now, err := s.boottime()
	if err != nil {
		return nil, err
	}
	remaining := grant.GetExpiresAt().AsTime().Sub(s.now())
	if remaining <= 0 || uint64(remaining) > math.MaxUint64-now {
		return nil, errResourceExpired
	}
	deadline := min(record.GetChallengeBoottimeNs(), now+uint64(remaining))
	return &agentv1.NativeEffectPermit{BootId: record.GetChallenge().GetBootId(), StartDeadlineBoottimeNs: deadline}, nil
}
