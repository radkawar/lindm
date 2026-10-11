package loadlab

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// proposeAdvisoryAcceptance leaves an affected finding pending independent human
// review so console acceptance covers both proposed and accepted risk.
func (s *demoSeed) proposeAdvisoryAcceptance(ctx context.Context, d *simulatedDevice) error {
	for token := ""; ; {
		response, err := s.owner.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: d.id, PageSize: 200, PageToken: token}))
		if err != nil {
			return fmt.Errorf("list demo advisory proposal: %w", err)
		}
		for _, finding := range response.Msg.GetFindings() {
			if finding.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
				continue
			}
			request := &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: d.id, FindingId: finding.GetId(), ExpiresAt: timestamppb.New(time.Now().Add(7 * 24 * time.Hour)), Reason: "Review the isolated management-network exposure before the scheduled patch window"}
			if _, err := s.owner.Admin.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}})); err != nil {
				return fmt.Errorf("propose demo advisory acceptance: %w", err)
			}
			// Explicit unavailable-evidence fixture: this UUID has no finding.
			// No exception is accepted; review must offer rejection, not approval.
			missing := &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: d.id, FindingId: uuid.NewString(), ExpiresAt: request.GetExpiresAt(), Reason: "Review stopped because finding evidence is unavailable"}
			if _, err := s.owner.Admin.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: missing}})); err != nil {
				return fmt.Errorf("propose missing-finding review fixture: %w", err)
			}
			return nil
		}
		token = response.Msg.GetNextPageToken()
		if token == "" {
			return nil
		}
	}
}
