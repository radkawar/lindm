// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// proposeAdvisoryAcceptance waits for the server's own evaluation of d to report
// an AFFECTED finding, then leaves its acceptance pending independent human
// review beside a proposal whose finding evidence is unavailable, so console
// review covers proposed as well as accepted risk. Only a complete feed's
// evaluation reports AFFECTED; partial coverage makes every finding UNKNOWN.
// A device that never reports one fails the seed rather than omitting both
// review fixtures.
func (s *demoSeed) proposeAdvisoryAcceptance(ctx context.Context, d *simulatedDevice) error {
	ctx, cancel := context.WithTimeout(ctx, demoEvaluationWait)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		finding, freshness, err := s.affectedFinding(ctx, d)
		if finding != nil {
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
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("wait for an AFFECTED demo advisory finding on %s (last freshness %v %q): %w", d.demo.hostname, freshness.GetState(), freshness.GetReason(), ctx.Err()), err)
		case <-ticker.C:
		}
	}
}

// affectedFinding returns d's first AFFECTED finding, or nil with the
// evaluation's freshness when the listing holds none.
func (s *demoSeed) affectedFinding(ctx context.Context, d *simulatedDevice) (*adminv1.AdvisoryFinding, *adminv1.AdvisoryFreshness, error) {
	var freshness *adminv1.AdvisoryFreshness
	for token := ""; ; {
		response, err := s.owner.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: d.id, PageSize: 200, PageToken: token}))
		if err != nil {
			return nil, freshness, fmt.Errorf("list demo advisory proposal findings: %w", err)
		}
		freshness = response.Msg.GetFreshness()
		for _, finding := range response.Msg.GetFindings() {
			if finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
				return finding, freshness, nil
			}
		}
		token = response.Msg.GetNextPageToken()
		if token == "" {
			return nil, freshness, nil
		}
	}
}
