// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// Periodic checks keep the original assignment: only the normal device
// acquisition path can schedule these actions, with the production minimum timer.
func exerciseDispatchRechecks(ctx context.Context, vm *guestVM, control *vmControlPlane, result *VMDispatchResult, head string, sequence uint64) (uint64, error) {
	state, err := control.dispatchState(ctx, result.DeviceID)
	if err != nil {
		return sequence, err
	}
	if state.GetAssignment().GetAssignmentId() != head || len(state.GetResources()) != 1 || state.GetResources()[0].GetLatestAction().GetResourceSequence() != sequence {
		return sequence, errors.New("periodic dispatch baseline changed assignment, resource or action")
	}
	previous := state.GetResources()[0]
	if previous.GetLastVerifiedAt() == nil || previous.GetObservedAt() == nil {
		return sequence, errors.New("converged dispatch baseline lacks verification timestamps")
	}
	for _, drift := range []bool{false, true} {
		resource, err := exerciseDispatchRecheck(ctx, vm, control, result, state.GetAssignment(), previous, drift)
		if err != nil {
			return sequence, err
		}
		previous = resource
		sequence = resource.GetLatestAction().GetResourceSequence()
	}
	return sequence, nil
}

func exerciseDispatchRecheck(ctx context.Context, vm *guestVM, control *vmControlPlane, result *VMDispatchResult, assignment *adminv1.ResourceAssignment, previous *adminv1.ResourceState, drift bool) (*adminv1.ResourceState, error) {
	scenario := VMDispatchScenario{Name: "1a periodic compliant recheck without start grant", StartedAt: time.Now().UTC(), Assignment: assignment, Coverage: "native periodic automatic dispatch"}
	beforeActive, beforeEnablement := "active", "enabled"
	compliance := adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT
	witness := "started\n"
	if drift {
		scenario.Name = "1b periodic drift detection and remediation"
		beforeActive, beforeEnablement = "inactive", "disabled"
		compliance = adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_DRIFT_REMEDIATED
		witness += "started\n"
	}
	defer func() {
		scenario.FinishedAt = time.Now().UTC()
		result.Scenarios = append(result.Scenarios, scenario)
	}()
	// Five minutes until due plus transport, native execution and evidence
	// ingestion allowance. Never shorten the production timer for this lab.
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	if drift {
		if err := lifecycleCommand(ctx, vm, "introduce out-of-band managed service drift", "systemctl disable --now "+dispatchUnit); err != nil {
			return nil, err
		}
	}
	native, err := vmServiceNativeProperties(ctx, vm, dispatchUnit)
	if err != nil {
		return nil, err
	}
	scenario.NativeBeforeActive, scenario.NativeBeforeEnablement = native["ActiveState"], native["UnitFileState"]
	if scenario.NativeBeforeActive != beforeActive || scenario.NativeBeforeEnablement != beforeEnablement {
		return nil, fmt.Errorf("%s: independent native baseline differs: got=%v want=%s/%s", scenario.Name, native, beforeActive, beforeEnablement)
	}
	for {
		state, err := control.dispatchState(ctx, result.DeviceID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", scenario.Name, err)
		}
		if !proto.Equal(state.GetAssignment(), assignment) || len(state.GetResources()) != 1 || state.GetResources()[0].GetResourceId() != previous.GetResourceId() {
			return nil, errors.New("periodic dispatch changed the original assignment or resource")
		}
		resource := state.GetResources()[0]
		action := resource.GetLatestAction()
		scenario.Resource, scenario.Action = resource, action
		if resource.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_ATTENTION || resource.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED {
			return nil, fmt.Errorf("%s cannot converge: %s", scenario.Name, state)
		}
		if action.GetResourceSequence() > previous.GetLatestAction().GetResourceSequence() && resource.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED {
			if action.GetActionId() == previous.GetLatestAction().GetActionId() || action.GetAttestedAt() == nil || action.GetReceivedAt() == nil || action.GetActionRevision() == 0 || action.GetClosedAt() == nil || action.GetClosedReason() != "result" {
				return nil, errors.New("periodic dispatch lacks fresh action and verified closed history")
			}
			if (action.GetStartAuthorizedAt() != nil) != drift {
				return nil, fmt.Errorf("%s: unexpected start authorization", scenario.Name)
			}
			if err := vmServiceSucceeded(action.GetStatus(), drift); err != nil {
				return nil, fmt.Errorf("%s: %w", scenario.Name, err)
			}
			before := action.GetStatus().GetBefore().GetSystemdService()
			if before.GetActiveState() != scenario.NativeBeforeActive || before.GetUnitFileState() != scenario.NativeBeforeEnablement {
				return nil, fmt.Errorf("%s: signed observation did not detect the independent native baseline", scenario.Name)
			}
			if resource.GetCompliance() != compliance || resource.GetLastVerifiedAt() == nil || resource.GetObservedAt() == nil || !resource.GetLastVerifiedAt().AsTime().After(previous.GetLastVerifiedAt().AsTime()) || !resource.GetObservedAt().AsTime().After(previous.GetObservedAt().AsTime()) {
				return nil, fmt.Errorf("%s: expected fresh %s evidence: %s", scenario.Name, compliance, resource)
			}
			if err := vmServiceNativeUnit(ctx, vm, dispatchUnit, "active", "enabled"); err != nil {
				return nil, err
			}
			observed, err := dispatchWitnessValue(ctx, vm)
			if err != nil {
				return nil, err
			}
			scenario.NativeActive, scenario.NativeEnablement, scenario.StartWitness = "active", "enabled", observed
			if observed != witness {
				return nil, fmt.Errorf("%s: unexpected native start witness %q", scenario.Name, observed)
			}
			return resource, nil
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return nil, fmt.Errorf("%s: %w; last=%s", scenario.Name, err, state)
		}
	}
}
