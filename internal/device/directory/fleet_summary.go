// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"lindm/internal/device/inventory"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

// GetFleetSummary aggregates the complete fleet.read scope in a single read
// snapshot. Approval visibility belongs to identity and is independently fenced;
// it must never be inferred from the fleet permission or a sampled inbox page.
func (s *Service) GetFleetSummary(ctx context.Context, req *connect.Request[adminv1.GetFleetSummaryRequest]) (*connect.Response[adminv1.GetFleetSummaryResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_fleet_summary")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	unrestricted, scopes, err := core.DeviceScopeFilter(actor, identity.PermissionReadFleet)
	if err != nil {
		return nil, core.MapErr(err)
	}
	limit := int(req.Msg.GetRecentActionLimit())
	if limit == 0 {
		limit = 10
	}
	var response *adminv1.GetFleetSummaryResponse
	if cached := s.FleetPopulation.Load(); unrestricted && cached != nil && s.Clock().Sub(cached.ObservedAt.AsTime()) <= FleetSummaryMaxAge {
		response = proto.CloneOf(cached)
	} else {
		tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return nil, core.MapErr(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		response, err = s.readFleetPopulation(ctx, devicedb.New(tx), unrestricted, scopes)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, core.MapErr(err)
		}
	}
	response.RecentActions = response.RecentActions[:min(limit, len(response.RecentActions))]
	if s.Identity != nil && !actor.ServiceAccount {
		pending, ready, err := s.Identity.CountOpenApprovals(ctx, actor.ID)
		if err != nil && !errors.Is(err, identity.ErrAuthorizationDenied) {
			return nil, core.ApprovalError(err)
		}
		if err == nil {
			response.Approvals = &adminv1.FleetApprovalSummary{PendingApprovals: uint64(pending), ReadyToRun: uint64(ready)}
		}
	}
	return core.NoStore(response), nil
}

// fleetSummaryMaxAge bounds how old a background-computed unrestricted fleet
// population may be when served; ObservedAt always reports its snapshot time.
const FleetSummaryMaxAge = 30 * time.Second

// fleetSummaryRefresh is the background refresh period of that population.
const fleetSummaryRefresh = 10 * time.Second

// readFleetPopulation reads the device-population aggregates (lifecycle,
// contact, operating systems, resource compliance and advisory findings) in the
// caller's single read snapshot.
func (s *Service) readFleetPopulation(ctx context.Context, q *devicedb.Queries, unrestricted bool, scopes []byte) (*adminv1.GetFleetSummaryResponse, error) {
	counts, err := q.FleetSummaryCounts(ctx, devicedb.FleetSummaryCountsParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, core.MapErr(err)
	}
	operatingSystems, err := q.FleetSummaryOS(ctx, devicedb.FleetSummaryOSParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, core.MapErr(err)
	}
	compliance, err := q.FleetSummaryCompliance(ctx, devicedb.FleetSummaryComplianceParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, core.MapErr(err)
	}
	patch, err := q.FleetSummaryPatch(ctx, devicedb.FleetSummaryPatchParams{StaleAfterSeconds: inventory.PatchStaleAfterSeconds, ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.GetFleetSummaryResponse{
		ObservedAt: core.ProtoTime(counts.ObservedAt),
		Lifecycle: &adminv1.FleetLifecycleSummary{
			TotalDevices: uint64(counts.TotalDevices), PendingDevices: uint64(counts.PendingDevices),
			ActiveDevices: uint64(counts.ActiveDevices), RevokedDevices: uint64(counts.RevokedDevices),
			RecoveryHoldDevices: uint64(counts.RecoveryHoldDevices),
		},
		Contact: &adminv1.FleetContactSummary{
			RecentDevices: uint64(counts.RecentDevices), StaleDevices: uint64(counts.StaleDevices),
			UnknownDevices: uint64(counts.UnknownDevices), StaleAfterSeconds: 86400,
		},
		OperatingSystems: &adminv1.FleetOSSummary{
			Groups: make([]*adminv1.FleetOSCount, 0, len(operatingSystems)), OtherDevices: uint64(counts.TotalDevices),
		},
		ResourceCompliance: &adminv1.FleetResourceComplianceSummary{
			TotalResources: uint64(compliance.TotalResources), CompliantResources: uint64(compliance.CompliantResources),
			DriftRemediatedResources: uint64(compliance.DriftRemediatedResources), AttentionResources: uint64(compliance.AttentionResources),
			StaleResources: uint64(compliance.StaleResources), UnknownResources: uint64(compliance.UnknownResources),
			UnassignedDevices: uint64(counts.UnassignedDevices),
		},
		PatchCompliance: inventory.FleetPatchSummary(patch),
	}
	for _, row := range operatingSystems {
		response.OperatingSystems.Groups = append(response.OperatingSystems.Groups, &adminv1.FleetOSCount{
			OsId: row.OsID, OsVersion: row.OsVersion, Devices: uint64(row.Devices),
		})
		response.OperatingSystems.OtherDevices -= uint64(row.Devices)
	}
	if s.Advisories != nil {
		findings, err := q.FleetSummaryFindings(ctx, devicedb.FleetSummaryFindingsParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
		if err != nil {
			return nil, core.MapErr(err)
		}
		devices, err := q.FleetSummaryAdvisoryDevices(ctx, devicedb.FleetSummaryAdvisoryDevicesParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
		if err != nil {
			return nil, core.MapErr(err)
		}
		response.Findings = &adminv1.FleetFindingSummary{
			CriticalFindings: uint64(findings.CriticalFindings), HighFindings: uint64(findings.HighFindings),
			MediumFindings: uint64(findings.MediumFindings), LowFindings: uint64(findings.LowFindings), OtherFindings: uint64(findings.OtherFindings),
			EvaluatedDevices: uint64(devices.Evaluated), PartialDevices: uint64(devices.Partial),
			UnknownDevices: uint64(devices.Total - devices.Evaluated - devices.Partial),
		}
	}
	actions, err := q.FleetSummaryRecentActions(ctx, devicedb.FleetSummaryRecentActionsParams{ScopeUnrestricted: unrestricted, Scopes: scopes, RowLimit: maxRecentActions})
	if err != nil {
		return nil, core.MapErr(err)
	}
	response.RecentActions = make([]*adminv1.FleetRecentAction, 0, len(actions))
	for _, row := range actions {
		outcome, err := recentActionOutcome(row)
		if err != nil {
			return nil, err
		}
		response.RecentActions = append(response.RecentActions, &adminv1.FleetRecentAction{
			ActionId: row.ID.String(), DeviceId: row.DeviceID.String(), Capability: row.Capability,
			CreatedAt: core.ProtoTime(row.IssuedAt), ExpiresAt: core.ProtoTime(row.ExpiresAt),
			StartAuthorizedAt: core.ProtoTime(row.StartAuthorizedAt), ClosedAt: core.ProtoTime(row.ClosedAt),
			ClosedReason: row.ClosedReason, OutcomeUnknown: row.OutcomeUnknown,
			Kind: row.Kind, ResourceId: row.ResourceID, Unit: row.Unit, Outcome: outcome,
		})
	}
	return response, nil
}

// recentActionOutcome reports success or failure only from the device's own
// status document; server closures without a conclusive report are never
// presented as success.
func recentActionOutcome(row devicedb.FleetSummaryRecentActionsRow) (adminv1.FleetActionOutcome, error) {
	reported := len(row.StatusDocument) > 0
	if reported && row.Kind == "resource" {
		status := new(agentv1.ResourceExecutionStatus)
		if err := proto.Unmarshal(row.StatusDocument, status); err != nil {
			return 0, core.ErrInternalState
		}
		switch status.GetState() {
		case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_SUCCEEDED, nil
		case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_FAILED, nil
		case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN, nil
		case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_EXPIRED, nil
		case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_CANCELLED, nil
		}
	} else if reported {
		status := new(agentv1.DeviceActionStatus)
		if err := proto.Unmarshal(row.StatusDocument, status); err != nil {
			return 0, core.ErrInternalState
		}
		switch status.GetState() {
		case agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_SUCCEEDED, nil
		case agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_FAILED, nil
		case agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN, nil
		case agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED:
			return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_EXPIRED, nil
		}
	}
	closed := row.ClosedAt.Valid
	switch {
	case closed && strings.HasPrefix(row.ClosedReason, "expired") && !row.StartAuthorizedAt.Valid && !reported:
		return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_EXPIRED, nil
	case closed && (row.OutcomeUnknown || row.StartAuthorizedAt.Valid || reported):
		// Closed after the device may have acted, without a conclusive report.
		return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN, nil
	case closed:
		return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_CANCELLED, nil
	case row.Kind == "device" && row.OutcomeUnknown:
		return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN, nil
	case row.StartAuthorizedAt.Valid || reported:
		return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_RUNNING, nil
	default:
		return adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_WAITING, nil
	}
}

// maxRecentActions is the request validation bound; the population keeps that
// many so any requested limit is served from one snapshot.
const maxRecentActions = 20

// RunFleetSummary keeps this instance's unrestricted fleet population fresh so
// console reads do not rescan every device under load. Scoped readers and a
// stale or missing population always read live. It writes nothing.
func (s *Service) RunFleetSummary(ctx context.Context) error {
	ticker := time.NewTicker(fleetSummaryRefresh)
	defer ticker.Stop()
	for {
		if err := s.RefreshFleetPopulation(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("fleet summary refresh failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Service) RefreshFleetPopulation(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, core.RpcTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	population, err := s.readFleetPopulation(ctx, devicedb.New(tx), true, []byte("[]"))
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.FleetPopulation.Store(population)
	return nil
}
