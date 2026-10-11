package device

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

// GetFleetSummary aggregates the complete fleet.read scope in a single read
// snapshot. Approval visibility belongs to identity and is independently fenced;
// it must never be inferred from the fleet permission or a sampled inbox page.
func (s *Service) GetFleetSummary(ctx context.Context, req *connect.Request[adminv1.GetFleetSummaryRequest]) (*connect.Response[adminv1.GetFleetSummaryResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_fleet_summary")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	unrestricted, scopes, err := deviceScopeFilter(actor, identity.PermissionReadFleet)
	if err != nil {
		return nil, mapErr(err)
	}
	var response *adminv1.GetFleetSummaryResponse
	if cached := s.fleetPopulation.Load(); unrestricted && cached != nil && s.clock().Sub(cached.ObservedAt.AsTime()) <= fleetSummaryMaxAge {
		response = proto.CloneOf(cached)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	if response == nil {
		response, err = s.readFleetPopulation(ctx, q, unrestricted, scopes)
		if err != nil {
			return nil, err
		}
	}
	limit := int32(req.Msg.GetRecentActionLimit())
	if limit == 0 {
		limit = 10
	}
	actions, err := q.FleetSummaryRecentActions(ctx, devicedb.FleetSummaryRecentActionsParams{ScopeUnrestricted: unrestricted, Scopes: scopes, RowLimit: limit})
	if err != nil {
		return nil, mapErr(err)
	}
	response.RecentActions = make([]*adminv1.FleetRecentAction, 0, len(actions))
	for _, row := range actions {
		response.RecentActions = append(response.RecentActions, &adminv1.FleetRecentAction{
			ActionId: row.ID.String(), DeviceId: row.DeviceID.String(), Capability: row.Capability,
			CreatedAt: protoTime(row.IssuedAt), ExpiresAt: protoTime(row.ExpiresAt),
			StartAuthorizedAt: protoTime(row.StartAuthorizedAt), ClosedAt: protoTime(row.ClosedAt),
			ClosedReason: row.ClosedReason, OutcomeUnknown: row.OutcomeUnknown,
			Kind: row.Kind, ResourceId: row.ResourceID, Unit: row.Unit,
		})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	if s.identity != nil && !actor.ServiceAccount {
		pending, err := s.identity.CountPendingApprovals(ctx, actor.ID)
		if err != nil && !errors.Is(err, identity.ErrAuthorizationDenied) {
			return nil, approvalError(err)
		}
		if err == nil {
			response.Approvals = &adminv1.FleetApprovalSummary{PendingApprovals: uint64(pending)}
		}
	}
	return noStore(response), nil
}

// fleetSummaryMaxAge bounds how old a background-computed unrestricted fleet
// population may be when served; ObservedAt always reports its snapshot time.
const fleetSummaryMaxAge = 30 * time.Second

// fleetSummaryRefresh is the background refresh period of that population.
const fleetSummaryRefresh = 10 * time.Second

// readFleetPopulation reads the device-population aggregates (lifecycle,
// contact, operating systems, resource compliance and advisory findings) in the
// caller's single read snapshot.
func (s *Service) readFleetPopulation(ctx context.Context, q *devicedb.Queries, unrestricted bool, scopes []byte) (*adminv1.GetFleetSummaryResponse, error) {
	counts, err := q.FleetSummaryCounts(ctx, devicedb.FleetSummaryCountsParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, mapErr(err)
	}
	operatingSystems, err := q.FleetSummaryOS(ctx, devicedb.FleetSummaryOSParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, mapErr(err)
	}
	compliance, err := q.FleetSummaryCompliance(ctx, devicedb.FleetSummaryComplianceParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, mapErr(err)
	}
	patch, err := q.FleetSummaryPatch(ctx, devicedb.FleetSummaryPatchParams{StaleAfterSeconds: patchStaleAfterSeconds, ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, mapErr(err)
	}
	response := &adminv1.GetFleetSummaryResponse{
		ObservedAt: protoTime(counts.ObservedAt),
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
		PatchCompliance: fleetPatchSummary(patch),
	}
	for _, row := range operatingSystems {
		response.OperatingSystems.Groups = append(response.OperatingSystems.Groups, &adminv1.FleetOSCount{
			OsId: row.OsID, OsVersion: row.OsVersion, Devices: uint64(row.Devices),
		})
		response.OperatingSystems.OtherDevices -= uint64(row.Devices)
	}
	if s.advisories != nil {
		findings, err := q.FleetSummaryFindings(ctx, devicedb.FleetSummaryFindingsParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
		if err != nil {
			return nil, mapErr(err)
		}
		devices, err := q.FleetSummaryAdvisoryDevices(ctx, devicedb.FleetSummaryAdvisoryDevicesParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
		if err != nil {
			return nil, mapErr(err)
		}
		response.Findings = &adminv1.FleetFindingSummary{
			CriticalFindings: uint64(findings.CriticalFindings), HighFindings: uint64(findings.HighFindings),
			MediumFindings: uint64(findings.MediumFindings), LowFindings: uint64(findings.LowFindings), OtherFindings: uint64(findings.OtherFindings),
			EvaluatedDevices: uint64(devices.Evaluated), UnknownDevices: uint64(devices.Total - devices.Evaluated),
		}
	}
	return response, nil
}

// RunFleetSummary keeps this instance's unrestricted fleet population fresh so
// console reads do not rescan every device under load. Scoped readers and a
// stale or missing population always read live. It writes nothing.
func (s *Service) RunFleetSummary(ctx context.Context) error {
	ticker := time.NewTicker(fleetSummaryRefresh)
	defer ticker.Stop()
	for {
		if err := s.refreshFleetPopulation(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("fleet summary refresh failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Service) refreshFleetPopulation(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
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
	s.fleetPopulation.Store(population)
	return nil
}
