// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	"lindm/gen/lindm/releasemanagement/v1/releasemanagementv1connect"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/releaseupdate"
	"lindm/internal/rpcreason"
)

var _ releasemanagementv1connect.ReleaseManagementServiceHandler = (*Service)(nil)

// ReleaseManagementHandler must be mounted behind identity.RequireSession.
func (s *Service) ReleaseManagementHandler() (string, http.Handler) {
	path, handler := releasemanagementv1connect.NewReleaseManagementServiceHandler(s, s.HandlerOptions()...)
	return path, http.MaxBytesHandler(handler, MaxMessageBytes+MaxMessageOverhead)
}

func releaseSeriesMessage(row devicedb.ReleasedAgentSeries) *releasemanagementv1.ReleaseSeries {
	return &releasemanagementv1.ReleaseSeries{Major: uint32(row.Major), Minor: uint32(row.Minor), ReleasedAt: timestamppb.New(row.ReleasedAt.Time), SupportUntil: timestamppb.New(row.SupportUntil.Time), MinimumProtocol: uint32(row.MinimumProtocol), MaximumProtocol: uint32(row.MaximumProtocol)}
}

func (s *Service) GetCompatibility(ctx context.Context, req *connect.Request[releasemanagementv1.GetCompatibilityRequest]) (*connect.Response[releasemanagementv1.GetCompatibilityResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionManageReleaseUpdates); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_compatibility_request")
	}
	rows, err := devicedb.New(s.Pool).ListReleasedAgentSeries(ctx)
	if err != nil {
		return nil, MapErr(err)
	}
	response := &releasemanagementv1.GetCompatibilityResponse{ServerRelease: s.ServerRelease, ServerProtocol: s.ServerProtocol}
	for _, row := range rows {
		response.Series = append(response.Series, releaseSeriesMessage(row))
	}
	return NoStore(response), nil
}

func (s *Service) RegisterReleaseSeries(ctx context.Context, req *connect.Request[releasemanagementv1.RegisterReleaseSeriesRequest]) (*connect.Response[releasemanagementv1.RegisterReleaseSeriesResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageReleaseUpdates)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_release_series")
	}
	digest, err := ActionDigest(req.Msg)
	if err != nil {
		return nil, MapErr(err)
	}
	id, _ := uuid.Parse(req.Msg.GetRequestId())
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageReleaseUpdates, func(ctx context.Context, q *devicedb.Queries) error {
		if err := q.LockReleaseControl(ctx); err != nil {
			return err
		}
		_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, "RegisterReleaseSeries", id, digest)
		if err != nil {
			return err
		}
		if !owned {
			return nil
		}
		now, err := DispatchClock(ctx, q)
		if err != nil {
			return err
		}
		rows, err := q.ListReleasedAgentSeries(ctx)
		if err != nil {
			return err
		}
		if err := admitReleaseSeries(rows, req.Msg.GetSeries(), now); err != nil {
			return err
		}
		series := req.Msg.GetSeries()
		// Publishing a newer minor cannot instantly evict the former third series.
		// Its retirement gets a fresh 90-day announcement in the same audited commit.
		if len(rows) > 0 && (series.GetMajor() > uint32(rows[0].Major) || (series.GetMajor() == uint32(rows[0].Major) && series.GetMinor() > uint32(rows[0].Minor))) {
			if err := q.ExtendReleasedAgentSeriesNotice(ctx, Timestamptz(now.Add(90*24*time.Hour))); err != nil {
				return err
			}
		}
		if err := q.PutReleasedAgentSeries(ctx, devicedb.PutReleasedAgentSeriesParams{Major: int32(series.GetMajor()), Minor: int32(series.GetMinor()), ReleasedAt: Timestamptz(series.GetReleasedAt().AsTime()), SupportUntil: Timestamptz(series.GetSupportUntil().AsTime()), MinimumProtocol: int32(series.GetMinimumProtocol()), MaximumProtocol: int32(series.GetMaximumProtocol())}); err != nil {
			return err
		}
		if err := InsertAudit(ctx, q, &actor.ID, auditkind.ReleaseSeriesRegister, fmt.Sprintf("%d.%d", series.GetMajor(), series.GetMinor()), req.Msg.GetReason()); err != nil {
			return err
		}
		return CompleteAdmin(ctx, q, actor.ID, "RegisterReleaseSeries", id, uuid.Nil, uuid.Nil, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(&releasemanagementv1.RegisterReleaseSeriesResponse{Series: req.Msg.GetSeries()}), nil
}

func admitReleaseSeries(rows []devicedb.ReleasedAgentSeries, next *releasemanagementv1.ReleaseSeries, now time.Time) error {
	if next.GetReleasedAt().AsTime().After(now) {
		return Invalid("release_not_released")
	}
	for _, row := range rows {
		if uint32(row.Major) != next.GetMajor() || uint32(row.Minor) != next.GetMinor() {
			continue
		}
		if !row.ReleasedAt.Time.Equal(next.GetReleasedAt().AsTime()) || uint32(row.MinimumProtocol) != next.GetMinimumProtocol() || uint32(row.MaximumProtocol) != next.GetMaximumProtocol() || next.GetSupportUntil().AsTime().Before(row.SupportUntil.Time) {
			return rpcreason.Error(connect.CodeFailedPrecondition, "release_history_immutable")
		}
		return nil
	}
	if len(rows) >= 1024 {
		return rpcreason.Error(connect.CodeResourceExhausted, "release_history_capacity")
	}
	// A newly announced end of support cannot strand an existing installation.
	if next.GetSupportUntil().AsTime().Before(now.Add(90 * 24 * time.Hour)) {
		return Invalid("release_notice_less_than_90_days")
	}
	return nil
}

// requireReleaseCompatibility is called inside the device/session transaction
// only before minting or returning new executable authority. Historical results,
// inventory, renewal and the public signed repository deliberately remain usable.
func (s *Service) RequireReleaseCompatibility(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, epoch uint64) error {
	if !s.RequireCompatibility {
		return nil
	}
	report, err := q.GetDeviceReleaseReport(ctx, generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "agent_release_unknown")
	}
	if err != nil {
		return err
	}
	if uint64(report.SessionEpoch) != epoch {
		return ErrSessionFenced
	}
	rows, err := q.ListReleasedAgentSeries(ctx)
	if err != nil {
		return err
	}
	now, err := DispatchClock(ctx, q)
	if err != nil {
		return err
	}
	if !ReleaseSupported(rows, report.AgentRelease, uint32(report.ProtocolVersion), s.ServerRelease, s.ServerProtocol, now) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "agent_release_unsupported")
	}
	return nil
}

func ReleaseSupported(rows []devicedb.ReleasedAgentSeries, agent string, protocol uint32, server string, serverProtocol uint32, now time.Time) bool {
	agentVersion, err := releaseupdate.ParseVersion(agent)
	if err != nil || protocol == 0 {
		return false
	}
	serverVersion, err := releaseupdate.ParseVersion(server)
	if err != nil || serverProtocol == 0 || protocol != serverProtocol {
		return false
	}
	serverKnown := false
	for _, row := range rows {
		if uint64(row.Major) == serverVersion[0] && uint64(row.Minor) == serverVersion[1] && !now.Before(row.ReleasedAt.Time) && int64(serverProtocol) >= int64(row.MinimumProtocol) && int64(serverProtocol) <= int64(row.MaximumProtocol) {
			serverKnown = true
			break
		}
	}
	if !serverKnown {
		return false
	}
	released := 0
	for _, row := range rows {
		if now.Before(row.ReleasedAt.Time) {
			continue
		}
		released++
		if uint64(row.Major) != agentVersion[0] || uint64(row.Minor) != agentVersion[1] {
			continue
		}
		return (released <= 3 || now.Before(row.SupportUntil.Time)) && int64(protocol) >= int64(row.MinimumProtocol) && int64(protocol) <= int64(row.MaximumProtocol)
	}
	return false
}
