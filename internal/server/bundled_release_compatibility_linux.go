// SPDX-License-Identifier: Apache-2.0
//go:build linux

package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/auditkind"
	devicecore "lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/releaseupdate"
)

// Only the protected, attestation-verified installed agent bundle can activate
// its own series. HTTP publications and agent-reported versions supply no trust.
func activateBundledRelease(ctx context.Context, service *devicecore.Service, native *nativeRepositories, identity buildinfo.Info) error {
	if native.bundledRelease == nil {
		return nil
	}
	return service.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		if err := q.LockReleaseControl(ctx); err != nil {
			return err
		}
		rows, err := q.ListReleasedAgentSeries(ctx)
		if err != nil {
			return err
		}
		now, err := devicecore.DispatchClock(ctx, q)
		if err != nil {
			return err
		}
		series, err := bundledReleaseSeries(native.bundledRelease, identity, rows, now)
		if err != nil || series == nil {
			return err
		}
		// Announce retirement before a new minor can displace a prior series.
		if err := q.ExtendReleasedAgentSeriesNotice(ctx, series.SupportUntil); err != nil {
			return err
		}
		if err := q.PutReleasedAgentSeries(ctx, *series); err != nil {
			return err
		}
		return devicecore.InsertAudit(ctx, q, nil, auditkind.ReleaseSeriesRegister, fmt.Sprintf("%d.%d", series.Major, series.Minor), "Authenticated installed release "+identity.Version+" at "+identity.Revision)
	})
}

func bundledReleaseSeries(manifest *releasev1.ReleaseManifest, identity buildinfo.Info, rows []devicedb.ReleasedAgentSeries, now time.Time) (*devicedb.PutReleasedAgentSeriesParams, error) {
	if identity.Version != manifest.GetVersion() || identity.Revision == "" || identity.Revision != manifest.GetRevision() {
		return nil, errors.New("installed agent release does not match server build identity")
	}
	version, err := releaseupdate.ParseVersion(identity.Version)
	if err != nil || version[0] > math.MaxInt32 || version[1] > math.MaxInt32 {
		return nil, errors.New("installed release series is invalid")
	}
	released := time.Unix(manifest.GetSourceDateEpoch(), 0).UTC()
	if manifest.GetSourceDateEpoch() <= 0 || released.After(now) {
		return nil, errors.New("authenticated installed release date is invalid")
	}
	for _, row := range rows {
		if uint64(row.Major) != version[0] || uint64(row.Minor) != version[1] {
			continue
		}
		if now.Before(row.ReleasedAt.Time) || int64(buildinfo.ProtocolVersion) < int64(row.MinimumProtocol) || int64(buildinfo.ProtocolVersion) > int64(row.MaximumProtocol) {
			return nil, errors.New("registered release history does not admit the installed protocol")
		}
		// Restarts and patch upgrades never rewrite immutable release history or
		// refresh retirement deadlines. Preserve explicit owner registrations.
		return nil, nil
	}
	if len(rows) >= 1024 {
		return nil, errors.New("release history capacity reached")
	}
	if len(rows) > 0 && (uint64(rows[0].Major) > version[0] || (uint64(rows[0].Major) == version[0] && uint64(rows[0].Minor) > version[1])) {
		return nil, errors.New("an older unregistered installed series requires explicit owner registration")
	}
	return &devicedb.PutReleasedAgentSeriesParams{
		Major: int32(version[0]), Minor: int32(version[1]),
		ReleasedAt: devicecore.Timestamptz(released), SupportUntil: devicecore.Timestamptz(now.Add(90 * 24 * time.Hour)),
		MinimumProtocol: int32(buildinfo.ProtocolVersion), MaximumProtocol: int32(buildinfo.ProtocolVersion),
	}, nil
}
