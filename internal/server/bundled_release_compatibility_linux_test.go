// SPDX-License-Identifier: Apache-2.0
//go:build linux

package server

import (
	"reflect"
	"testing"
	"time"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/agent/buildinfo"
	devicecore "lindm/internal/device/core"
	"lindm/internal/device/devicedb"
)

func bundledSeriesFixture() (*releasev1.ReleaseManifest, buildinfo.Info, time.Time) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	identity := buildinfo.Info{Version: "0.2.8", Revision: "authenticated-source-revision"}
	return &releasev1.ReleaseManifest{Version: identity.Version, Revision: identity.Revision, SourceDateEpoch: now.Add(-time.Hour).Unix()}, identity, now
}

func seriesRow(series *devicedb.PutReleasedAgentSeriesParams) devicedb.ReleasedAgentSeries {
	return devicedb.ReleasedAgentSeries{Major: series.Major, Minor: series.Minor, ReleasedAt: series.ReleasedAt, SupportUntil: series.SupportUntil, MinimumProtocol: series.MinimumProtocol, MaximumProtocol: series.MaximumProtocol}
}

func TestBundledReleaseActivatesOnlyKnownBuildAndProtocol(t *testing.T) {
	manifest, identity, now := bundledSeriesFixture()
	series, err := bundledReleaseSeries(manifest, identity, nil, now)
	if err != nil || series == nil {
		t.Fatalf("fresh authenticated installed release refused: %v", err)
	}
	if !series.SupportUntil.Time.Equal(now.Add(90*24*time.Hour)) || !series.ReleasedAt.Time.Equal(time.Unix(manifest.SourceDateEpoch, 0)) {
		t.Fatal("release date or ninety-day notice was fabricated")
	}
	rows := []devicedb.ReleasedAgentSeries{seriesRow(series)}
	if !devicecore.ReleaseSupported(rows, "0.2.8", buildinfo.ProtocolVersion, identity.Version, buildinfo.ProtocolVersion, now) {
		t.Fatal("the installed release still cannot receive executable work")
	}
	for _, release := range []string{"0.1.8", "0.3.8", "unknown"} {
		if devicecore.ReleaseSupported(rows, release, buildinfo.ProtocolVersion, identity.Version, buildinfo.ProtocolVersion, now) {
			t.Fatalf("unregistered agent release %q bypassed the compatibility gate", release)
		}
	}
	if devicecore.ReleaseSupported(rows, "0.2.8", buildinfo.ProtocolVersion+1, identity.Version, buildinfo.ProtocolVersion, now) {
		t.Fatal("unsupported protocol bypassed the compatibility gate")
	}
}

func TestBundledReleasePreservesRegisteredHistoryOnRestartAndPatchUpgrade(t *testing.T) {
	manifest, identity, now := bundledSeriesFixture()
	series, err := bundledReleaseSeries(manifest, identity, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	rows := []devicedb.ReleasedAgentSeries{seriesRow(series)}
	before := append([]devicedb.ReleasedAgentSeries(nil), rows...)
	for _, version := range []string{"0.2.8", "0.2.9"} {
		manifest.Version, identity.Version = version, version
		got, err := bundledReleaseSeries(manifest, identity, rows, now.Add(time.Hour))
		if err != nil || got != nil || !reflect.DeepEqual(rows, before) {
			t.Fatalf("restart or patch rewrote release history: %v", err)
		}
	}
}

func TestBundledReleaseRefusesUntrustedOrIncompatibleActivation(t *testing.T) {
	for _, name := range []string{"version", "revision", "empty-revision", "invalid-version", "overflow", "future", "missing-date", "older", "protocol", "capacity"} {
		t.Run(name, func(t *testing.T) {
			manifest, identity, now := bundledSeriesFixture()
			var rows []devicedb.ReleasedAgentSeries
			switch name {
			case "version":
				identity.Version = "0.2.9"
			case "revision":
				identity.Revision = "different-source-revision"
			case "empty-revision":
				identity.Revision = ""
			case "invalid-version":
				manifest.Version, identity.Version = "invalid", "invalid"
			case "overflow":
				manifest.Version, identity.Version = "0.2147483648.0", "0.2147483648.0"
			case "future":
				manifest.SourceDateEpoch = now.Add(time.Second).Unix()
			case "missing-date":
				manifest.SourceDateEpoch = 0
			case "older":
				rows = []devicedb.ReleasedAgentSeries{{Major: 0, Minor: 3}}
			case "protocol":
				rows = []devicedb.ReleasedAgentSeries{{Major: 0, Minor: 2, ReleasedAt: devicecore.Timestamptz(now.Add(-time.Hour)), MinimumProtocol: 2, MaximumProtocol: 2}}
			case "capacity":
				rows = make([]devicedb.ReleasedAgentSeries, 1024)
			}
			if series, err := bundledReleaseSeries(manifest, identity, rows, now); err == nil || series != nil {
				t.Fatal("unsafe release activation accepted")
			}
		})
	}
}

func TestCustomNativeRepositoryCannotActivateCompatibility(t *testing.T) {
	if err := activateBundledRelease(t.Context(), nil, &nativeRepositories{}, buildinfo.Info{Version: "0.2.8"}); err != nil {
		t.Fatal(err)
	}
}
