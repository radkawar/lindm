// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/admin/v1/adminv1connect"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

func TestHeldAdvisoriesGuestArchitecture(t *testing.T) {
	release, ok := platform.Lookup("ubuntu-24.04")
	if !ok {
		t.Fatal("missing guest registry row")
	}
	for input, want := range map[string]string{"amd64": "amd64", "arm64": "arm64", "x86_64": "amd64", "aarch64": "arm64"} {
		t.Run(input, func(t *testing.T) {
			cfg, err := HeldAdvisories(*release, input)
			if err != nil {
				t.Fatal(err)
			}
			if err := protovalidate.Validate(cfg); err != nil {
				t.Fatal(err)
			}
			if !cfg.GetRefreshEnabled() || len(cfg.GetFeeds()) != 1 {
				t.Fatalf("held configuration = %v", cfg)
			}
			feed := cfg.GetFeeds()[0]
			if feed.GetArchitecture() != want || feed.GetDistro() != release.ID || feed.GetRelease() != release.Version.Value || feed.GetUrl() != "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip" || feed.GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP || feed.GetMaxAgeSeconds() != 86400 || feed.GetMaxArchiveBytes() < 2<<30 {
				t.Fatalf("guest feed = %v", feed)
			}
		})
	}
}

func TestHeldAdvisoriesRPMGuestArchitecture(t *testing.T) {
	for _, target := range []struct {
		key, url, stream string
		format           advisoryv1.FeedFormat
		maxAge           uint64
	}{
		{key: "fedora-44", url: "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/", format: advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD, maxAge: 86400},
		{key: "rhel-9", url: "https://security.access.redhat.com/data/csaf/v2/", stream: "standard", format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES, maxAge: 604800},
	} {
		release, ok := platform.Lookup(target.key)
		if !ok {
			t.Fatalf("missing registry row %s", target.key)
		}
		for input, want := range map[string]string{"amd64": "x86_64", "arm64": "aarch64", "x86_64": "x86_64", "aarch64": "aarch64"} {
			t.Run(target.key+"/"+input, func(t *testing.T) {
				cfg, err := HeldAdvisories(*release, input)
				if err != nil {
					t.Fatal(err)
				}
				if err := protovalidate.Validate(cfg); err != nil {
					t.Fatal(err)
				}
				if !cfg.GetRefreshEnabled() || len(cfg.GetFeeds()) != 1 {
					t.Fatalf("held configuration = %v", cfg)
				}
				url := target.url
				if target.format == advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD {
					url += want + "/repodata/repomd.xml"
				}
				feed := cfg.Feeds[0]
				if feed.GetDistro() != release.ID || feed.GetRelease() != release.Version.Value || feed.GetArchitecture() != want || feed.GetUrl() != url || feed.GetFormat() != target.format || feed.GetMaxAgeSeconds() != target.maxAge || feed.GetPlatformStream() != target.stream {
					t.Fatalf("incorrect RPM guest source: %v", feed)
				}
			})
		}
		if _, err := HeldAdvisories(*release, "s390x"); err == nil {
			t.Fatalf("%s accepted unsupported guest architecture", target.key)
		}
	}
}

func TestHeldAdvisoriesRejectUnsupportedCoverage(t *testing.T) {
	for _, key := range []string{"rocky-9", "linuxmint-22.3", "debian-13"} {
		t.Run(key, func(t *testing.T) {
			release, ok := platform.Lookup(key)
			if !ok {
				t.Fatalf("missing registry row %s", key)
			}
			if _, err := HeldAdvisories(*release, "amd64"); err == nil {
				t.Fatal("accepted missing or partial online coverage")
			}
		})
	}
	if _, err := HeldAdvisories(platform.Release{}, "amd64"); err == nil {
		t.Fatal("accepted unknown release")
	}
	release, _ := platform.Lookup("ubuntu-24.04")
	if _, err := HeldAdvisories(*release, "riscv64"); err == nil {
		t.Fatal("accepted unsupported guest architecture")
	}
}

func TestEnableAdvisoriesRejectsConnectedFixture(t *testing.T) {
	fixture := &AuthorityFixture{connected: &connectedAuthority{}}
	if err := fixture.EnableAdvisories(t.Context(), nil, ""); err == nil || err.Error() != "advisory configuration requires controller-owned authority fixture" {
		t.Fatalf("connected configuration error = %v", err)
	}
}

func TestHeldFeedCacheSurvivesRestartWithoutBodyTransfer(t *testing.T) {
	var requests, bodies atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("If-None-Match") == `"current"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		bodies.Add(1)
		w.Header().Set("ETag", `"current"`)
		_, _ = io.WriteString(w, "complete vendor export")
	}))
	defer server.Close()
	directory := t.TempDir()
	for attempt := range 2 {
		// A new transport represents a new fixture/controller process using the
		// same work directory; no in-memory cache survives this boundary.
		cache := &acceptanceFeedCache{base: http.DefaultTransport, directory: directory, remaining: heldAdvisoryByteBudget}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := cache.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		if err := errors.Join(err, response.Body.Close()); err != nil {
			t.Fatal(err)
		}
		if string(body) != "complete vendor export" || len(cache.artifacts) != 1 || cache.artifacts[0].Revalidated != (attempt == 1) {
			t.Fatalf("cache refresh %d lost verified bytes: %v", attempt, cache.artifacts)
		}
	}
	if requests.Load() != 2 || bodies.Load() != 1 {
		t.Fatalf("requests=%d body transfers=%d", requests.Load(), bodies.Load())
	}
}

type heldFindingsServer struct {
	adminv1connect.UnimplementedAdminServiceHandler
	list func(context.Context, *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error)
}

func (s *heldFindingsServer) ListDeviceFindings(ctx context.Context, request *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
	return s.list(ctx, request)
}

func heldFindingsSession(t *testing.T, server *heldFindingsServer) *OwnerSession {
	t.Helper()
	path, handler := adminv1connect.NewAdminServiceHandler(server)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	return &OwnerSession{Admin: adminv1connect.NewAdminServiceClient(httpServer.Client(), httpServer.URL)}
}

func TestWaitDeviceFindingsWaitsThenCountsEveryPage(t *testing.T) {
	var calls atomic.Int32
	session := heldFindingsSession(t, &heldFindingsServer{list: func(_ context.Context, request *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
		out := &adminv1.ListDeviceFindingsResponse{Freshness: &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED, SnapshotId: "snapshot"}}
		if calls.Add(1) == 1 {
			out.Freshness.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN
			out.Freshness.Reason = "evaluation_pending"
		} else if request.Msg.GetPageToken() == "" {
			out.Findings = []*adminv1.AdvisoryFinding{{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED}}
			out.NextPageToken = "second"
		} else {
			out.Findings = []*adminv1.AdvisoryFinding{{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED}}
		}
		return connect.NewResponse(out), nil
	}})
	counts, err := WaitDeviceFindings(t.Context(), session, "device", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || counts.Affected != 1 || counts.Accepted != 1 || counts.Unknown != 0 || counts.Freshness.GetSnapshotId() != "snapshot" {
		t.Fatalf("incomplete findings: calls=%d counts=%+v", calls.Load(), counts)
	}
}

func TestWaitDeviceFindingsNeverReturnsUnknownAsZero(t *testing.T) {
	session := heldFindingsSession(t, &heldFindingsServer{list: func(context.Context, *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
		return connect.NewResponse(&adminv1.ListDeviceFindingsResponse{Freshness: &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN, Reason: "feed_unavailable"}}), nil
	}})
	counts, err := WaitDeviceFindings(t.Context(), session, "device", 100*time.Millisecond)
	if counts != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unknown evaluation treated as ready: %+v %v", counts, err)
	}
}

func TestWaitDeviceFindingsPropagatesReadFailure(t *testing.T) {
	session := heldFindingsSession(t, &heldFindingsServer{list: func(context.Context, *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("forbidden"))
	}})
	if counts, err := WaitDeviceFindings(t.Context(), session, "device", time.Second); counts != nil || connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("API failure hidden: %+v %v", counts, err)
	}
}

func TestWaitDeviceFindingsReturnsEvaluatedZero(t *testing.T) {
	session := heldFindingsSession(t, &heldFindingsServer{list: func(context.Context, *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
		return connect.NewResponse(&adminv1.ListDeviceFindingsResponse{Freshness: &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR}}), nil
	}})
	counts, err := WaitDeviceFindings(t.Context(), session, "device", time.Second)
	if err != nil || counts == nil || counts.Affected != 0 || counts.Unknown != 0 || counts.Freshness.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR {
		t.Fatalf("evaluated zero was not ready: %+v %v", counts, err)
	}
}

func TestDeviceFindingCountsDiscardsChangedEvaluation(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		session := heldFindingsSession(t, &heldFindingsServer{list: func(_ context.Context, request *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
			if request.Msg.GetPageToken() != "" && conflict {
				return nil, connect.NewError(connect.CodeAborted, errors.New("advisory_evidence_changed"))
			}
			out := &adminv1.ListDeviceFindingsResponse{
				Freshness:     &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED, SnapshotId: "first"},
				Findings:      []*adminv1.AdvisoryFinding{{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED}},
				NextPageToken: "second",
			}
			if request.Msg.GetPageToken() != "" {
				out.Freshness.SnapshotId = "replacement"
				out.NextPageToken = ""
			}
			return connect.NewResponse(out), nil
		}})
		if counts, err := deviceFindingCounts(t.Context(), session, "device"); counts != nil || err != nil {
			t.Fatalf("mixed changed evaluation: conflict=%v counts=%+v err=%v", conflict, counts, err)
		}
	}
}
