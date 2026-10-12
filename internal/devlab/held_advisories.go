package devlab

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/advisory"
	"lindm/internal/config"
	"lindm/internal/platform"
)

// HeldAdvisories derives online feeds exclusively from the platform registry.
// Rows without maintained complete export facts are explicitly unsupported.
func HeldAdvisories(release platform.Release, architecture string) (*configv1.AdvisoryConfig, error) {
	registered, ok := platform.Lookup(release.Key)
	if !ok {
		return nil, errors.New("held advisories require a registered release")
	}
	release = *registered
	nativeArchitecture := architecture
	switch architecture {
	case "amd64", "x86_64":
		nativeArchitecture, architecture = "x86_64", "amd64"
	case "arm64", "aarch64":
		nativeArchitecture, architecture = "aarch64", "arm64"
	}
	if !slices.Contains(release.Architectures, nativeArchitecture) {
		return nil, fmt.Errorf("held advisories: architecture %q unsupported for %s", architecture, release.Key)
	}
	if release.Packages.Backend != platform.BackendAPT {
		architecture = nativeArchitecture
	}
	if release.Advisory.Partial != "" {
		return nil, fmt.Errorf("held advisories: partial coverage for %s: %s", release.Key, release.Advisory.Partial)
	}
	if len(release.Advisory.Feeds) == 0 || release.Advisory.Ecosystem == "" {
		return nil, fmt.Errorf("held advisories: no advisory ecosystem for %s", release.Key)
	}
	cfg := &configv1.AdvisoryConfig{RefreshEnabled: true}
	for _, source := range release.Advisory.Feeds {
		export, ok := release.Advisory.Exports[source]
		url := export.URL
		if len(export.ArchitectureURLs) != 0 {
			url = export.ArchitectureURLs[nativeArchitecture]
		}
		if !ok || url == "" || export.MaxAgeSeconds == 0 {
			return nil, fmt.Errorf("held advisories: no maintained %s export for %s", source, release.Key)
		}
		var format advisoryv1.FeedFormat
		switch export.Format {
		case "osv-zip":
			format = advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP
		case "rpm-repomd":
			format = advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD
		case "redhat-csaf-archives":
			format = advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES
		default:
			return nil, fmt.Errorf("held advisories: unsupported export format %q for %s", export.Format, release.Key)
		}
		feed := &advisoryv1.FeedSource{
			Id:     "held-" + release.Key + "-" + architecture + "-" + string(source),
			Distro: release.ID, Release: release.FeedRelease(release.Version.Value),
			Architecture: architecture, Url: url, Format: format, MaxAgeSeconds: export.MaxAgeSeconds,
			PlatformStream: export.PlatformStream,
		}
		if export.MaxArchiveBytes != 0 {
			feed.MaxArchiveBytes = proto.Uint64(export.MaxArchiveBytes)
		}
		cfg.Feeds = append(cfg.Feeds, feed)
	}
	return cfg, nil
}

const (
	heldAdvisoryByteBudget = 4 << 30
	heldAdvisoryDuration   = 2 * time.Hour
)

// EnableAdvisories publishes the first real refresh through the acceptance HTTP
// cache, then persists the config and restarts only lindmd on the same database.
// cacheDir belongs to the controller's persistent lab work directory, not the
// disposable fixture. Connected fixtures cannot mutate controller configuration.
// Identical configuration leaves existing publications intact; the normal server
// worker refreshes when due, and held callers still gate on WaitDeviceFindings.
// The persisted feeds are exactly the ones refreshed here, including their
// cached-download idle bound: a different feed configuration would retire the
// held publication when the server restarts.
func (f *AuthorityFixture) EnableAdvisories(ctx context.Context, cfg *configv1.AdvisoryConfig, cacheDir string) error {
	if f.connected != nil {
		return errors.New("advisory configuration requires controller-owned authority fixture")
	}
	if f.closed {
		return errors.New("isolated authority fixture is closed")
	}
	if cfg == nil || !cfg.GetRefreshEnabled() || len(cfg.GetFeeds()) == 0 {
		return errors.New("held advisories require feeds and enabled refresh")
	}
	if cacheDir == "" {
		return errors.New("held advisories require a persistent cache directory")
	}
	cfg = cachedRefreshConfig(cfg, heldAdvisoryDuration)
	ctx, cancel := context.WithTimeout(ctx, heldAdvisoryDuration)
	defer cancel()
	document, err := config.Load(f.configPath())
	if err != nil {
		return err
	}
	if proto.Equal(document.Proto.GetAdvisories(), cfg) {
		return nil
	}
	document.Proto.Advisories = cfg
	resources, err := document.Resolve()
	if err != nil {
		return err
	}
	defer resources.HTTPClient.CloseIdleConnections()
	pool, err := pgxpool.NewWithConfig(ctx, resources.Database)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := refreshHeldAdvisories(ctx, pool, document.Proto.GetAdvisories(), resources.HTTPClient, cacheDir); err != nil {
		return fmt.Errorf("refresh held advisories: %w", err)
	}
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return err
	}
	if err := f.writeConfig(encoded); err != nil {
		return err
	}
	return f.Restart(ctx)
}

func refreshHeldAdvisories(ctx context.Context, pool *pgxpool.Pool, cfg *configv1.AdvisoryConfig, client *http.Client, cacheDir string) error {
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return err
	}
	cache := &acceptanceFeedCache{base: client.Transport, directory: cacheDir, remaining: heldAdvisoryByteBudget}
	if cache.base == nil {
		cache.base = http.DefaultTransport
	}
	cachedClient := *client
	cachedClient.Transport = cache
	service, err := advisory.New(ctx, pool, cfg, &cachedClient)
	if err != nil {
		return err
	}
	return service.Refresh(ctx)
}

// DeviceFindingCounts counts every page of a single current device evaluation.
// A zero affected count is meaningful only with the returned non-unknown freshness.
type DeviceFindingCounts struct {
	Affected  uint64
	Accepted  uint64
	Unknown   uint64
	Clear     uint64
	Freshness *adminv1.AdvisoryFreshness
}

// UnknownEvaluationError reports a device whose current evaluation stayed
// UNKNOWN for the whole wait. Counts carries that evaluation and its reason;
// callers decide whether the product's reason is an honest terminal state.
type UnknownEvaluationError struct {
	Counts *DeviceFindingCounts
	err    error
}

func (e *UnknownEvaluationError) Error() string {
	return fmt.Sprintf("wait for device advisory evaluation (%s): %v", e.Counts.Freshness.GetReason(), e.err)
}

func (e *UnknownEvaluationError) Unwrap() error { return e.err }

// WaitDeviceFindings waits for a current evaluation through the admin API, never
// treating missing coverage or a pending evaluation as a zero finding count.
func WaitDeviceFindings(ctx context.Context, session *OwnerSession, deviceID string, timeout time.Duration) (*DeviceFindingCounts, error) {
	if session == nil || session.Admin == nil || deviceID == "" || timeout <= 0 {
		return nil, errors.New("device findings require an admin session, device and positive timeout")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	reason := "evaluation_pending"
	var last *DeviceFindingCounts
	for {
		counts, err := deviceFindingCounts(ctx, session, deviceID)
		if err != nil {
			return nil, fmt.Errorf("read device findings: %w", err)
		}
		if counts != nil {
			switch counts.Freshness.GetState() {
			case adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED,
				adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED,
				adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR:
				return counts, nil
			}
			reason, last = counts.Freshness.GetReason(), counts
		}
		select {
		case <-ctx.Done():
			if last != nil && last.Freshness.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN && reason != "" && reason != "evaluation_pending" {
				return nil, &UnknownEvaluationError{Counts: last, err: ctx.Err()}
			}
			return nil, fmt.Errorf("wait for device advisory evaluation (%s): %w", reason, ctx.Err())
		case <-ticker.C:
		}
	}
}

func deviceFindingCounts(ctx context.Context, session *OwnerSession, deviceID string) (*DeviceFindingCounts, error) {
	counts := &DeviceFindingCounts{}
	request := &adminv1.ListDeviceFindingsRequest{DeviceId: deviceID, PageSize: 200}
	for {
		response, err := session.Admin.ListDeviceFindings(ctx, connect.NewRequest(request))
		if err != nil {
			// A new inventory or publication invalidates the cursor. Poll the new
			// evaluation instead of mixing counts from different generations.
			if request.PageToken != "" && connect.CodeOf(err) == connect.CodeAborted {
				return nil, nil
			}
			return nil, err
		}
		freshness := response.Msg.GetFreshness()
		if counts.Freshness == nil {
			counts.Freshness = freshness
		} else if !proto.Equal(counts.Freshness, freshness) {
			return nil, nil
		}
		if freshness.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || freshness.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNSPECIFIED {
			return counts, nil
		}
		for _, finding := range response.Msg.GetFindings() {
			switch finding.GetState() {
			case adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED:
				counts.Affected++
			case adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED:
				counts.Accepted++
			case adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR:
				counts.Clear++
			default:
				counts.Unknown++
			}
		}
		request.PageToken = response.Msg.GetNextPageToken()
		if request.PageToken == "" {
			return counts, nil
		}
	}
}
