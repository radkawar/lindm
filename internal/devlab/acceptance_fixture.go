package devlab

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/advisory"
	"lindm/internal/config"
)

// CreateAcceptanceEnrollment issues a distinct browser-owned account through the
// real account API. Separate engines never borrow an authenticated cookie jar.
func (f *AuthorityFixture) CreateAcceptanceEnrollment(ctx context.Context, username string) (_ *authv1.AccountEnrollment, resultErr error) {
	if f.local == nil || f.ConsoleOrigin == consoleOrigin {
		return nil, errors.New("acceptance enrollment requires dynamic local console fixture")
	}
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, owner.Close(cleanup))
	}()
	enrollment := new(authv1.AccountEnrollment)
	if err := owner.localRequest(ctx, "/auth/accounts/create", &authv1.CreateAccountRequest{Username: username, Role: "owner"}, enrollment, http.StatusOK); err != nil {
		return nil, err
	}
	return enrollment, nil
}

// AcceptanceFeedResult keeps source evidence even when publication fails.
type AcceptanceFeedResult struct {
	StartedAt             time.Time                          `json:"started_at"`
	DurationSeconds       float64                            `json:"duration_seconds"`
	ByteBudget            int64                              `json:"byte_budget"`
	DurationBudgetSeconds float64                            `json:"duration_budget_seconds"`
	Artifacts             []AcceptanceFeedArtifact           `json:"artifacts"`
	Feeds                 *adminv1.ListAdvisoryFeedsResponse `json:"feeds,omitempty"`
}

// RefreshAcceptanceFeeds invokes the production refresh/publication pipeline on
// complete vendor exports, never curated records or the offline import path.
// Fedora publishes RPM updateinfo, not CSAF; Red Hat's paired CSAF archives are
// fetched separately. HTTP revalidation preserves vendor freshness on cache hits.
func (f *AuthorityFixture) RefreshAcceptanceFeeds(ctx context.Context, cacheDirectory string, byteBudget int64, duration time.Duration) (result *AcceptanceFeedResult, resultErr error) {
	if byteBudget <= 0 || duration <= 0 {
		return nil, errors.New("positive feed size and duration budgets required")
	}
	if err := os.MkdirAll(cacheDirectory, 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	result = &AcceptanceFeedResult{StartedAt: time.Now().UTC(), ByteBudget: byteBudget, DurationBudgetSeconds: duration.Seconds()}
	defer func() { result.DurationSeconds = time.Since(result.StartedAt).Seconds() }()
	document, err := config.Load(f.configPath())
	if err != nil {
		return result, err
	}
	resources, err := document.Resolve()
	if err != nil {
		return result, err
	}
	defer resources.HTTPClient.CloseIdleConnections()
	pool, err := pgxpool.NewWithConfig(ctx, resources.Database)
	if err != nil {
		return result, err
	}
	defer pool.Close()
	cache := &acceptanceFeedCache{base: resources.HTTPClient.Transport, directory: cacheDirectory, remaining: byteBudget}
	if cache.base == nil {
		cache.base = http.DefaultTransport
	}
	defer func() { result.Artifacts = cache.artifacts }()
	client := *resources.HTTPClient
	client.Transport = cache
	cfg := &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{
		{Id: "acceptance-ubuntu", Distro: "ubuntu", Release: "24.04", Architecture: "amd64", Url: "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip", Format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP, MaxAgeSeconds: 86400},
		{Id: "acceptance-fedora", Distro: "fedora", Release: "44", Architecture: "x86_64", Url: "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/repomd.xml", Format: advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD, MaxAgeSeconds: 86400},
		{Id: "acceptance-rhel", Distro: "rhel", Release: "9", Architecture: "x86_64", PlatformStream: "standard", Url: "https://security.access.redhat.com/data/csaf/v2/", Format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES, MaxAgeSeconds: 604800},
	}}
	service, err := advisory.New(ctx, pool, cfg, &client)
	if err != nil {
		return result, err
	}
	refreshErr := service.Refresh(ctx)
	result.Feeds, err = service.Feeds(ctx)
	return result, errors.Join(refreshErr, err)
}
