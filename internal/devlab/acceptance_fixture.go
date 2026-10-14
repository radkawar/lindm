// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
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
	"lindm/internal/platform"
)

// CreateAcceptanceEnrollment issues a distinct browser-owned account through the
// real account API. Separate engines never borrow an authenticated cookie jar.
func (f *AuthorityFixture) CreateAcceptanceEnrollment(ctx context.Context, username, role string) (_ *authv1.AccountEnrollment, resultErr error) {
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
	if err := owner.localRequest(ctx, "/auth/accounts/create", &authv1.CreateAccountRequest{Username: username, Role: role}, enrollment, http.StatusOK); err != nil {
		return nil, err
	}
	return enrollment, nil
}

// DisableAcceptanceAccount retires a per-run browser operator through the normal
// account API. It leaves the named human owner and lane identities untouched.
func (f *AuthorityFixture) DisableAcceptanceAccount(ctx context.Context, accountID string) (resultErr error) {
	if f.local == nil || accountID == "" || accountID == f.local.owner.id || f.local.approver != nil && accountID == f.local.approver.id {
		return errors.New("acceptance account cleanup requires a distinct browser account")
	}
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeReleaseSession(owner)) }()
	return owner.localRequest(ctx, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: accountID, Enabled: false, Role: "owner"}, nil, http.StatusNoContent)
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
func (f *AuthorityFixture) RefreshAcceptanceFeeds(ctx context.Context, cacheDirectory string, byteBudget int64, duration time.Duration) (*AcceptanceFeedResult, error) {
	cfg, err := acceptanceAdvisories()
	if err != nil {
		return nil, err
	}
	return f.RefreshVendorFeeds(ctx, cacheDirectory, byteBudget, duration, cfg.Feeds)
}

// RefreshVendorFeeds configures exactly feeds (disabling any other configured
// feed, as the server's own configuration does) and refreshes them through the
// production pipeline with the revalidating, byte-bounded acceptance cache.
func (f *AuthorityFixture) RefreshVendorFeeds(ctx context.Context, cacheDirectory string, byteBudget int64, duration time.Duration, feeds []*advisoryv1.FeedSource) (result *AcceptanceFeedResult, resultErr error) {
	if byteBudget <= 0 || duration <= 0 || len(feeds) == 0 {
		return nil, errors.New("vendor feeds and positive size and duration budgets required")
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
	service, err := advisory.New(ctx, pool, cachedRefreshConfig(&configv1.AdvisoryConfig{Feeds: feeds}, duration), &client)
	if err != nil {
		return result, err
	}
	refreshErr := service.Refresh(ctx)
	result.Feeds, err = service.Feeds(ctx)
	return result, errors.Join(refreshErr, err)
}

func acceptanceAdvisories() (*configv1.AdvisoryConfig, error) {
	cfg := &configv1.AdvisoryConfig{}
	for _, target := range []struct{ release, id string }{
		{"ubuntu-24.04", "acceptance-ubuntu"},
		{"fedora-44", "acceptance-fedora"},
		{"rhel-9", "acceptance-rhel"},
	} {
		release, ok := platform.Lookup(target.release)
		if !ok {
			return nil, fmt.Errorf("acceptance feed release %s is not in the platform registry", target.release)
		}
		derived, err := HeldAdvisories(*release, "x86_64")
		if err != nil {
			return nil, err
		}
		if len(derived.GetFeeds()) != 1 {
			return nil, fmt.Errorf("acceptance feed release %s requires exactly one maintained export", target.release)
		}
		source := derived.Feeds[0]
		source.Id = target.id
		// Acceptance retains its existing parser archive default; held demos
		// opt into the registry's larger archive allowance separately.
		source.MaxArchiveBytes = nil
		cfg.Feeds = append(cfg.Feeds, source)
	}
	return cfg, nil
}
