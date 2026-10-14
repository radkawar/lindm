// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOktaSourceCurrentAuthorityAndImmutableIDs(t *testing.T) {
	var state atomic.Int32
	fixture := newProviderFixture(t, "okta", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users/00uImmutableUser" {
			if state.Load() == 3 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			status := "ACTIVE"
			if state.Load() == 2 {
				status = "SUSPENDED"
			}
			writeProviderJSON(t, w, fmt.Sprintf(`{"id":"00uImmutableUser","status":%q,"profile":{"firstName":"Renamed","lastName":"Person","login":"recycled@example.com"}}`, status))
			return
		}
		if r.URL.Path != "/api/v1/users/00uImmutableUser/groups" {
			t.Errorf("unexpected management path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if state.Load() != 0 {
			writeProviderJSON(t, w, `[]`)
			return
		}
		if r.URL.Query().Get("after") == "second" {
			writeProviderJSON(t, w, `[{"id":"00gAdmin","profile":{"name":"renamed again"}},{"id":"00gAudit"}]`)
			return
		}
		if r.URL.Query().Get("limit") != strconv.Itoa(groupPageSize) {
			t.Error("unbounded first group page")
		}
		w.Header().Add("Link", "<https://"+r.Host+r.URL.Path+"?after=second>; rel=\"next\"")
		writeProviderJSON(t, w, `[{"id":"00gAdmin","profile":{"name":"Not an authorization key"}}]`)
	})
	obs, err := fixture.source.Observe(context.Background(), "00uImmutableUser")
	if err != nil || !obs.Found || !obs.Direct || !obs.Enabled || obs.UserID != "00uImmutableUser" || obs.DisplayName != "Renamed Person" || len(obs.Groups) != 2 || obs.Groups[0] != "00gAdmin" || obs.Groups[1] != "00gAudit" || !obs.AcquiredAt.IsZero() {
		t.Fatalf("current authority = %+v, %v", obs, err)
	}
	for _, current := range []int32{1, 2, 3} {
		state.Store(current)
		obs, err := fixture.source.Observe(context.Background(), "00uImmutableUser")
		if err != nil || len(obs.Groups) != 0 || obs.Found != (current < 3) || obs.Enabled != (current == 1) {
			t.Fatalf("state %d retained stale authority: %+v, %v", current, obs, err)
		}
	}
	if fixture.tokens.Load() != 1 {
		t.Fatal("unexpired credential was not reused")
	}
}

func TestOktaSourceAccountStatuses(t *testing.T) {
	for _, status := range []string{"STAGED", "PROVISIONED", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT", "SUSPENDED", "DEPROVISIONED", "UNKNOWN", "active", ""} {
		t.Run(status, func(t *testing.T) {
			fixture := newProviderFixture(t, "okta", func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/groups") {
					t.Error("inactive account requested groups")
				}
				writeProviderJSON(t, w, fmt.Sprintf(`{"id":"00uImmutableUser","status":%q}`, status))
			})
			obs, err := fixture.source.Observe(context.Background(), "00uImmutableUser")
			if obs.Enabled || len(obs.Groups) != 0 || (err != nil) != (status == "") {
				t.Fatalf("status %q = %+v, %v", status, obs, err)
			}
		})
	}
}

func TestOktaSourceRejectsMaliciousPagination(t *testing.T) {
	for _, mode := range []string{"origin", "other-user", "other-api", "userinfo", "fragment", "relative", "duplicate-next", "cycle", "malformed", "encoded-path"} {
		t.Run(mode, func(t *testing.T) {
			var pages atomic.Int32
			fixture := newProviderFixture(t, "okta", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/users/user-id" {
					writeProviderJSON(t, w, `{"id":"user-id","status":"ACTIVE"}`)
					return
				}
				pages.Add(1)
				collection := "https://" + r.Host + "/api/v1/users/user-id/groups"
				target := collection + "?after=next"
				switch mode {
				case "origin":
					target = "https://attacker.invalid/api/v1/users/user-id/groups?after=next"
				case "other-user":
					target = "https://" + r.Host + "/api/v1/users/other/groups?after=next"
				case "other-api":
					target = "https://" + r.Host + "/api/v1/apps?after=next"
				case "userinfo":
					target = "https://attacker@" + r.Host + "/api/v1/users/user-id/groups?after=next"
				case "fragment":
					target += "#fragment"
				case "relative":
					target = "/api/v1/users/user-id/groups?after=next"
				case "encoded-path":
					target = "https://" + r.Host + "/api/v1/users/user-id/%67roups?after=next"
				case "cycle":
					target = collection + "?limit=" + strconv.Itoa(groupPageSize)
				}
				link := "<" + target + ">; rel=\"next\""
				if mode == "duplicate-next" {
					link += ", " + link
				}
				if mode == "malformed" {
					link = "not-a-link"
				}
				w.Header().Set("Link", link)
				writeProviderJSON(t, w, `[{"id":"group-id"}]`)
			})
			obs, err := fixture.source.Observe(context.Background(), "user-id")
			if err == nil || len(obs.Groups) != 0 || obs.Enabled || pages.Load() != 1 {
				t.Fatalf("malicious pagination retained partial grants: %+v, %v, pages=%d", obs, err, pages.Load())
			}
		})
	}
}

func TestOktaRateLimitHeadersBoundRetries(t *testing.T) {
	for _, mode := range []string{"retry-after", "reset", "both", "future", "invalid", "missing", "exhausted"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			fixture := newProviderFixture(t, "okta", func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) > 1 && mode != "exhausted" {
					writeProviderJSON(t, w, `{"id":"user-id","status":"SUSPENDED"}`)
					return
				}
				switch mode {
				case "retry-after", "exhausted":
					w.Header().Set("Retry-After", "0")
				case "reset":
					w.Header().Set("X-Rate-Limit-Reset", "1800000000")
				case "both":
					w.Header().Set("Retry-After", "0")
					w.Header().Set("X-Rate-Limit-Reset", "1800003600")
				case "future":
					w.Header().Set("Retry-After", "3600")
				case "invalid":
					w.Header().Set("X-Rate-Limit-Reset", "not-a-time")
				}
				w.WriteHeader(http.StatusTooManyRequests)
			})
			obs, err := fixture.source.Observe(context.Background(), "user-id")
			wantSuccess := mode == "retry-after" || mode == "reset"
			wantRequests := int32(1)
			if wantSuccess {
				wantRequests = 2
			}
			if mode == "exhausted" {
				wantRequests = 4
			}
			if (err == nil) != wantSuccess || obs.Enabled || requests.Load() != wantRequests {
				t.Fatalf("rate limit result = %+v, %v, requests=%d", obs, err, requests.Load())
			}
		})
	}
	if delay, retry, err := oktaRetry(http.StatusTooManyRequests, http.Header{"Retry-After": {time.Unix(1800000002, 0).UTC().Format(http.TimeFormat)}}, nil, 0, time.Unix(1800000000, 0)); err != nil || !retry || delay != 2*time.Second {
		t.Fatalf("HTTP-date retry = %s, %t, %v", delay, retry, err)
	}
}

func TestOktaRejectsUncorrelatedOrIncompleteAuthority(t *testing.T) {
	for _, mode := range []string{"wrong-user", "null-groups", "missing-group-id", "mutable-group-id", "unbounded-pages"} {
		t.Run(mode, func(t *testing.T) {
			var pages atomic.Int32
			fixture := newProviderFixture(t, "okta", func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/groups") {
					if mode == "wrong-user" {
						writeProviderJSON(t, w, `{"id":"replacement-id","status":"ACTIVE","profile":{"login":"user-id"}}`)
					} else {
						writeProviderJSON(t, w, `{"id":"user-id","status":"ACTIVE"}`)
					}
					return
				}
				page := pages.Add(1)
				switch mode {
				case "null-groups":
					writeProviderJSON(t, w, `null`)
				case "missing-group-id":
					writeProviderJSON(t, w, `[{"profile":{"name":"admins"}}]`)
				case "mutable-group-id":
					writeProviderJSON(t, w, `[{"id":"admins@example.com"}]`)
				case "unbounded-pages":
					w.Header().Set("Link", fmt.Sprintf("<https://%s%s?after=%d>; rel=\"next\"", r.Host, r.URL.Path, page))
					writeProviderJSON(t, w, `[{"id":"group-admin"}]`)
				default:
					t.Error("uncorrelated account requested groups")
				}
			})
			obs, err := fixture.source.Observe(context.Background(), "user-id")
			if err == nil || obs.Enabled || len(obs.Groups) != 0 {
				t.Fatalf("incomplete authority accepted: %+v, %v", obs, err)
			}
			if mode == "unbounded-pages" && pages.Load() != int32(maxGroupPaths/groupPageSize) {
				t.Fatalf("pagination bound = %d", pages.Load())
			}
		})
	}
}
