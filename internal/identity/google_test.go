package identity

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoogleSourceCurrentAuthorityAndConfiguredMembership(t *testing.T) {
	var state atomic.Int32
	fixture := newProviderFixture(t, "google", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/directory/v1/users/1234567890" {
			if state.Load() == 3 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.URL.Query().Get("fields") != "id,suspended,archived,deletionTime,name" || r.URL.Query().Get("viewType") != "admin_view" {
				t.Error("missing authoritative user field selection")
			}
			writeProviderJSON(t, w, fmt.Sprintf(`{"id":"1234567890","suspended":%t,"archived":false,"name":{"fullName":"Renamed Person"},"primaryEmail":"recycled@example.com"}`, state.Load() == 2))
			return
		}
		if r.URL.Path != "/admin/directory/v1/groups/group-admin/hasMember/1234567890" && r.URL.Path != "/admin/directory/v1/groups/group-auditor/hasMember/1234567890" {
			t.Errorf("unexpected group listing or email correlation: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		member := strings.Contains(r.URL.Path, "/group-admin/") && state.Load() == 0
		writeProviderJSON(t, w, fmt.Sprintf(`{"isMember":%t}`, member))
	})
	obs, err := fixture.source.Observe(context.Background(), "1234567890")
	if err != nil || !obs.Found || !obs.Direct || !obs.Enabled || obs.UserID != "1234567890" || obs.DisplayName != "Renamed Person" || len(obs.Groups) != 1 || obs.Groups[0] != "group-admin" || !obs.AcquiredAt.IsZero() {
		t.Fatalf("observation = %+v, %v", obs, err)
	}
	for _, current := range []int32{1, 2, 3} {
		state.Store(current)
		obs, err := fixture.source.Observe(context.Background(), "1234567890")
		if err != nil || len(obs.Groups) != 0 || obs.Found != (current < 3) || obs.Enabled != (current == 1) {
			t.Fatalf("state %d retained authority: %+v, %v", current, obs, err)
		}
	}
	if fixture.tokens.Load() != 1 {
		t.Fatal("unexpired service token was not reused")
	}
}

func TestGoogleSourceLifecycleAndMalformedState(t *testing.T) {
	for _, test := range []struct {
		name      string
		body      string
		wantError bool
	}{
		{name: "suspended", body: `{"id":"user-id","suspended":true,"archived":false}`},
		{name: "archived", body: `{"id":"user-id","suspended":false,"archived":true}`},
		{name: "deleted", body: `{"id":"user-id","suspended":false,"archived":false,"deletionTime":"2026-01-01T00:00:00Z"}`},
		{name: "missing suspended", body: `{"id":"user-id","archived":false}`, wantError: true},
		{name: "missing archived", body: `{"id":"user-id","suspended":false}`, wantError: true},
		{name: "null archived", body: `{"id":"user-id","suspended":false,"archived":null}`, wantError: true},
		{name: "wrong immutable user", body: `{"id":"replacement-id","suspended":false,"archived":false,"primaryEmail":"user-id"}`, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProviderFixture(t, "google", func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/groups/") {
					t.Error("invalid or disabled account queried membership")
				}
				writeProviderJSON(t, w, test.body)
			})
			obs, err := fixture.source.Observe(context.Background(), "user-id")
			if (err != nil) != test.wantError || obs.Enabled || len(obs.Groups) != 0 {
				t.Fatalf("invalid lifecycle granted authority: %+v, %v", obs, err)
			}
		})
	}
}

func TestGoogleMembershipErrorsNeverRetainPartialGrants(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		body      string
		wantError bool
	}{
		{name: "cross-domain nested", status: http.StatusBadRequest, body: `{"error":{"message":"Invalid input"}}`, wantError: true},
		{name: "forbidden", status: http.StatusForbidden, body: `{"error":{"errors":[{"reason":"forbidden"}]}}`, wantError: true},
		{name: "missing membership", status: http.StatusOK, body: `{}`, wantError: true},
		{name: "null membership", status: http.StatusOK, body: `{"isMember":null}`, wantError: true},
		{name: "removed group", status: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProviderFixture(t, "google", func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/users/") {
					writeProviderJSON(t, w, `{"id":"user-id","suspended":false,"archived":false}`)
					return
				}
				if strings.Contains(r.URL.Path, "/group-admin/") {
					writeProviderJSON(t, w, `{"isMember":true}`)
					return
				}
				w.WriteHeader(test.status)
				writeProviderJSON(t, w, test.body)
			})
			obs, err := fixture.source.Observe(context.Background(), "user-id")
			if (err != nil) != test.wantError || test.wantError && (obs.Enabled || len(obs.Groups) != 0) || !test.wantError && (len(obs.Groups) != 1 || obs.Groups[0] != "group-admin") {
				t.Fatalf("membership result = %+v, %v", obs, err)
			}
		})
	}
}

func TestGoogleQuotaBoundedExponentialBackoff(t *testing.T) {
	for _, reason := range []string{"userRateLimitExceeded", "quotaExceeded", "rateLimitExceeded"} {
		t.Run(reason, func(t *testing.T) {
			var requests atomic.Int32
			fixture := newProviderFixture(t, "google", func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				status := http.StatusForbidden
				if reason == "rateLimitExceeded" {
					status = http.StatusTooManyRequests
				}
				w.WriteHeader(status)
				writeProviderJSON(t, w, fmt.Sprintf(`{"error":{"errors":[{"reason":%q}]}}`, reason))
			})
			var delays []time.Duration
			fixture.oauth.wait = func(ctx context.Context, delay time.Duration) error {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("quota retry has no observation deadline")
				}
				delays = append(delays, delay)
				return nil
			}
			obs, err := fixture.source.Observe(context.Background(), "user-id")
			if err == nil || obs.Enabled || requests.Load() != 4 || len(delays) != 3 {
				t.Fatalf("unbounded quota result: %+v, %v, requests=%d, delays=%v", obs, err, requests.Load(), delays)
			}
			for attempt, delay := range delays {
				base := time.Second * time.Duration(1<<attempt)
				if delay < base || delay > base+time.Second {
					t.Errorf("backoff %d = %s", attempt, delay)
				}
			}
		})
	}
}

func TestGoogleQuotaCannotExtendObservationDeadline(t *testing.T) {
	var requests atomic.Int32
	fixture := newProviderFixture(t, "google", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	obs, err := fixture.source.Observe(context.Background(), "user-id")
	if err == nil || obs.Enabled || requests.Load() != 1 {
		t.Fatalf("quota extended deadline: %+v, %v, requests=%d", obs, err, requests.Load())
	}
}
