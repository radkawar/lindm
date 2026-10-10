package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// These TLS fixtures model documented Microsoft responses; they are not live
// Entra qualification or measurements of Microsoft's propagation/availability.
func entraFixture(t *testing.T, graph http.HandlerFunc) (*entraSource, *atomic.Int32) {
	t.Helper()
	var tokens atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodPost || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != "https://graph.microsoft.com/.default" || r.Form.Get("client_id") != "directory-client" || r.Form.Get("client_secret") != "directory-secret" {
				t.Error("incorrect app-only token request")
			}
			writeGraphJSON(t, w, fmt.Sprintf(`{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, tokens.Add(1)))
			return
		}
		if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" {
			t.Error("Graph request missing bearer authentication or wrong method")
		}
		graph(w, r)
	}))
	t.Cleanup(server.Close)
	source, err := newEntraSource(context.Background(), server.URL+"/v1.0", "directory-client", "directory-secret", server.URL+"/token", server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return source, &tokens
}

func writeGraphJSON(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	if _, err := fmt.Fprint(w, body); err != nil {
		t.Errorf("write fixture: %v", err)
	}
}

func TestEntraSourceCurrentAuthority(t *testing.T) {
	user, admin := uuid.New(), uuid.New()
	var state atomic.Int32
	source, tokens := entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/"+user.String()) {
			if r.URL.Query().Get("$select") != "id,accountEnabled,displayName" {
				t.Error("user fields not explicitly selected")
			}
			if state.Load() == 3 {
				w.WriteHeader(http.StatusNotFound)
				writeGraphJSON(t, w, `{"error":{"code":"Request_ResourceNotFound"}}`)
				return
			}
			if state.Load() == 4 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeGraphJSON(t, w, fmt.Sprintf(`{"id":%q,"accountEnabled":%t,"displayName":"Ada\nLovelace"}`, user, state.Load() != 2))
			return
		}
		if r.URL.Path != "/v1.0/users/"+user.String()+"/transitiveMemberOf/microsoft.graph.group" || r.Header.Get("ConsistencyLevel") != "eventual" {
			t.Error("wrong transitive membership request")
		}
		if state.Load() == 2 {
			t.Error("disabled user membership was queried")
		}
		if state.Load() != 0 {
			writeGraphJSON(t, w, `{"value":[]}`)
			return
		}
		if r.URL.Query().Get("$skiptoken") == "page2" {
			writeGraphJSON(t, w, fmt.Sprintf(`{"value":[{"id":%q}]}`, admin))
			return
		}
		if r.URL.Query().Get("$count") != "true" || r.URL.Query().Get("$select") != "id" || r.URL.Query().Get("$top") != "100" {
			t.Error("missing bounded advanced Graph query")
		}
		writeGraphJSON(t, w, fmt.Sprintf(`{"value":[{"id":%q}],"@odata.nextLink":%q}`, admin, "https://"+r.Host+r.URL.Path+"?$skiptoken=page2"))
	})
	var directory DirectorySource = source
	obs, err := directory.Observe(context.Background(), user.String())
	if err != nil || !obs.Found || !obs.Enabled || !obs.Direct || obs.UserID != user.String() || obs.DisplayName != "AdaLovelace" || len(obs.Groups) != 1 || obs.Groups[0] != admin.String() || !obs.AcquiredAt.IsZero() {
		t.Fatalf("observation = %+v, %v", obs, err)
	}
	for _, current := range []int32{1, 2, 3, 4} {
		state.Store(current)
		obs, err = directory.Observe(context.Background(), user.String())
		if len(obs.Groups) != 0 || obs.Found != (current < 3) || obs.Enabled != (current == 1) || (err != nil) != (current == 4) {
			t.Fatalf("state %d retained authority: %+v, %v", current, obs, err)
		}
	}
	if tokens.Load() != 1 {
		t.Fatal("unexpired app-only token not reused")
	}
}

func TestEntraRejectsMalformedAndUnboundedResponses(t *testing.T) {
	user := uuid.New()
	for _, test := range []struct {
		name string
		user string
		page func(*http.Request, int32) string
	}{
		{name: "missing enabled", user: fmt.Sprintf(`{"id":%q}`, user)},
		{name: "null enabled", user: fmt.Sprintf(`{"id":%q,"accountEnabled":null}`, user)},
		{name: "wrong object", user: fmt.Sprintf(`{"id":%q,"accountEnabled":true}`, uuid.New())},
		{name: "malformed user", user: `{`},
		{name: "oversized user", user: strings.Repeat(" ", maxDirectoryBody+1)},
		{name: "missing collection", page: func(*http.Request, int32) string { return `{}` }},
		{name: "null collection", page: func(*http.Request, int32) string { return `{"value":null}` }},
		{name: "invalid group", page: func(*http.Request, int32) string { return `{"value":[{"id":"email@example.com"}]}` }},
		{name: "null group", page: func(*http.Request, int32) string { return `{"value":[null]}` }},
		{name: "oversized page", page: func(*http.Request, int32) string {
			groups := make([]map[string]string, groupPageSize+1)
			for i := range groups {
				groups[i] = map[string]string{"id": uuid.NewString()}
			}
			data, err := json.Marshal(map[string]any{"value": groups})
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}},
		{name: "page limit", page: func(r *http.Request, page int32) string {
			return fmt.Sprintf(`{"value":[],"@odata.nextLink":%q}`, "https://"+r.Host+r.URL.Path+fmt.Sprintf("?$skiptoken=%d", page))
		}},
		{name: "foreign paging host", page: func(*http.Request, int32) string {
			return `{"value":[],"@odata.nextLink":"https://attacker.invalid/v1.0/users/other?$skiptoken=1"}`
		}},
		{name: "foreign paging user", page: func(r *http.Request, _ int32) string {
			return fmt.Sprintf(`{"value":[],"@odata.nextLink":%q}`, "https://"+r.Host+"/v1.0/users/other/transitiveMemberOf/microsoft.graph.group?$skiptoken=1")
		}},
		{name: "paging cycle", page: func(r *http.Request, _ int32) string {
			return fmt.Sprintf(`{"value":[],"@odata.nextLink":%q}`, "https://"+r.Host+r.URL.RequestURI())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var pages atomic.Int32
			source, _ := entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, user.String()) {
					body := test.user
					if body == "" {
						body = fmt.Sprintf(`{"id":%q,"accountEnabled":true}`, user)
					}
					writeGraphJSON(t, w, body)
					return
				}
				writeGraphJSON(t, w, test.page(r, pages.Add(1)))
			})
			obs, err := source.Observe(context.Background(), user.String())
			if err == nil || obs.Found || len(obs.Groups) != 0 || pages.Load() > maxGroupPaths/groupPageSize {
				t.Fatalf("malformed response granted authority: %+v, %v, pages %d", obs, err, pages.Load())
			}
		})
	}
}

func TestEntraConcurrentTokenRefresh(t *testing.T) {
	user := uuid.New()
	source, tokens := entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer token-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, user.String()) {
			writeGraphJSON(t, w, fmt.Sprintf(`{"id":%q,"accountEnabled":true}`, user))
		} else {
			writeGraphJSON(t, w, `{"value":[]}`)
		}
	})
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			obs, err := source.Observe(context.Background(), user.String())
			if err != nil || !obs.Enabled {
				t.Errorf("concurrent observation: %+v, %v", obs, err)
			}
		})
	}
	wg.Wait()
	if tokens.Load() != 2 {
		t.Fatalf("token requests = %d, want one refresh", tokens.Load())
	}
}

func TestEntraThrottlingAndTimeouts(t *testing.T) {
	user := uuid.New()
	for _, test := range []struct {
		name      string
		status    int
		retry     string
		always    bool
		allowed   bool
		wantCalls int32
		minWait   time.Duration
	}{
		{name: "429 recovers", status: 429, retry: "0", allowed: true, wantCalls: 2},
		{name: "Retry-After delay honored", status: 429, retry: "1", allowed: true, wantCalls: 2, minWait: time.Second},
		{name: "503 recovers", status: 503, retry: "0", allowed: true, wantCalls: 2},
		{name: "HTTP date recovers", status: 503, retry: time.Now().Add(-time.Second).UTC().Format(http.TimeFormat), allowed: true, wantCalls: 2},
		{name: "beyond deadline", status: 429, retry: "60", wantCalls: 1},
		{name: "invalid retry", status: 429, retry: "invalid", wantCalls: 1},
		{name: "missing retry", status: 503, wantCalls: 1},
		{name: "overflow retry", status: 429, retry: "999999999999999999999", wantCalls: 1},
		{name: "persistent throttling", status: 429, retry: "0", always: true, wantCalls: 4},
		{name: "persistent 401", status: 401, always: true, wantCalls: 2},
		{name: "redirect denied", status: 302, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			source, _ := entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 || test.always {
					w.Header().Set("Retry-After", test.retry)
					w.Header().Set("Location", "https://attacker.invalid/")
					w.WriteHeader(test.status)
					return
				}
				writeGraphJSON(t, w, fmt.Sprintf(`{"id":%q,"accountEnabled":false}`, user))
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			started := time.Now()
			obs, err := source.Observe(ctx, user.String())
			if (err == nil) != test.allowed || (!test.allowed && obs.Found) || calls.Load() != test.wantCalls {
				t.Fatalf("observation %+v, error %v, requests %d", obs, err, calls.Load())
			}
			if time.Since(started) < test.minWait {
				t.Fatal("Graph retried before Retry-After elapsed")
			}
		})
	}
	t.Run("request cancellation", func(t *testing.T) {
		source, _ := entraFixture(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		obs, err := source.Observe(ctx, user.String())
		if err == nil || obs.Found {
			t.Fatalf("timeout retained authority: %+v, %v", obs, err)
		}
	})
	t.Run("token gate cancellation", func(t *testing.T) {
		source, _ := entraFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected Graph request") })
		source.tokenGate <- struct{}{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := source.directoryToken(ctx, "")
		<-source.tokenGate
		if err == nil {
			t.Fatal("cancelled token wait succeeded")
		}
	})
	t.Run("retry cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cancel()
		if err := waitGraphRetry(ctx, "1", time.Now()); err == nil {
			t.Fatal("cancelled retry succeeded")
		}
	})
}
