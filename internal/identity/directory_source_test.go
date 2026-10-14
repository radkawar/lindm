// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestKeycloakSourceReadsCurrentAuthority(t *testing.T) {
	subject := uuid.New()
	var state atomic.Int32
	var tokenRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			tokenRequests.Add(1)
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s", r.Method)
			}
			if _, err := fmt.Fprint(w, `{"access_token":"directory-token","token_type":"Bearer","expires_in":300}`); err != nil {
				t.Errorf("write token: %v", err)
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer directory-token" {
			t.Error("directory read missing bearer token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if state.Load() == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var body string
		switch r.URL.Path {
		case "/admin/realms/lindm/users/" + subject.String():
			body = fmt.Sprintf(`{"id":%q,"username":"ada","enabled":%t}`, subject.String(), state.Load() == 0)
		case "/admin/realms/lindm/users/" + subject.String() + "/federated-identity":
			body = `[]`
		case "/admin/realms/lindm/users/" + subject.String() + "/groups":
			body = `[{"path":"/admins"}]`
		default:
			t.Errorf("unexpected directory path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, err := fmt.Fprint(w, body); err != nil {
			t.Errorf("write directory response: %v", err)
		}
	}))
	defer server.Close()

	source, err := newKeycloakSource(context.Background(), server.URL+"/realms/lindm", "directory", "secret", server.URL+"/token", server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var directory DirectorySource = source
	observation, err := directory.Observe(context.Background(), subject.String())
	if err != nil || !observation.Found || !observation.Enabled || !observation.Direct || observation.UserID != subject.String() || len(observation.Groups) != 1 || observation.Groups[0] != "/admins" {
		t.Fatalf("enabled observation = %+v, error = %v", observation, err)
	}
	if !observation.AcquiredAt.IsZero() {
		t.Fatal("source assigned a timestamp instead of the service database clock")
	}
	state.Store(1)
	observation, err = directory.Observe(context.Background(), subject.String())
	if err != nil || !observation.Found || observation.Enabled || len(observation.Groups) != 0 {
		t.Fatalf("disabled observation = %+v, error = %v", observation, err)
	}
	state.Store(2)
	observation, err = directory.Observe(context.Background(), subject.String())
	if err == nil || observation.Found || len(observation.Groups) != 0 {
		t.Fatalf("failed read retained authority: observation = %+v, error = %v", observation, err)
	}
	if got := tokenRequests.Load(); got != 1 {
		t.Fatalf("token requests = %d, want 1 for reusable unexpired credentials", got)
	}
}
