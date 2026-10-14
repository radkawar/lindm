// SPDX-License-Identifier: Apache-2.0

package redhatimages

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type registrationFixture struct {
	mu              sync.Mutex
	keys            map[string]bool
	created         int
	deleted         int
	authenticated   int
	badBearer       bool
	malformedCreate bool
	conflict        bool
	deleteFailure   bool
	systems         map[string]System
	systemDeletes   []string
	systemReads     int
	systemFailure   string
	keepSystem      bool
	renameSystem    string
	repeatPage      bool
	keepKey         bool
}

func registrationClient(t *testing.T, f *registrationFixture) *Client {
	t.Helper()
	if f.keys == nil {
		f.keys = make(map[string]bool)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Host == "sso.redhat.com" {
			f.authenticated++
			_, _ = io.WriteString(w, `{"access_token":"registration-bearer","token_type":"bearer","expires_in":900}`)
			return
		}
		f.badBearer = f.badBearer || (r.Host != "console.redhat.com" && r.Host != "api.access.redhat.com") || r.Header.Get("Authorization") != "Bearer registration-bearer"
		switch {
		case r.URL.Path == "/management/v1/systems" && r.Method == http.MethodGet:
			ids := make([]string, 0, len(f.systems))
			for id := range f.systems {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			if f.repeatPage {
				offset = 0
			}
			rows := make([]System, 0)
			for i := offset; i < len(ids) && i < offset+systemPageSize; i++ {
				rows = append(rows, f.systems[ids[i]])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"body": rows})
		case strings.HasPrefix(r.URL.Path, "/management/v1/systems/"):
			id := strings.TrimPrefix(r.URL.Path, "/management/v1/systems/")
			system, exists := f.systems[id]
			if r.Method == http.MethodDelete {
				f.systemDeletes = append(f.systemDeletes, id)
				if id == f.systemFailure {
					w.WriteHeader(503)
					_, _ = io.WriteString(w, "private-native-error")
					return
				}
				if !exists {
					w.WriteHeader(404)
					return
				}
				if !f.keepSystem {
					delete(f.systems, id)
				}
				w.WriteHeader(204)
				return
			}
			f.systemReads++
			if !exists {
				w.WriteHeader(404)
				return
			}
			if f.renameSystem != "" {
				system.Name = f.renameSystem
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"body": system, "account": "private-account", "activationKey": "private-key"})
		case r.URL.Path == "/api/rhsm/v2/organization":
			_, _ = io.WriteString(w, `{"body":{"id":123456}}`)
		case r.URL.Path == "/api/rhsm/v2/activation_keys" && r.Method == http.MethodPost:
			var payload struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if !ownedRegistration(payload.Name) {
				t.Error("created key outside lab namespace")
			}
			if f.conflict {
				w.WriteHeader(409)
				return
			}
			f.keys[payload.Name] = true
			f.created++
			if f.malformedCreate {
				_, _ = io.WriteString(w, `not-json-secret`)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"body": map[string]string{"name": payload.Name}}); err != nil {
				t.Error(err)
			}
		case r.URL.Path == "/api/rhsm/v2/activation_keys" && r.Method == http.MethodGet:
			rows := make([]map[string]string, 0, len(f.keys))
			for name := range f.keys {
				rows = append(rows, map[string]string{"name": name})
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"body": rows}); err != nil {
				t.Error(err)
			}
		case strings.HasPrefix(r.URL.Path, "/api/rhsm/v2/activation_keys/") && r.Method == http.MethodDelete:
			if f.deleteFailure {
				w.WriteHeader(503)
				return
			}
			name := strings.TrimPrefix(r.URL.Path, "/api/rhsm/v2/activation_keys/")
			if !ownedRegistration(name) {
				t.Error("deleted unrelated activation key")
			}
			if !f.keys[name] {
				w.WriteHeader(404)
				return
			}
			if !f.keepKey {
				delete(f.keys, name)
			}
			f.deleted++
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{http: &http.Client{Transport: fixtureTransport{target: u, base: server.Client().Transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, now: time.Now}
	t.Cleanup(client.Close)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("offline-private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := client.authenticate(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestRegistrationLeaseOwnsOnlyGeneratedKey(t *testing.T) {
	f := &registrationFixture{keys: map[string]bool{"customer-key": true}}
	client := registrationClient(t, f)
	lease, err := client.CreateRegistration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	organization, key := lease.Credentials()
	if organization != "123456" || !ownedRegistration(key) {
		t.Fatal("invalid private registration credentials")
	}
	for _, rendered := range []string{fmt.Sprintf("%v", lease), fmt.Sprintf("%+v", lease), fmt.Sprintf("%#v", lease)} {
		if strings.Contains(rendered, key) || strings.Contains(rendered, organization) {
			t.Fatal("lease formatting leaks credentials")
		}
	}
	// Expired access credentials are refreshed from the protected token file
	// before cleanup, not retried after a mutation may already have committed.
	client.expires = time.Time{}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if organization, key := lease.Credentials(); organization != "" || key != "" {
		t.Fatal("closed lease retained exposed credentials")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.created != 1 || f.deleted != 1 || f.authenticated != 2 || f.badBearer || len(f.keys) != 1 || !f.keys["customer-key"] {
		t.Fatal("lease ownership, auth refresh or idempotency failed")
	}
}

func TestRegistrationMalformedCreateCleansOwnedResource(t *testing.T) {
	f := &registrationFixture{malformedCreate: true}
	client := registrationClient(t, f)
	if _, err := client.CreateRegistration(context.Background()); err == nil || strings.Contains(err.Error(), "not-json-secret") {
		t.Fatal("malformed create response accepted or leaked")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.created != 1 || f.deleted != 1 || len(f.keys) != 0 {
		t.Fatal("ambiguous create left owned activation key")
	}
}

func TestRegistrationConflictNeverDeletesExistingKey(t *testing.T) {
	f := &registrationFixture{conflict: true}
	client := registrationClient(t, f)
	if _, err := client.CreateRegistration(context.Background()); err == nil {
		t.Fatal("conflicting create accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleted != 0 {
		t.Fatal("conflicting create deleted a key")
	}
}

func TestRegistrationCleanupRequiresConfirmationAndExactNamespace(t *testing.T) {
	owned := registrationPrefix + strings.Repeat("a", 32)
	f := &registrationFixture{keys: map[string]bool{owned: true, "customer-key": true, registrationPrefix + "customer": true, registrationPrefix + strings.Repeat("A", 32): true}}
	client := registrationClient(t, f)
	if _, err := client.CleanupRegistrations(context.Background(), false, ""); err == nil {
		t.Fatal("unconfirmed cleanup accepted")
	}
	result, err := client.CleanupRegistrations(context.Background(), true, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.KeysDeleted != 1 || !result.KeysAbsenceVerified {
		t.Fatal("incorrect cleanup count")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.keys) != 3 || f.keys[owned] || f.deleted != 1 {
		t.Fatal("cleanup affected keys outside exact owned namespace")
	}
}

func TestRegistrationCleanupFailureRetainsHandle(t *testing.T) {
	f := new(registrationFixture)
	client := registrationClient(t, f)
	lease, err := client.CreateRegistration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.deleteFailure = true
	f.mu.Unlock()
	if err := lease.Close(context.Background()); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	_, key := lease.Credentials()
	if key == "" {
		t.Fatal("cleanup failure discarded key handle")
	}
	f.mu.Lock()
	f.deleteFailure = false
	f.mu.Unlock()
	if err := lease.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
