//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

// These tests use only a unique owned user/group in the real development realm.
// The application retains its read-only directory credential; the fixture alone
// holds the separate laboratory mutation credential.
type dispatchDirectory struct {
	client            *http.Client
	token             string
	name, user, group string
}

func dispatchIdentity(t *testing.T, pool *pgxpool.Pool, scopes ...*authv1.DeviceScope) (*identity.Service, identity.Principal, *dispatchDirectory) {
	t.Helper()
	dir := filepath.Join("..", "..", ".cache", "dev")
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(read("transport-ca.crt")) {
		t.Fatal("invalid lab transport CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ResponseHeaderTimeout: 10 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"lindm-lab-admin"}, "client_secret": {strings.TrimSpace(string(read("lab-admin-secret")))}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost:18443/realms/lindm/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("lab token request failed: status=%d read=%v close=%v", response.StatusCode, err, closeErr)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &token); err != nil || token.AccessToken == "" {
		t.Fatal("invalid lab token response")
	}
	clear(data)
	fixture := &dispatchDirectory{client: client, token: token.AccessToken, name: "dispatch-" + uuid.NewString()}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, object := range []struct{ resource, id string }{{"users", fixture.user}, {"groups", fixture.group}} {
			id := object.id
			if id == "" {
				query := url.Values{"exact": {"true"}, "max": {"2"}}
				if object.resource == "users" {
					query.Set("username", fixture.name)
				} else {
					query.Set("search", fixture.name)
				}
				_, body, err := fixture.request(ctx, http.MethodGet, "/"+object.resource+"?"+query.Encode(), nil, http.StatusOK)
				if err != nil {
					t.Error(err)
					continue
				}
				var objects []struct{ ID, Name, Username string }
				if err := json.Unmarshal(body, &objects); err != nil || len(objects) > 1 {
					t.Error("ambiguous fixture cleanup")
					continue
				}
				if len(objects) == 0 {
					continue
				}
				if objects[0].Name != fixture.name && objects[0].Username != fixture.name {
					t.Error("unexpected fixture cleanup object")
					continue
				}
				id = objects[0].ID
			}
			if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil {
				t.Error("invalid owned cleanup ID")
				continue
			}
			if _, _, err := fixture.request(ctx, http.MethodDelete, "/"+object.resource+"/"+id, nil, http.StatusNoContent); err != nil {
				t.Error(err)
			}
		}
	})
	for _, resource := range []string{"groups", "users"} {
		payload := map[string]any{"name": fixture.name}
		if resource == "users" {
			payload = map[string]any{"username": fixture.name, "enabled": true}
		}
		header, _, err := fixture.request(t.Context(), http.MethodPost, "/"+resource, payload, http.StatusCreated)
		if err != nil {
			t.Fatal(err)
		}
		location, err := url.Parse(header.Get("Location"))
		if err != nil || location.Scheme != "https" || location.Host != "localhost:18443" || !strings.HasPrefix(location.Path, "/admin/realms/lindm/"+resource+"/") {
			t.Fatal("invalid fixture creation location")
		}
		id := strings.TrimPrefix(location.Path, "/admin/realms/lindm/"+resource+"/")
		if _, err := uuid.Parse(id); err != nil {
			t.Fatal(err)
		}
		if resource == "users" {
			fixture.user = id
		} else {
			fixture.group = id
		}
	}
	fixture.membership(t, true)
	service, err := identity.New(t.Context(), pool, identity.Config{Issuer: "https://localhost:18443/realms/lindm", ClientID: "lindm-console", ClientSecret: strings.TrimSpace(string(read("console-secret"))), DirectoryClientID: "lindm-directory", DirectoryClientSecret: strings.TrimSpace(string(read("directory-secret"))), PublicURL: "https://localhost:18444", Policy: &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "/" + fixture.name, Role: identity.RoleAdmin, Scopes: scopes}}}, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	actor := identity.Principal{ID: uuid.New(), Issuer: "https://localhost:18443/realms/lindm", Subject: fixture.user, Role: identity.RoleAdmin}
	if _, err := pool.Exec(t.Context(), "INSERT INTO principals(id,issuer,subject) VALUES($1,$2,$3)", actor.ID, actor.Issuer, actor.Subject); err != nil {
		t.Fatal(err)
	}
	return service, actor, fixture
}

func (f *dispatchDirectory) request(ctx context.Context, method, path string, payload any, want int) (http.Header, []byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://localhost:18443/admin/realms/lindm"+path, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := f.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	if closeErr != nil {
		return nil, nil, closeErr
	}
	if response.StatusCode != want {
		return nil, nil, fmt.Errorf("owned directory %s %s: status %d want %d", method, path, response.StatusCode, want)
	}
	return response.Header, data, nil
}

// reviewer creates a distinct owned directory user in the fixture group, so an
// independent approval is authorized by the same fresh directory policy.
func (f *dispatchDirectory) reviewer(t *testing.T, pool *pgxpool.Pool) context.Context {
	t.Helper()
	name := f.name + "-reviewer"
	header, _, err := f.request(t.Context(), http.MethodPost, "/users", map[string]any{"username": name, "enabled": true}, http.StatusCreated)
	if err != nil {
		t.Fatal(err)
	}
	location, err := url.Parse(header.Get("Location"))
	if err != nil || location.Scheme != "https" || location.Host != "localhost:18443" || !strings.HasPrefix(location.Path, "/admin/realms/lindm/users/") {
		t.Fatal("invalid reviewer creation location")
	}
	id := strings.TrimPrefix(location.Path, "/admin/realms/lindm/users/")
	if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil {
		t.Fatal("invalid reviewer ID")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, _, err := f.request(ctx, http.MethodDelete, "/users/"+id, nil, http.StatusNoContent); err != nil {
			t.Error(err)
		}
	})
	if _, _, err := f.request(t.Context(), http.MethodPut, "/users/"+id+"/groups/"+f.group, nil, http.StatusNoContent); err != nil {
		t.Fatal(err)
	}
	reviewer := identity.Principal{ID: uuid.New(), Issuer: "https://localhost:18443/realms/lindm", Subject: id, Role: identity.RoleAdmin}
	if _, err := pool.Exec(t.Context(), "INSERT INTO principals(id,issuer,subject) VALUES($1,$2,$3)", reviewer.ID, reviewer.Issuer, reviewer.Subject); err != nil {
		t.Fatal(err)
	}
	return identity.WithPrincipal(t.Context(), reviewer)
}

func (f *dispatchDirectory) membership(t *testing.T, enabled bool) {
	t.Helper()
	method := http.MethodDelete
	if enabled {
		method = http.MethodPut
	}
	if _, _, err := f.request(t.Context(), method, "/users/"+f.user+"/groups/"+f.group, nil, http.StatusNoContent); err != nil {
		t.Fatal(err)
	}
}
