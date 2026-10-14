// SPDX-License-Identifier: Apache-2.0

package ctl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "lindm/gen/lindm/auth/v1"
)

// This exercises the real listener, TLS exchange and private file; it is a
// protocol boundary test, not a substitute for real browser/OIDC qualification.
func TestLoginLoopbackPersistenceAndLogout(t *testing.T) {
	token, code := testToken(t), testToken(t)
	var challenge, redirect, verifier string
	var bindingMu sync.Mutex
	var revoked atomic.Bool
	client, path, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Error("authentication credential request has query")
		}
		switch r.URL.Path {
		case "/auth/cli/exchange":
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
				t.Error("exchange must be unauthenticated POST")
			}
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			request := &authv1.CLIExchangeRequest{}
			if err := protojson.Unmarshal(data, request); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			bindingMu.Lock()
			verifier = request.GetCodeVerifier()
			digest := sha256.Sum256([]byte(verifier))
			if request.GetCode() != code || request.GetRedirectUri() != redirect || base64.RawURLEncoding.EncodeToString(digest[:]) != challenge {
				t.Error("exchange binding mismatch")
			}
			bindingMu.Unlock()
			writeProto(t, w, &authv1.CLIExchangeResponse{Token: token, ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))})
		case "/auth/session":
			if r.Header.Get("Authorization") != "Bearer "+token || revoked.Load() {
				w.WriteHeader(401)
				return
			}
			writeProto(t, w, &authv1.SessionPrincipal{Id: "operator", Role: "owner"})
		case "/auth/logout":
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+token {
				t.Error("logout credential boundary")
			}
			revoked.Store(true)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	err := client.Login(context.Background(), func(ctx context.Context, target string) error {
		u, err := url.Parse(target)
		if err != nil {
			return err
		}
		q := u.Query()
		bindingMu.Lock()
		redirect, challenge = q.Get("redirect_uri"), q.Get("code_challenge")
		bindingMu.Unlock()
		callback, err := url.Parse(redirect)
		if err != nil {
			return err
		}
		if callback.Hostname() != "127.0.0.1" || callback.Path != "/callback" || callback.Port() == "" || len(q.Get("state")) != 43 {
			t.Fatal("incorrect loopback or state")
		}
		if strings.Contains(target, token) || q.Has("code_verifier") {
			t.Fatal("credential in authorize URL")
		}
		getCallback(t, redirect+"?"+url.Values{"state": {testToken(t)}, "code": {code}}.Encode(), 400)
		getCallback(t, redirect+"?"+url.Values{"state": {q.Get("state"), q.Get("state")}, "code": {code}}.Encode(), 400)
		getCallback(t, redirect+"?"+url.Values{"state": {q.Get("state")}, "code": {"invalid"}}.Encode(), 400)
		getCallback(t, redirect+"?"+url.Values{"state": {q.Get("state")}, "code": {code}}.Encode(), 200)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	bindingMu.Lock()
	savedVerifier := verifier
	bindingMu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), token) || strings.Contains(string(data), savedVerifier) || strings.Contains(string(data), code) {
		t.Fatal("persisted credential boundary violated")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %o", info.Mode().Perm())
	}
	principal, err := client.Whoami(context.Background())
	if err != nil || principal.GetId() != "operator" {
		t.Fatalf("whoami = %v, %v", principal, err)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg, err := client.store.load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GetSessionToken() != "" || !revoked.Load() {
		t.Fatal("logout did not revoke and clear")
	}
}

func TestLoginCancellationClosesListener(t *testing.T) {
	client, path, _ := testClient(t, http.NotFoundHandler())
	ctx, cancel := context.WithCancel(context.Background())
	var redirect string
	err := client.Login(ctx, func(_ context.Context, target string) error {
		u, err := url.Parse(target)
		if err != nil {
			return err
		}
		redirect = u.Query().Get("redirect_uri")
		cancel()
		return nil
	})
	if err == nil {
		t.Fatal("cancelled login succeeded")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled login persisted config: %v", err)
	}
	response, err := (&http.Client{Timeout: time.Second}).Get(redirect)
	if err == nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("callback listener remains open")
	}
}

func TestBearerRedirectNeverLeavesOrigin(t *testing.T) {
	var reached atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true); w.WriteHeader(204) }))
	defer destination.Close()
	client, _, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	client.config.SessionToken = testToken(t)
	_, err := client.Whoami(context.Background())
	var status *HTTPError
	if !errors.As(err, &status) || status.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect result = %v", err)
	}
	if reached.Load() {
		t.Fatal("followed bearer redirect")
	}
}

func TestConfigurationPermissionsSymlinksAndPinning(t *testing.T) {
	client, path, config := testClient(t, http.NotFoundHandler())
	if err := client.store.save(config); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"origin", "ca"} {
		changed := proto.CloneOf(config)
		if field == "origin" {
			changed.ServerOrigin = "https://other.example"
		} else {
			changed.CaPem += "\n"
		}
		other, err := New(path, changed)
		if err == nil {
			if closeErr := other.Close(); closeErr != nil {
				t.Error(closeErr)
			}
			t.Fatalf("replaced %s pin", field)
		}
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := client.store.load(); err == nil {
		t.Fatal("accepted readable credential file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	other, err := New(link, nil)
	if err == nil {
		if closeErr := other.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("accepted credential symlink")
	}
	dirLink := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(filepath.Dir(path), dirLink); err != nil {
		t.Fatal(err)
	}
	other, err = New(filepath.Join(dirLink, "config.json"), nil)
	if err == nil {
		if closeErr := other.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("accepted directory symlink")
	}
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	other, err = New(path, nil)
	if err == nil {
		if closeErr := other.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("accepted public credential directory")
	}
}

func TestMalformedExchangeDoesNotPersistOrDisclose(t *testing.T) {
	secret := "server-secret-must-not-appear"
	client, path, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProto(t, w, &authv1.CLIExchangeResponse{Token: secret, ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))})
	}))
	err := client.Login(context.Background(), func(_ context.Context, target string) error {
		u, err := url.Parse(target)
		if err != nil {
			return err
		}
		q := u.Query()
		getCallback(t, q.Get("redirect_uri")+"?"+url.Values{"state": {q.Get("state")}, "code": {testToken(t)}}.Encode(), 200)
		return nil
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe exchange error: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid token persisted: %v", err)
	}
}

func TestConfigurationRejectsHardlinksAndUnknownFields(t *testing.T) {
	client, path, config := testClient(t, http.NotFoundHandler())
	if err := client.store.save(config); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "hardlink.json")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := client.store.load(); err == nil {
		t.Fatal("accepted multiply linked credential file")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A misspelled security field must not silently weaken persisted settings.
	data = append([]byte(`{"unknownSecuritySetting":true,`), data[1:]...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.store.load(); err == nil {
		t.Fatal("accepted unknown config field")
	}
}

func TestLogoutFailureRetainsDurableCredential(t *testing.T) {
	client, _, config := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	config.SessionToken = testToken(t)
	client.config.SessionToken = config.SessionToken
	if err := client.store.save(config); err != nil {
		t.Fatal(err)
	}
	if err := client.Logout(context.Background()); err == nil {
		t.Fatal("logout claimed success without revocation")
	}
	saved, err := client.store.load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.GetSessionToken() != config.GetSessionToken() {
		t.Fatal("logout lost unrevoked credential")
	}
}

func TestPinnedOriginTrailingSlash(t *testing.T) {
	_, path, config := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/session" {
			t.Errorf("authentication path = %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeProto(t, w, &authv1.SessionPrincipal{Id: "operator"})
	}))
	config.ServerOrigin += "/"
	config.SessionToken = testToken(t)
	client, err := New(path, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := client.Whoami(context.Background()); err != nil {
		t.Fatal(err)
	}
}
