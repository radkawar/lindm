// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/admin/v1/adminv1connect"
)

func TestBrokerLoginFormsConfineCredentialsAndSAML(t *testing.T) {
	base, err := url.Parse(brokerUpstreamIssuer + "/protocol/saml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, action, inputs, id, kind string
		allowed                        bool
	}{
		{"upstream credential", brokerUpstreamIssuer + "/login-actions/authenticate?client_id=" + url.QueryEscape(brokerSAMLClient), "", "kc-form-login", "password", true},
		{"signed response transport", brokerIssuer + "/broker/" + brokerAlias + "/endpoint", `<input type="hidden" name="SAMLResponse" value="signed-envelope"><input type="hidden" name="RelayState" value="exact-relay">`, "", "response", true},
		{"request transport", brokerUpstreamIssuer + "/protocol/saml", `<input type="hidden" name="SAMLRequest" value="request">`, "", "request", true},
		{"shared realm credential", issuer + "/login-actions/authenticate?client_id=lindm-console", "", "kc-form-login", "", false},
		{"foreign credential", "https://untrusted.example/login", "", "kc-form-login", "", false},
		{"different SAML destination", brokerIssuer + "/broker/other/endpoint", `<input type="hidden" name="SAMLResponse" value="signed-envelope">`, "", "", false},
		{"ambiguous envelope", brokerIssuer + "/broker/" + brokerAlias + "/endpoint", `<input type="hidden" name="SAMLResponse" value="one"><input type="hidden" name="SAMLResponse" value="two">`, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`<form method="post" id="%s" action="%s">%s</form>`, tc.id, tc.action, tc.inputs))
			action, values, kind, err := brokerForm(body, base)
			if (err == nil) != tc.allowed {
				t.Fatalf("action=%v kind=%s error=%v", action, kind, err)
			}
			if tc.allowed && kind != tc.kind {
				t.Fatalf("kind=%s want=%s", kind, tc.kind)
			}
			if tc.kind == "response" && values.Get("RelayState") != "exact-relay" {
				t.Fatal("SAML relay binding altered")
			}
		})
	}
	if _, _, _, err := brokerForm([]byte(`<form method="post"></form><form method="post"></form>`), base); err == nil {
		t.Fatal("ambiguous forms accepted")
	}
}

func TestBrokerCleanupRequiresCompleteOwnedRunPrefix(t *testing.T) {
	prefix := brokerOwnedPrefix + uuid.NewString()
	if !brokerCleanupPrefix(prefix) {
		t.Fatal("exact owned run prefix rejected")
	}
	for _, value := range []string{"", "lindm", brokerOwnedPrefix, prefix + "-user", strings.TrimSuffix(prefix, prefix[len(prefix)-1:]), brokerOwnedPrefix + uuid.Nil.String(), brokerOwnedPrefix + "../lindm"} {
		if brokerCleanupPrefix(value) {
			t.Fatalf("unsafe cleanup prefix accepted: %q", value)
		}
	}
}

func TestBrokerBrowserRejectsSharedConsoleAndOtherRealms(t *testing.T) {
	origin := "https://localhost:49152"
	for _, tc := range []struct {
		target  string
		allowed bool
	}{
		{origin + "/auth/callback?code=one", true},
		{brokerIssuer + "/protocol/openid-connect/auth", true},
		{brokerUpstreamIssuer + "/login-actions/authenticate", true},
		{"https://localhost:18444/auth/callback", false},
		{issuer + "/protocol/openid-connect/auth", false},
		{"https://localhost:18443/realms/lindm-broker-other/login", false},
		{"http://localhost:49152/auth/callback", false},
		{origin + "/auth/callback#fragment", false},
	} {
		endpoint, err := url.Parse(tc.target)
		if err != nil {
			t.Fatal(err)
		}
		if brokerBrowserURL(endpoint, origin) != tc.allowed {
			t.Fatalf("unexpected redirect policy for %s", tc.target)
		}
	}
}

func TestBrokerGroupRemovalRequiresEmptySessionGrantsAndDeniedRPC(t *testing.T) {
	for _, tc := range []struct {
		name, session, stage string
		accepted             bool
	}{
		{"removed grants", `{}`, "group-removal", true},
		{"role remains", `{"role":"admin"}`, "group-removal", false},
		{"permission remains", `{"permissions":["devices.read"]}`, "group-removal", false},
		{"binding remains", `{"bindings":[{"role":"admin"}]}`, "group-removal", false},
		{"disable must deny session", `{}`, "disable", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/auth/session", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(tc.session)); err != nil {
					t.Error(err)
				}
			})
			mux.Handle(adminv1connect.AdminServiceListDevicesProcedure, connect.NewUnaryHandler(
				adminv1connect.AdminServiceListDevicesProcedure,
				func(context.Context, *connect.Request[adminv1.ListDevicesRequest]) (*connect.Response[adminv1.ListDevicesResponse], error) {
					return nil, connect.NewError(connect.CodePermissionDenied, errors.New("grant removed"))
				}))
			server := httptest.NewTLSServer(mux)
			defer server.Close()
			client := server.Client()
			browser := &brokerBrowser{client: client, origin: server.URL, admin: adminv1connect.NewAdminServiceClient(client, server.URL)}
			timeout := 50 * time.Millisecond
			if tc.accepted {
				timeout = 3 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, _, err := awaitBrokerDenial(ctx, browser, time.Now(), tc.stage)
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%t error=%v", tc.accepted, err)
			}
		})
	}
}

func TestBrokerStartupDiagnosticsAreBoundedAndRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.log")
	if err := os.WriteFile(path, []byte("startup failure secret-value\n"+strings.Repeat("x", 70*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	err := brokerStartupError(path, "secret-value")
	if err == nil || strings.Contains(err.Error(), "secret-value") || !strings.Contains(err.Error(), "[redacted]") || len(err.Error()) > 65*1024 {
		t.Fatal("startup diagnostics were not bounded and redacted")
	}
}
