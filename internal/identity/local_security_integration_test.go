//go:build integration

package identity

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
)

func TestBreakGlassPolicyDenialsDoNotLockCredentials(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := s.BootstrapLocalOwner(ctx, "emergency")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, auth)
	s.localPrimary = false
	s.issuer = "https://external.example/realms/lindm"
	policy := &configv1.BreakGlassPolicy{AllowedPermissions: []string{string(PermissionReadFleet)}, ConsoleOnly: true, MaxSessionLifetime: durationpb.New(time.Hour), RequireIncidentReason: true}
	for _, test := range []struct {
		name, reason, remote   string
		designated, configured bool
	}{
		{"remote peer", "incident", "192.0.2.1:1234", true, true},
		{"missing reason", "", "127.0.0.1:1234", true, true},
		{"undesignated", "incident", "127.0.0.1:1234", false, true},
		{"unconfigured", "incident", "127.0.0.1:1234", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s.breakGlass = nil
			if test.configured {
				s.breakGlass = policy
			}
			if _, err := pool.Exec(ctx, "UPDATE local_accounts SET break_glass=$2 WHERE id=$1", enrollment.AccountID, test.designated); err != nil {
				t.Fatal(err)
			}
			for range 6 {
				if _, err := s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "emergency", Password: "wrong password 123!", IncidentReason: test.reason}, test.remote); !errors.Is(err, errUnauthenticated) {
					t.Fatalf("policy denial: %v", err)
				}
			}
			account, err := identitydb.New(pool).GetLocalAccount(ctx, enrollment.AccountID)
			if err != nil {
				t.Fatal(err)
			}
			if account.FailedAttempts != 0 || account.LockedUntil.Valid {
				t.Fatalf("policy denial changed credential state: attempts=%d locked=%t", account.FailedAttempts, account.LockedUntil.Valid)
			}
		})
	}
	s.breakGlass = policy
	if _, err := pool.Exec(ctx, "UPDATE local_accounts SET break_glass=true WHERE id=$1", enrollment.AccountID); err != nil {
		t.Fatal(err)
	}
	// A peer-policy failure between password and WebAuthn also cannot lock out the account.
	challenge, err := s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "emergency", Password: localTestPassword, IncidentReason: "incident"}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, false, true, 1)
	if _, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}, "login", "192.0.2.1:1234"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("finish policy denial: %v", err)
	}
	account, err := identitydb.New(pool).GetLocalAccount(ctx, enrollment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.FailedAttempts != 0 || account.LockedUntil.Valid {
		t.Fatal("finish policy denial changed credential state")
	}
	_ = loginLocal(t, s, ctx, "emergency", "incident", auth)
}

func TestLocalLockExpiryStartsFiveAttemptWindow(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	enrollLocal(t, s, ctx, enrollment, localAuthenticator(t))
	if _, err := pool.Exec(ctx, "UPDATE local_accounts SET failed_attempts=5,locked_until=clock_timestamp()-interval '1 second' WHERE id=$1", enrollment.AccountID); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		if _, err := s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "owner", Password: "wrong password 123!"}, "127.0.0.1:1234"); !errors.Is(err, errUnauthenticated) {
			t.Fatal(err)
		}
		account, err := identitydb.New(pool).GetLocalAccount(ctx, enrollment.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		if account.FailedAttempts != int32(attempt) || account.LockedUntil.Valid != (attempt == 5) {
			t.Fatalf("attempt %d: durable attempts=%d locked=%t", attempt, account.FailedAttempts, account.LockedUntil.Valid)
		}
	}
	if _, err := s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "owner", Password: localTestPassword}, "127.0.0.1:1234"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("fifth failure did not lock account: %v", err)
	}
}

func TestLocalSessionUsesDatabaseAuthorityDespiteProcessClockSkew(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, auth)
	cookie := loginLocal(t, s, ctx, "owner", "", auth)
	for _, skew := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		s.now = func() time.Time { return time.Now().Add(skew) }
		if _, decision, err := s.resolve(ctx, cookie); err != nil || decision.Kind != accessOK {
			t.Fatalf("clock skew %s denied current local row: %v %v", skew, decision, err)
		}
	}
	if _, err := pool.Exec(ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", enrollment.AccountID); err != nil {
		t.Fatal(err)
	}
	if _, decision, err := s.resolve(ctx, cookie); err != nil || decision.Kind != accessUnauthenticated {
		t.Fatalf("clock skew hid current disable: %v %v", decision, err)
	}
}

// This fixture serves constructor discovery/token responses only; it makes no
// claim to qualify OIDC login. The live Keycloak lab owns that evidence.
func localStartupExternalConfig(t *testing.T) Config {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/.well-known/openid-configuration" {
			writeJSON(w, http.StatusOK, map[string]any{"issuer": server.URL + "/realms/test", "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/keys"})
		} else if r.URL.Path == "/token" {
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "constructor-test-token", "token_type": "Bearer", "expires_in": 3600})
		} else {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return Config{Issuer: server.URL + "/realms/test", ClientID: "console", ClientSecret: "console-secret", DirectoryClientID: "directory", DirectoryClientSecret: "directory-secret", PublicURL: localTestOrigin, HTTPClient: server.Client()}
}

func TestAuthenticationModeStartupPreservesOwnerLogin(t *testing.T) {
	t.Run("external owner cannot enter local primary", func(t *testing.T) {
		s, ctx, pool := localIntegrationService(t)
		external := localStartupExternalConfig(t)
		id := uuid.New()
		if err := s.withTx(ctx, func(q *identitydb.Queries) error {
			if _, err := q.UpsertPrincipal(ctx, identitydb.UpsertPrincipalParams{ID: id, Issuer: external.Issuer, Subject: id.String()}); err != nil {
				return err
			}
			if _, err := q.PinOwnerRole(ctx, id); err != nil {
				return err
			}
			_, err := q.MarkDeploymentInitialized(ctx, &id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := New(ctx, pool, Config{Local: true, PublicURL: localTestOrigin}); !errors.Is(err, errOwnerAuthenticationMode) {
			t.Fatalf("stranded external owner accepted in local primary: %v", err)
		}
		service, err := New(ctx, pool, external)
		if err != nil {
			t.Fatalf("matching external owner rejected: %v", err)
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("local owner needs enrolled emergency designation", func(t *testing.T) {
		s, ctx, pool := localIntegrationService(t)
		enrollment, err := s.BootstrapLocalOwner(ctx, "owner")
		if err != nil {
			t.Fatal(err)
		}
		external := localStartupExternalConfig(t)
		if _, err := New(ctx, pool, external); !errors.Is(err, errOwnerAuthenticationMode) {
			t.Fatalf("local owner stranded without policy: %v", err)
		}
		external.BreakGlass = &configv1.BreakGlassPolicy{AllowedPermissions: []string{string(PermissionManageAccounts)}, MaxSessionLifetime: durationpb.New(time.Hour), RequireIncidentReason: true}
		if _, err := New(ctx, pool, external); !errors.Is(err, errOwnerAuthenticationMode) {
			t.Fatalf("undesignated local owner accepted: %v", err)
		}
		if _, err := pool.Exec(ctx, "UPDATE local_accounts SET break_glass=true WHERE id=$1", enrollment.AccountID); err != nil {
			t.Fatal(err)
		}
		if _, err := New(ctx, pool, external); !errors.Is(err, errOwnerAuthenticationMode) {
			t.Fatalf("unenrolled emergency owner accepted: %v", err)
		}
		enrollLocal(t, s, ctx, enrollment, localAuthenticator(t))
		service, err := New(ctx, pool, external)
		if err != nil {
			t.Fatalf("enrolled emergency owner rejected: %v", err)
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", enrollment.AccountID); err != nil {
			t.Fatal(err)
		}
		if _, err := New(ctx, pool, external); !errors.Is(err, errOwnerAuthenticationMode) {
			t.Fatalf("disabled emergency owner accepted: %v", err)
		}
	})
}
