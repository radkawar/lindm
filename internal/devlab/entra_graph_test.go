package devlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const entraTestPrefix = "lindm-entra-check-6a8a9b65-0d4c-49d1-85f9-c6e3d3272bf1"
const entraTestID = "ac340398-b70b-4626-a694-d0cbe67c3ce8"

// A shortened prefix must never become a tenant-wide destructive selector.
func TestEntraOwnershipBoundary(t *testing.T) {
	for _, prefix := range []string{"", "lindm-entra-check-", strings.TrimSuffix(entraTestPrefix, "1"), entraTestPrefix + "-owner", strings.ToUpper(entraTestPrefix), "lindm-entra-check-00000000-0000-0000-0000-000000000000", "lindm-entra-check-6a8a9b65-0d4c-19d1-85f9-c6e3d3272bf1"} {
		if validEntraPrefix(prefix) {
			t.Errorf("accepted incomplete or non-random prefix %q", prefix)
		}
		if err := cleanupEntra(t.Context(), prefix); err == nil {
			t.Errorf("cleanup accepted invalid selector %q", prefix)
		}
	}
	if !validEntraPrefix(entraTestPrefix) {
		t.Fatal("valid UUIDv4 run prefix rejected")
	}
	for _, collection := range []string{"applications", "servicePrincipals", "users", "groups"} {
		t.Run(collection, func(t *testing.T) {
			name := entraNames(entraTestPrefix, collection)[0]
			owned := entraObject{ID: entraTestID, AppID: entraTestID, DisplayName: name, Description: entraTestPrefix, Department: entraTestPrefix, MailNickname: name, UserPrincipalName: name + "@example.onmicrosoft.com", Tags: []string{entraTestPrefix}, SecurityEnabled: true}
			if !entraOwns(entraTestPrefix, collection, owned) {
				t.Fatal("exact owned object rejected")
			}
			for _, change := range []struct {
				name  string
				apply func(*entraObject)
			}{
				{"suffix extension", func(o *entraObject) { o.DisplayName += "-unrelated" }},
				{"bare prefix", func(o *entraObject) { o.DisplayName = entraTestPrefix }},
				{"foreign run", func(o *entraObject) { o.DisplayName = strings.ReplaceAll(o.DisplayName, "6a8a9b65", "7a8a9b65") }},
				{"invalid ID", func(o *entraObject) { o.ID = "../other" }},
				{"missing markers", func(o *entraObject) { o.Description = ""; o.Department = ""; o.Tags = nil }},
			} {
				t.Run(change.name, func(t *testing.T) {
					candidate := owned
					change.apply(&candidate)
					if entraOwns(entraTestPrefix, collection, candidate) {
						t.Fatal("object outside ownership boundary accepted")
					}
				})
			}
			if collection == "users" {
				owned.UserPrincipalName = "unrelated@example.onmicrosoft.com"
				if entraOwns(entraTestPrefix, collection, owned) {
					t.Fatal("display-name lookalike with a foreign UPN accepted")
				}
			}
			if collection == "groups" {
				owned.IsAssignableToRole = true
				if entraOwns(entraTestPrefix, collection, owned) {
					t.Fatal("role-assignable group accepted as an ordinary fixture group")
				}
			}
		})
	}
}

func TestEntraPagingCredentialBoundary(t *testing.T) {
	base := entraGraphBase + "users/" + entraTestID + "/transitiveMemberOf/microsoft.graph.group"
	if !entraNext(base, base+"?$skiptoken=opaque") {
		t.Fatal("same-collection opaque page rejected")
	}
	for _, next := range []string{
		"https://attacker.invalid/v1.0/users/" + entraTestID + "?$skiptoken=x",
		strings.Replace(base, "https://", "http://", 1) + "?$skiptoken=x",
		strings.Replace(base, "graph.microsoft.com", "user@graph.microsoft.com", 1) + "?$skiptoken=x",
		base + "?x=1#fragment", base, base + "/other?x=1",
		strings.Replace(base, entraTestID, "other", 1) + "?$skiptoken=x",
		base + "?x=" + strings.Repeat("x", 8192),
	} {
		if entraNext(base, next) {
			t.Fatal("credential-bearing query could follow a foreign or unbounded page")
		}
	}
}

// Exercise the actual subprocess capture boundary: az can echo a secret-bearing
// request in stderr, and neither that output nor arbitrary Graph codes may escape.
func TestEntraSubprocessRedaction(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' 'ERROR: {\"error\":{\"code\":\"Authorization_RequestDenied\",\"message\":\"password=NEVER-PRINT-THIS token=ALSO-PRIVATE\"}}' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "az"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := entraAZ(t.Context(), "create test users", entraUserPermission, "rest")
	if err == nil {
		t.Fatal("permission denial was accepted")
	}
	message := err.Error()
	for _, wanted := range []string{"create test users", "Authorization_RequestDenied", "User.ReadWrite.All", "User Administrator", "not inferred"} {
		if !strings.Contains(message, wanted) {
			t.Errorf("missing actionable sanitized detail %q", wanted)
		}
	}
	for _, secret := range []string{"NEVER-PRINT-THIS", "ALSO-PRIVATE", "password=", "token="} {
		if strings.Contains(message, secret) {
			t.Fatal("subprocess error disclosed sensitive output")
		}
	}
	if got := entraErrorCode([]byte(`{"error":{"code":"SECRET-IN-CODE","message":"private"}}`)); got != "unavailable" {
		t.Fatal("unrecognized Graph code was echoed")
	}
}

func TestEntraBadRequestDoesNotClaimMissingRole(t *testing.T) {
	raw := []byte(`{"error":{"code":"Request_BadRequest","message":"The appId SECRET does not reference a valid application object"}}`)
	code := entraErrorCode(raw)
	if code != "Request_BadRequest:application_not_visible" {
		t.Fatalf("lost safe failure category: %s", code)
	}
	message := (&entraGraphError{"create servicePrincipals", code, entraAppPermission}).Error()
	if strings.Contains(message, "SECRET") || !strings.Contains(message, "does not establish a missing permission") {
		t.Fatalf("unsafe or misleading blocker: %s", message)
	}
}

// Cleanup must survive caller cancellation, re-check exact ownership immediately
// before DELETE, and refuse lookalikes even when discovery returned them.
func TestEntraCleanupCancellationAndOwnership(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "owned"
		if foreign {
			name = "foreign"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			groupName := entraTestPrefix + "-admins"
			object := entraObject{ID: entraTestID, DisplayName: groupName, Description: entraTestPrefix, MailNickname: groupName, SecurityEnabled: true}
			if foreign {
				object.Description = "someone else's resource"
			}
			encoded, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "object"), encoded, 0600); err != nil {
				t.Fatal(err)
			}
			// The fake exposes only one owned-ID read and empty discovery. It
			// records destructive actions, not command formatting or forwarding.
			script := `#!/bin/sh
method=
url=
while [ "$#" -gt 0 ]; do
 case "$1" in
  --method) shift; method="$1" ;;
  --url) shift; url="$1" ;;
 esac
 shift
done
if [ "$method" = DELETE ]; then
 printf '%s\n' "$url" >> "$ENTRA_FAKE_DIR/deleted"
 exit 0
fi
case "$url" in
 */groups/` + entraTestID + `\?*) cat "$ENTRA_FAKE_DIR/object" ;;
 *) printf '%s\n' '{"value":[]}' ;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "az"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENTRA_FAKE_DIR", dir)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			tenant := entraTenant{prefix: entraTestPrefix, graph: entraGraph{runDir: dir, subscription: entraTestID}, owned: []entraOwned{{Collection: "groups", ID: entraTestID}}}
			err = tenant.cleanup(ctx)
			deleted, readErr := os.ReadFile(filepath.Join(dir, "deleted"))
			if foreign {
				if err == nil || !os.IsNotExist(readErr) {
					t.Fatal("cleanup deleted a foreign exact-name lookalike or silently ignored ownership failure")
				}
			} else if err != nil || readErr != nil || string(deleted) != entraGraphBase+"groups/"+entraTestID+"\n" {
				t.Fatalf("cancelled cleanup failed to delete only the owned object: cleanup=%v read=%v", err, readErr)
			}
		})
	}
}

func TestEntraRedirectRejectsUnsafeOrigin(t *testing.T) {
	tenant := &entraTenant{}
	for _, origin := range []string{"http://localhost:1234", "https://example.com:1234", "https://localhost", "https://localhost:0", "https://localhost:65536", "https://localhost:1234/", "https://localhost:1234?", "https://localhost:1234?secret=x", "https://localhost:1234#fragment", "https://user@localhost:1234"} {
		if err := tenant.redirect(t.Context(), origin); err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Errorf("unsafe callback origin %q reached ownership/mutation boundary: %v", origin, err)
		}
	}
}

func TestEntraOAuthFailureRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: invalid client secret PRIVATE-SECRET correlation PRIVATE-ID"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), "POST", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = entraHTTP(server.Client(), request, "acquire directory app token")
	if err == nil {
		t.Fatal("OAuth failure accepted")
	}
	for _, wanted := range []string{"HTTP 401", "AADSTS7000215", "acquire directory app token"} {
		if !strings.Contains(err.Error(), wanted) {
			t.Errorf("sanitized OAuth blocker omitted %q", wanted)
		}
	}
	if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "correlation") {
		t.Fatal("OAuth error disclosed secret-bearing description")
	}
	for _, invalid := range []string{"AADSTS7000215secret", "AADSTS1234567890", "AADSTSsecret"} {
		if entraErrorCode([]byte(invalid)) != "unavailable" {
			t.Fatal("non-numeric or unbounded AADSTS diagnostic escaped")
		}
	}
}
