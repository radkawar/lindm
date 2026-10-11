package redhatimages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

// Test traffic reaches a real TLS server through the normal HTTP transport. Only
// destination routing changes; production origin/header policy runs unchanged.
type fixtureTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (f fixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	u := *request.URL
	copy.Host = request.URL.Host
	u.Scheme, u.Host = f.target.Scheme, f.target.Host
	copy.URL = &u
	return f.base.RoundTrip(copy)
}

type acquisitionFixture struct {
	mu            sync.Mutex
	calls         []string
	badAuth       bool
	redirect      string
	cdnRedirect   bool
	wrongHash     bool
	wrongSize     bool
	duplicate     bool
	noEntitlement bool
}

func fixtureClient(t *testing.T, f *acquisitionFixture) (*Client, string) {
	t.Helper()
	payload := []byte("official fixture qcow bytes")
	digest := sha256.Sum256(payload)
	hexDigest := hex.EncodeToString(digest[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.Host+r.URL.Path)
		bearer := r.Header.Get("Authorization")
		if r.Host == "api.access.redhat.com" {
			f.badAuth = f.badAuth || bearer != "Bearer access-secret"
		} else {
			f.badAuth = f.badAuth || bearer != ""
		}
		if r.Host == "sso.redhat.com" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if r.Form.Get("refresh_token") != "offline-secret" || r.Form.Get("client_id") != "rhsm-api" || r.Form.Get("grant_type") != "refresh_token" {
				t.Error("incorrect refresh-grant body")
			}
			if f.redirect != "" {
				w.Header().Set("Location", f.redirect)
				w.WriteHeader(307)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"access-secret","token_type":"bearer","expires_in":900}`)
			return
		}
		if strings.Contains(r.URL.Path, "/images/rhel/") {
			href := apiOrigin + "/management/v1/images/" + hexDigest + "/download"
			if f.noEntitlement {
				href = ""
			}
			row := map[string]string{"filename": "rhel-9.8-x86_64-kvm.qcow2", "checksum": hexDigest, "arch": "x86_64", "datePublished": "2026-05-12T14:26:31Z", "downloadHref": href}
			rows := []map[string]string{row}
			if f.duplicate {
				rows = append(rows, row)
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"body": rows}); err != nil {
				t.Error(err)
			}
			return
		}
		if r.Host == "api.access.redhat.com" {
			href := "https://access.cdn.redhat.com/content/origin/files/sha256/ab/image.qcow2?_auth_=signed-secret"
			if f.redirect != "" {
				href = f.redirect
			}
			w.Header().Set("Location", href)
			w.WriteHeader(307)
			if err := json.NewEncoder(w).Encode(map[string]any{"body": map[string]string{"filename": "rhel-9.8-x86_64-kvm.qcow2", "href": href}}); err != nil {
				t.Error(err)
			}
			return
		}
		if f.cdnRedirect {
			w.Header().Set("Location", "https://evil.example/leak?signed-secret")
			w.WriteHeader(307)
			return
		}
		data := payload
		if f.wrongHash {
			data = []byte(strings.Repeat("x", len(payload)))
		}
		size := len(data)
		if f.wrongSize && r.Method == http.MethodHead {
			size++
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(new(labv1.VendorImageReceipt)))
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{http: &http.Client{Transport: fixtureTransport{target: u, base: server.Client().Transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, now: func() time.Time { return time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC) }, validator: validator}
	t.Cleanup(client.Close)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("offline-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return client, token
}

func TestAcquisitionTLSAndPrivateReceipt(t *testing.T) {
	fixture := new(acquisitionFixture)
	client, token := fixtureClient(t, fixture)
	ctx := context.Background()
	if err := client.authenticate(ctx, token); err != nil {
		t.Fatal(err)
	}
	image, err := client.Discover(ctx, "9.8", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	path, receipt, err := client.Download(ctx, image, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || uint64(info.Size()) != receipt.ImageSizeBytes {
		t.Fatal("staged image mode or size mismatch")
	}
	serialized, err := protojson.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"offline-secret", "access-secret", "signed-secret", "access.cdn.redhat.com"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("receipt leaks %s", secret)
		}
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.badAuth || len(fixture.calls) != 5 {
		t.Fatalf("credential isolation or request sequence failed: bad auth=%v, calls=%d", fixture.badAuth, len(fixture.calls))
	}
}

func TestAcquisitionRejectsIntegrityAndDestinationChanges(t *testing.T) {
	for _, name := range []string{"digest", "size", "signed-url-host", "signed-url-http", "cdn-redirect", "no-entitlement", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			fixture := new(acquisitionFixture)
			client, token := fixtureClient(t, fixture)
			ctx := context.Background()
			if err := client.authenticate(ctx, token); err != nil {
				t.Fatal(err)
			}
			fixture.mu.Lock()
			switch name {
			case "digest":
				fixture.wrongHash = true
			case "size":
				fixture.wrongSize = true
			case "signed-url-host":
				fixture.redirect = "https://evil.example/path?signed-secret"
			case "signed-url-http":
				fixture.redirect = "http://access.cdn.redhat.com/content/origin/files/sha256/ab/image?signed-secret"
			case "cdn-redirect":
				fixture.cdnRedirect = true
			case "no-entitlement":
				fixture.noEntitlement = true
			case "duplicate":
				fixture.duplicate = true
			}
			fixture.mu.Unlock()
			image, err := client.Discover(ctx, "9.8", "x86_64")
			dir := t.TempDir()
			if err == nil {
				_, _, err = client.Download(ctx, image, dir)
			}
			if err == nil {
				t.Fatal("unsafe acquisition accepted")
			}
			if strings.Contains(err.Error(), "signed-secret") || strings.Contains(err.Error(), "offline-secret") || strings.Contains(err.Error(), "access-secret") {
				t.Fatal("error leaks credentials")
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatal("partial acquisition survived failure")
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if fixture.badAuth {
				t.Fatal("API credential leaked to CDN")
			}
			for _, call := range fixture.calls {
				if strings.Contains(call, "evil.example") {
					t.Fatal("followed unauthorized redirect")
				}
			}
		})
	}
}

func TestAuthenticationNeverFollowsRedirect(t *testing.T) {
	fixture := &acquisitionFixture{redirect: "https://evil.example/steal"}
	client, token := fixtureClient(t, fixture)
	if err := client.authenticate(context.Background(), token); err == nil {
		t.Fatal("authentication redirect accepted")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.calls) != 1 {
		t.Fatal("offline refresh body followed redirect")
	}
}

func TestTokenRequiresPrivateRegularOwnedFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(file); err == nil {
		t.Fatal("world-readable token accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(link); err == nil {
		t.Fatal("symlink token accepted")
	}
	if _, err := readToken(dir); err == nil {
		t.Fatal("directory token accepted")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(file, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if _, err := readToken(file); err == nil {
			t.Fatal("foreign-owned token accepted")
		}
	}
}

func TestMalformedVersionCannotChangeAPIDestination(t *testing.T) {
	client, _ := fixtureClient(t, new(acquisitionFixture))
	for _, version := range []string{"9.8/../../systems", "9.8?token=secret", "9.08", "11.0", "latest", "9.-1"} {
		if _, err := client.Discover(context.Background(), version, "x86_64"); err == nil {
			t.Fatalf("accepted %q", version)
		}
	}
	for _, architecture := range []string{"", "arm64", "x86_64/../../systems", "s390x"} {
		if _, err := client.Discover(context.Background(), "9.8", architecture); err == nil {
			t.Fatalf("accepted architecture %q", architecture)
		}
	}
}
