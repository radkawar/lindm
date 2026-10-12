//go:build integration

package devlab

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/advisory"
	"lindm/internal/config"
	"lindm/internal/platform"
	"lindm/internal/testdb"
)

func heldOSVServer(t *testing.T) (*httptest.Server, *configv1.AdvisoryConfig, *atomic.Int32) {
	t.Helper()
	raw, err := os.ReadFile("../advisory/feed/testdata/ubuntu-USN-6859-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("USN-6859-1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	bodies := new(atomic.Int32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"osv-export"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		bodies.Add(1)
		w.Header().Set("ETag", `"osv-export"`)
		_, _ = w.Write(archive.Bytes())
	}))
	t.Cleanup(server.Close)
	release, _ := platform.Lookup("ubuntu-24.04")
	cfg, err := HeldAdvisories(*release, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Feeds[0].Url = server.URL + "/all.zip"
	return server, cfg, bodies
}

func TestHeldAdvisoryRefreshPublishesAndRevalidates(t *testing.T) {
	pool, _ := testdb.Open(t)
	server, cfg, bodies := heldOSVServer(t)
	cacheDir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for range 2 {
		if err := refreshHeldAdvisories(ctx, pool, cfg, server.Client(), cacheDir); err != nil {
			t.Fatal(err)
		}
	}
	if bodies.Load() != 1 {
		t.Fatalf("second production refresh transferred a body: %d", bodies.Load())
	}
	service, err := advisory.New(ctx, pool, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	feeds, err := service.Feeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The parser deliberately does not grant complete-ecosystem coverage to
	// a loopback URL. This verifies acquisition/publication, not vendor coverage.
	if len(feeds.GetFeeds()) != 1 || feeds.Feeds[0].GetCheckedAt() == nil || feeds.Feeds[0].GetAdvisoryCount() == 0 || feeds.Feeds[0].GetError() != "" || feeds.Feeds[0].GetFresh() {
		t.Fatalf("refresh did not publish records with bounded authority: %v", feeds)
	}
}

func TestEnableAdvisoriesRestartsOnlyServerWithPublishedConfig(t *testing.T) {
	binary, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	fixture, err := OpenDeviceActionAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	server, cfg, bodies := heldOSVServer(t)
	document, err := config.Load(fixture.configPath())
	if err != nil {
		t.Fatal(err)
	}
	// Trust only this fake vendor in addition to the fixture's existing roots.
	roots, err := os.ReadFile(document.Proto.GetTrustedCaFile())
	if err != nil {
		t.Fatal(err)
	}
	roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})...)
	rootPath := filepath.Join(t.TempDir(), "vendor-ca.pem")
	if err := os.WriteFile(rootPath, roots, 0600); err != nil {
		t.Fatal(err)
	}
	document.Proto.TrustedCaFile = rootPath
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.writeConfig(encoded); err != nil {
		t.Fatal(err)
	}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	pid, database := fixture.processPID.Load(), fixture.DatabaseName
	cacheDir := t.TempDir()
	if err := fixture.EnableAdvisories(ctx, cfg, cacheDir); err != nil {
		t.Fatal(err)
	}
	if fixture.processPID.Load() == pid || fixture.processPID.Load() == 0 || fixture.DatabaseName != database {
		t.Fatal("enabling advisories did not restart only lindmd on the same database")
	}
	persisted, err := config.Load(fixture.configPath())
	if err != nil {
		t.Fatal(err)
	}
	// The persisted feeds equal the refreshed ones (with the cached-download idle
	// bound), so the restarted server keeps the held publication below.
	if !proto.Equal(persisted.Proto.GetAdvisories(), cachedRefreshConfig(cfg, heldAdvisoryDuration)) {
		t.Fatal("restarted config differs from the refreshed advisory feeds")
	}
	feeds, err := owner.Admin.ListAdvisoryFeeds(ctx, connect.NewRequest(&adminv1.ListAdvisoryFeedsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(feeds.Msg.GetFeeds()) != 1 || feeds.Msg.Feeds[0].GetCheckedAt() == nil || feeds.Msg.Feeds[0].GetAdvisoryCount() == 0 || feeds.Msg.Feeds[0].GetError() != "" {
		t.Fatalf("restarted lindmd lost published records: %v", feeds.Msg)
	}
	pid = fixture.processPID.Load()
	if err := fixture.EnableAdvisories(ctx, cfg, cacheDir); err != nil {
		t.Fatal(err)
	}
	unchanged, err := owner.Admin.ListAdvisoryFeeds(ctx, connect.NewRequest(&adminv1.ListAdvisoryFeedsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if fixture.processPID.Load() != pid || len(unchanged.Msg.GetFeeds()) != 1 || !proto.Equal(unchanged.Msg.Feeds[0].GetCheckedAt(), feeds.Msg.Feeds[0].GetCheckedAt()) {
		t.Fatal("unchanged advisory configuration restarted lindmd or republished its existing feed")
	}
	if bodies.Load() != 1 {
		t.Fatalf("restart repeated the vendor body download: %d", bodies.Load())
	}
}
