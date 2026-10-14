// SPDX-License-Identifier: Apache-2.0

package releaseupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/proto"
)

func TestPublisherRoleKeySeparation(t *testing.T) {
	keys := fixtureSigners(t)
	keys.Timestamp = keys.Targets
	if _, err := CreateRepository(context.Background(), PublisherConfig{Directory: filepath.Join(t.TempDir(), "repo"), Signers: keys}); err == nil {
		t.Fatal("one key authorized for multiple roles")
	}
	f := newRepositoryFixture(t)
	cfg := f.publisher.cfg
	cfg.Signers.Root = nil
	publisher, err := NewPublisher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publisher.SetRollout(context.Background(), "stable", true, 10); err != nil {
		t.Fatalf("online publisher required offline root key: %v", err)
	}
	cfg.Signers.Targets = fixtureSigners(t).Targets
	before := mustRead(t, filepath.Join(f.directory, "metadata/timestamp.json"))
	if _, err = NewPublisher(cfg); err == nil {
		t.Fatal("unauthorized role signer accepted")
	}
	if !bytes.Equal(before, mustRead(t, filepath.Join(f.directory, "metadata/timestamp.json"))) {
		t.Fatal("failed publication changed commit point")
	}
}

func TestRolloutIntentCompareAndReplay(t *testing.T) {
	f := newRepositoryFixture(t)
	result, err := f.publisher.SetRolloutRequest(context.Background(), "stable", true, 12, 1, "owned-request")
	if err != nil {
		t.Fatal(err)
	}
	if result.GetGeneration() != 2 || result.GetRolloutRequestId() != "owned-request" {
		t.Fatal("intent not signed")
	}
	before := mustRead(t, filepath.Join(f.directory, "metadata/timestamp.json"))
	replay, err := f.publisher.SetRolloutRequest(context.Background(), "stable", true, 12, 1, "owned-request")
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(replay, result) {
		t.Fatal("retry changed signed intent")
	}
	if !bytes.Equal(before, mustRead(t, filepath.Join(f.directory, "metadata/timestamp.json"))) {
		t.Fatal("retry republished metadata")
	}
	if _, err = f.publisher.SetRolloutRequest(context.Background(), "stable", true, 12, 1, "foreign-request"); err == nil {
		t.Fatal("stale concurrent intent accepted")
	}
	if _, err = f.publisher.SetRolloutRequest(context.Background(), "stable", false, 12, 1, "owned-request"); err == nil {
		t.Fatal("request identity rebound to other payload")
	}
}

func TestPublisherInterruptedGenerationRecovery(t *testing.T) {
	f := newRepositoryFixture(t)
	// A durable immutable targets write followed by a crash before timestamp is
	// indistinguishable from this orphan. Never overwrite or expose it as current.
	mustWrite(t, filepath.Join(f.directory, "metadata/3.targets.json"), []byte("orphaned incomplete publication"))
	restarted, err := NewPublisher(f.publisher.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.SetRollout(context.Background(), "stable", false, 100); err != nil {
		t.Fatal(err)
	}
	timestamp, err := metadata.Timestamp().FromBytes(mustRead(t, filepath.Join(f.directory, "metadata/timestamp.json")))
	if err != nil {
		t.Fatal(err)
	}
	if timestamp.Signed.Version != 4 {
		t.Fatalf("new immutable generation %d", timestamp.Signed.Version)
	}
	if string(mustRead(t, filepath.Join(f.directory, "metadata/3.targets.json"))) != "orphaned incomplete publication" {
		t.Fatal("orphaned immutable version overwritten")
	}
	if _, err = f.client(t, "", nil).Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
}

func TestPublisherInterruptedRootAliasRecovery(t *testing.T) {
	f := newRepositoryFixture(t)
	next := fixtureSigners(t)
	if err := f.publisher.RotateRoot(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	// Restore only the convenience alias to model a crash just before its rename.
	mustWrite(t, filepath.Join(f.directory, "metadata/root.json"), f.root)
	restarted, err := NewPublisher(PublisherConfig{Directory: f.directory, Signers: next, Now: f.publisher.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.SetRollout(context.Background(), "stable", false, 100); err != nil {
		t.Fatal(err)
	}
	if _, err = f.client(t, "", nil).Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyRepositoryHandler(t *testing.T) {
	f := newRepositoryFixture(t)
	handler, err := NewRepositoryHandler(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(f.directory, "private.pem"), []byte("private"))
	if err = os.Symlink(filepath.Join(f.directory, "private.pem"), filepath.Join(f.directory, "metadata/99.root.json")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/", "/metadata/", "/private.pem", "/metadata/../private.pem", "/metadata/%2e%2e/private.pem", "/metadata/99.root.json", "/targets/.import-secret", "/metadata/timestamp.json?private=1"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", target, recorder.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, "/metadata/timestamp.json", nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s allowed", method)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, "/metadata/timestamp.json", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s failed %d", method, recorder.Code)
		}
	}
}

func TestMirrorUsesSameVerificationAndStreamingBoundary(t *testing.T) {
	f := newRepositoryFixture(t)
	if err := f.publisher.RotateRoot(context.Background(), fixtureSigners(t)); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "mirror")
	open := func(ctx context.Context, name string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return os.Open(filepath.Join(f.directory, filepath.FromSlash(name)))
	}
	cfg := MirrorConfig{Directory: directory, BootstrapRoot: f.root, Fetch: DirectoryFetch(f.directory), OpenTarget: open}
	if err := Mirror(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	client := f.client(t, "", DirectoryFetch(directory))
	selection, err := client.Select(context.Background(), fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(directory, selection.TargetPath)), f.payload) {
		t.Fatal("mirror target differs")
	}
	if _, err = os.Stat(filepath.Join(directory, "metadata/1.root.json")); err != nil {
		t.Fatal("mirror lost bootstrap rotation chain", err)
	}
	before := mustRead(t, filepath.Join(directory, "metadata/timestamp.json"))
	if _, err = f.publisher.SetRollout(context.Background(), "stable", false, 100); err != nil {
		t.Fatal(err)
	}
	cfg.OpenTarget = func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte("corrupt mirror transfer"))), nil
	}
	if err = Mirror(context.Background(), cfg); err == nil {
		t.Fatal("mirror accepted target corruption")
	}
	if !bytes.Equal(before, mustRead(t, filepath.Join(directory, "metadata/timestamp.json"))) {
		t.Fatal("failed mirror exposed partial generation")
	}
}

func TestTargetSourceSymlinkAndCatalogGenerationRejected(t *testing.T) {
	f := newRepositoryFixture(t)
	channel := proto.CloneOf(f.channel)
	if err := f.publisher.Publish(context.Background(), channel, nil); err == nil {
		t.Fatal("duplicate channel generation accepted")
	}
	channel.Generation = 2
	source := filepath.Join(t.TempDir(), "source")
	mustWrite(t, source, f.payload)
	link := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := f.publisher.Publish(context.Background(), channel, map[string]string{channel.Artifacts[0].TargetPath: link}); err == nil {
		t.Fatal("symlink publication source accepted")
	}
	if _, err := f.publisher.Channel(context.Background(), "../metadata"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("traversal not rejected")
	}
}

func TestRootQuorumAndHandlerDirectorySymlinks(t *testing.T) {
	keys := fixtureSigners(t)
	keys.Root = append(keys.Root, fixtureSigners(t).Root...)
	directory := filepath.Join(t.TempDir(), "repository")
	publisher, err := CreateRepository(context.Background(), PublisherConfig{Directory: directory, Signers: keys})
	if err != nil {
		t.Fatal(err)
	}
	root, err := publisher.root()
	if err != nil {
		t.Fatal(err)
	}
	if root.Signed.Roles["root"].Threshold != 2 {
		t.Fatal("root quorum was not preserved")
	}
	root.Signatures = root.Signatures[:1]
	incomplete, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewClient(ClientConfig{StateDir: filepath.Join(t.TempDir(), "state"), BootstrapRoot: incomplete, Fetch: DirectoryFetch(directory)}); err == nil {
		t.Fatal("incomplete bootstrap quorum accepted")
	}
	link := filepath.Join(t.TempDir(), "repository-link")
	if err = os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if _, err = NewRepositoryHandler(link); err == nil {
		t.Fatal("symlink repository root accepted")
	}
}

func TestDevelopmentKeysNeverOverwriteAndStaySeparate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "development-custody")
	if err := GenerateDevelopmentKeys(directory); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadRoleSigners(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CreateRepository(context.Background(), PublisherConfig{Directory: filepath.Join(t.TempDir(), "repository"), Signers: keys}); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, filepath.Join(directory, "root.pem"))
	if err = GenerateDevelopmentKeys(directory); err == nil {
		t.Fatal("development generation replaced existing custody")
	}
	if !bytes.Equal(before, mustRead(t, filepath.Join(directory, "root.pem"))) {
		t.Fatal("existing root key changed")
	}
	if err = os.Chmod(filepath.Join(directory, "timestamp.pem"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadRoleSigners(directory, false); err == nil {
		t.Fatal("public-readable online private key accepted")
	}
}
