package offlinebundle

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestOpenStagesOnlySignedBytes(t *testing.T) {
	authority := newTestAuthority(t)
	now := time.Now().UTC()
	directory := writeTestBundle(t, authority, 3, now.Add(-time.Hour), 24*time.Hour)
	bundle, err := Open(t.Context(), directory, authority.verifier, now)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Manifest.GetSequence() != 3 {
		t.Fatalf("sequence %d", bundle.Manifest.GetSequence())
	}
	if err := bundle.VerifyFiles(t.Context()); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "staged")
	staged, err := bundle.Stage(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range testLayout {
		data, err := os.ReadFile(staged.Path(name))
		if err != nil || string(data) != content {
			t.Fatalf("staged %s = %q, %v", name, data, err)
		}
		info, err := os.Stat(staged.Path(name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("staged %s is not private: %v %v", name, info.Mode(), err)
		}
	}
	if _, err := os.Stat(filepath.Join(destination, ManifestName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staging copied the unlisted manifest into the publication tree")
	}
}

func TestOpenRejectsUnauthenticatedOrStaleBundles(t *testing.T) {
	authority := newTestAuthority(t)
	other := newTestAuthority(t)
	now := time.Now().UTC()
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, directory string)
		key    *Verifier
		at     time.Time
		want   error
		text   string
	}{
		{name: "expired", at: now.Add(48 * time.Hour), want: ErrExpired},
		{name: "future creation", at: now.Add(-2 * time.Hour), want: ErrNotYetValid},
		{name: "foreign key", key: other.verifier, text: "signature rejected"},
		{name: "manifest edit", mutate: func(t *testing.T, directory string) {
			path := filepath.Join(directory, ManifestName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := regexp.MustCompile(`("sequence":\s*")3"`).ReplaceAll(data, []byte(`${1}4"`))
			if bytes.Equal(changed, data) {
				t.Fatal("fixture manifest has no sequence to edit")
			}
			if err := os.WriteFile(path, changed, 0644); err != nil {
				t.Fatal(err)
			}
		}, text: "differs from its signed payload"},
		{name: "unlisted file", mutate: func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "repositories", "extra"), []byte("x"), 0644); err != nil {
				t.Fatal(err)
			}
		}, want: ErrCorrupt},
		{name: "missing file", mutate: func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, "advisories", "fedora44")); err != nil {
				t.Fatal(err)
			}
		}, want: ErrCorrupt},
		{name: "size change", mutate: func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "advisories", "fedora44"), []byte("<updates/>"), 0644); err != nil {
				t.Fatal(err)
			}
		}, want: ErrCorrupt},
		{name: "symlink", mutate: func(t *testing.T, directory string) {
			path := filepath.Join(directory, "repositories", "amd64", "apt", "pool", "main", "l", "agent.deb")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(directory, "advisories", "fedora44"), path); err != nil {
				t.Fatal(err)
			}
		}, want: ErrCorrupt},
	} {
		t.Run(test.name, func(t *testing.T) {
			created := now.Add(-time.Hour)
			if test.name == "future creation" {
				created = now
			}
			directory := writeTestBundle(t, authority, 3, created, 24*time.Hour)
			if test.mutate != nil {
				test.mutate(t, directory)
			}
			key := authority.verifier
			if test.key != nil {
				key = test.key
			}
			at := now
			if !test.at.IsZero() {
				at = test.at
			}
			_, err := Open(t.Context(), directory, key, at)
			if err == nil {
				t.Fatal("bundle accepted")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error %v, want %v", err, test.want)
			}
			if test.text != "" && !strings.Contains(err.Error(), test.text) {
				t.Fatalf("error %v, want %q", err, test.text)
			}
		})
	}
}

func TestStageRejectsSameSizeTamperingAndLeavesNoCopy(t *testing.T) {
	authority := newTestAuthority(t)
	now := time.Now().UTC()
	directory := writeTestBundle(t, authority, 1, now.Add(-time.Minute), time.Hour)
	bundle, err := Open(t.Context(), directory, authority.verifier, now)
	if err != nil {
		t.Fatal(err)
	}
	// Opened bundles are not trusted in place: a same-size change after Open
	// must be caught while copying.
	path := filepath.Join(directory, "repositories", "amd64", "apt", "pool", "main", "l", "agent.deb")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyFiles(t.Context()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("in-place verification: %v", err)
	}
	destination := filepath.Join(t.TempDir(), "staged")
	if _, err := bundle.Stage(t.Context(), destination); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("stage: %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed staging left a partial copy")
	}
}

func TestSigningKeyCustody(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "key")
	id, err := GenerateDevelopmentKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(directory, "bundle.pem")
	if _, err := loadSigningKey(SigningKey{Path: key, KeyID: id, Custody: "production"}); err == nil {
		t.Fatal("development key accepted as production custody")
	}
	if _, err := loadSigningKey(SigningKey{Path: key, KeyID: strings.Repeat("0", 64), Custody: "development"}); err == nil {
		t.Fatal("unpinned key accepted")
	}
	if err := os.Chmod(key, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigningKey(SigningKey{Path: key, KeyID: id, Custody: "development"}); err == nil {
		t.Fatal("group-readable key accepted")
	}
	if _, err := LoadVerifier(filepath.Join(directory, "bundle.pub"), strings.Repeat("a", 64)); err == nil {
		t.Fatal("public key accepted under a different pin")
	}
}

func TestRepositoryHandlerServesOnlyPublishedTrees(t *testing.T) {
	directory := t.TempDir()
	for name, content := range map[string]string{"repositories/amd64/apt/dists/stable/InRelease": "signed", "release/release.json": "{}", ".staging-1/bundle/x": "private", "private.key": "secret"} {
		path := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(directory, "private.key"), filepath.Join(directory, "repositories", "link")); err != nil {
		t.Fatal(err)
	}
	handler, err := NewRepositoryHandler(directory)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.StripPrefix("/offline/", handler))
	defer server.Close()
	for path, want := range map[string]int{
		"/offline/repositories/amd64/apt/dists/stable/InRelease":     http.StatusOK,
		"/offline/release/release.json":                              http.StatusOK,
		"/offline/repositories/link":                                 http.StatusNotFound,
		"/offline/.staging-1/bundle/x":                               http.StatusNotFound,
		"/offline/private.key":                                       http.StatusNotFound,
		"/offline/repositories/amd64/":                               http.StatusNotFound,
		"/offline/repositories/amd64/apt/dists/stable/InRelease?x=1": http.StatusNotFound,
	} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s: status %d, want %d", path, response.StatusCode, want)
		}
	}
	response, err := http.Post(server.URL+"/offline/release/release.json", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d", response.StatusCode)
	}
}
