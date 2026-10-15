// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"lindm/internal/platform"
)

func TestPGDGKeyRequiresPinnedAuthorityAndBoundedHTTPS(t *testing.T) {
	key, err := openpgp.NewEntity("Synthetic repository", "", "fixture@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	writer, err := armor.Encode(&encoded, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/valid":
			_, _ = w.Write(encoded.Bytes())
		case "/large":
			_, _ = w.Write(bytes.Repeat([]byte("x"), (64<<10)+1))
		case "/redirect":
			http.Redirect(w, r, "/valid", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fingerprint := strings.ToUpper(hex.EncodeToString(key.PrimaryKey.Fingerprint))
	for _, test := range []struct {
		path, fingerprint string
		want              bool
	}{
		{"/valid", fingerprint, true},
		{"/valid", strings.Repeat("0", len(fingerprint)), false},
		{"/large", fingerprint, false},
		{"/redirect", fingerprint, false},
		{"/missing", fingerprint, false},
	} {
		t.Run(test.path+test.fingerprint, func(t *testing.T) {
			repository := &platform.PostgreSQLRepository{KeyURL: server.URL + test.path, KeyFingerprint: test.fingerprint}
			actual, err := fetchPGDGKey(t.Context(), client, repository)
			if (err == nil) != test.want || (test.want && !bytes.Equal(actual, encoded.Bytes())) {
				t.Fatalf("authority admission = %v, want success %t", err, test.want)
			}
		})
	}
	if _, err := fetchPGDGKey(t.Context(), client, &platform.PostgreSQLRepository{KeyURL: "http://example.test/key"}); err == nil {
		t.Fatal("accepted unauthenticated key transport")
	}
}

func TestPGDGSourceScopesTrustAndVersionedPackages(t *testing.T) {
	for _, key := range []string{"ubuntu-22.04", "debian-12"} {
		release, _ := platform.Lookup(key)
		repository := release.Server.PostgreSQLRepository
		source := string(pgdgSource(repository))
		if !strings.Contains(source, "Signed-By: "+pgdgKeyPath+" "+repository.KeyFingerprint+"\n") ||
			!strings.Contains(source, "Suites: "+release.Codename+"-pgdg\n") || strings.Contains(source, "trusted.gpg") {
			t.Fatalf("unscoped repository authority: %s", source)
		}
		for _, name := range release.Server.RequiredPackages {
			if name == "postgresql" || name == "postgresql-client" {
				t.Fatal("PGDG metapackage would track the latest major")
			}
		}
	}
}

func TestPGDGPublicationRefusesOperatorFilesAndSymlinks(t *testing.T) {
	root := rootDatabaseFixture(t)
	path := filepath.Join(root, "repository.sources")
	if err := publishRepositoryFile(path, []byte("scoped source\n")); err != nil {
		t.Fatal(err)
	}
	if err := publishRepositoryFile(path, []byte("scoped source\n")); err != nil {
		t.Fatalf("matching managed state refused: %v", err)
	}
	if err := publishRepositoryFile(path, []byte("different source\n")); err == nil {
		t.Fatal("replaced operator configuration")
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := publishRepositoryFile(alias, []byte("scoped source\n")); err == nil {
		t.Fatal("followed replaceable repository symlink")
	}
}
