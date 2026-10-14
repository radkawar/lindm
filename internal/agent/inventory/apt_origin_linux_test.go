// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/sys/unix"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

var aptFixtureTime = time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)

// aptFixture returns sources over a private lists directory holding files and
// a keyring directory holding keys. A nil files map means no lists directory.
func aptFixture(t *testing.T, files map[string][]byte, keys ...*openpgp.Entity) aptSources {
	t.Helper()
	root := t.TempDir()
	lists := filepath.Join(root, "lists")
	if files != nil {
		if err := os.Mkdir(lists, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(lists, "partial"), 0o700); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(lists, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	trusted := filepath.Join(root, "trusted.gpg.d")
	if err := os.Mkdir(trusted, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, key := range keys {
		var buf bytes.Buffer
		if err := key.Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(trusted, fmt.Sprintf("key-%d.gpg", i)), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Fixtures are owned by the test user; the leaf rule keeps custody's
	// write-permission check, and the root-ancestry walk is native-only.
	return aptSources{
		lists:    lists,
		keyrings: []aptKeyring{{dir: root, only: "missing.gpg"}, {dir: trusted}},
		now:      func() time.Time { return aptFixtureTime },
		openDir: func(path string) (*os.File, error) {
			return os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		},
		protected: func(stat *unix.Stat_t) bool { return stat.Mode&0o022 == 0 },
	}
}

func aptKey(t *testing.T, name string) *openpgp.Entity {
	t.Helper()
	key, err := openpgp.NewEntity(name, "", name+"@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return aptFixtureTime.Add(-time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func fingerprint(key *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(key.PrimaryKey.Fingerprint))
}

type aptIndex struct {
	path     string // Release-relative, e.g. main/binary-amd64/Packages
	packages [][3]string
	tamper   bool // stored bytes differ from the Release SHA256 entry
	gz       bool
}

func packagesFile(packages [][3]string) []byte {
	var b strings.Builder
	for _, p := range packages {
		fmt.Fprintf(&b, "Package: %s\nArchitecture: %s\nVersion: %s\nMaintainer: x <x@example.invalid>\nDescription: fixture\n long continuation line\n\n", p[0], p[2], p[1])
	}
	return []byte(b.String())
}

// addRelease writes one APT source as APT stores it: <prefix>_InRelease (or
// _Release + optional _Release.gpg) and <prefix>_<path with "/"→"_"> indexes.
func addRelease(t *testing.T, files map[string][]byte, prefix, fields string, signer *openpgp.Entity, clearsigned bool, indexes ...aptIndex) {
	t.Helper()
	var release strings.Builder
	release.WriteString(fields)
	release.WriteString("SHA256:\n")
	for _, index := range indexes {
		data := packagesFile(index.packages)
		name := index.path
		if index.gz {
			var buf bytes.Buffer
			w := gzip.NewWriter(&buf)
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			data = buf.Bytes()
			name += ".gz"
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&release, " %x %d %s\n", sum, len(data), name)
		if index.tamper {
			data = append(data, []byte("Package: injected\nVersion: 1\nArchitecture: amd64\n\n")...)
		}
		files[prefix+"_"+strings.ReplaceAll(name, "/", "_")] = data
	}
	text := []byte(release.String())
	switch {
	case signer == nil:
		files[prefix+"_Release"] = text
	case clearsigned:
		var out bytes.Buffer
		w, err := clearsign.Encode(&out, signer.PrivateKey, &packet.Config{Time: func() time.Time { return aptFixtureTime.Add(-time.Minute) }})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(text); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		files[prefix+"_InRelease"] = out.Bytes()
	default:
		var sig bytes.Buffer
		if err := openpgp.ArmoredDetachSign(&sig, signer, bytes.NewReader(text), &packet.Config{Time: func() time.Time { return aptFixtureTime.Add(-time.Minute) }}); err != nil {
			t.Fatal(err)
		}
		files[prefix+"_Release"] = text
		files[prefix+"_Release.gpg"] = sig.Bytes()
	}
}

func installed(entries ...[3]string) []*inventoryv1.Package {
	packages := make([]*inventoryv1.Package, len(entries))
	for i, e := range entries {
		packages[i] = &inventoryv1.Package{Name: e[0], Version: e[1], Architecture: e[2], Manager: "dpkg", SourceName: e[0], SourceVersion: e[1], Module: &inventoryv1.ModuleObservation{Status: unavailable}}
	}
	return packages
}

func listingString(l *inventoryv1.AptListing) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", l.GetOrigin(), l.GetLabel(), l.GetSuite(), l.GetCodename(), l.GetSignature(), l.GetSigner())
}

func originStrings(pkg *inventoryv1.Package) []string {
	var out []string
	for _, l := range pkg.GetOrigin().GetListings() {
		out = append(out, listingString(l))
	}
	return out
}

func TestAptOriginsMintLikeLists(t *testing.T) {
	ubuntu, mint, attacker := aptKey(t, "ubuntu-archive"), aptKey(t, "linuxmint"), aptKey(t, "attacker")
	files := map[string][]byte{}
	ubuntuFields := "Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble-updates\nCodename: noble\n"
	addRelease(t, files, "archive.ubuntu.com_ubuntu_dists_noble-updates", ubuntuFields, ubuntu, true,
		aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{{"libssl3t64", "3.0.13-0ubuntu3.5", "amd64"}, {"shared", "1.0", "amd64"}, {"tzdata", "2026a-0ubuntu0.24.04", "all"}}},
		aptIndex{path: "main/binary-i386/Packages", packages: [][3]string{{"libssl3t64", "3.0.13-0ubuntu3.5", "i386"}}})
	// Same version in the security pocket: two Ubuntu listings, one origin.
	addRelease(t, files, "security.ubuntu.com_ubuntu_dists_noble-security", strings.ReplaceAll(ubuntuFields, "noble-updates", "noble-security"), ubuntu, true,
		aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{{"libssl3t64", "3.0.13-0ubuntu3.5", "amd64"}}})
	// Mint publishes Release + detached Release.gpg (no InRelease).
	addRelease(t, files, "packages.linuxmint.com_dists_zena", "Origin: linuxmint\nLabel: linuxmint\nSuite: zena\nCodename: zena\n", mint, false,
		aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{{"mint-common", "2.3.1", "all"}, {"shared", "1.0", "amd64"}}})
	// An unsigned file repository claiming Ubuntu's identity.
	addRelease(t, files, "_srv_mirror_dists_noble", "Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble\nCodename: noble\n", nil, false,
		aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{{"unsigned-claim", "1.0", "amd64"}}})
	// A signature by a key absent from every APT keyring, claiming Ubuntu.
	addRelease(t, files, "evil.example_dists_noble", "Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble\nCodename: noble\n", attacker, true,
		aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{{"forged-claim", "1.0", "amd64"}}})
	// A verified Release whose index bytes do not match its SHA256 entry.
	addRelease(t, files, "mirror.example_ubuntu_dists_noble", "Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble\nCodename: noble\n", ubuntu, true,
		aptIndex{path: "universe/binary-amd64/Packages", packages: [][3]string{{"tampered", "1.0", "amd64"}}, tamper: true})
	sources := aptFixture(t, files, ubuntu, mint)
	packages := installed(
		[3]string{"libssl3t64", "3.0.13-0ubuntu3.5", "amd64"},
		[3]string{"libssl3t64", "3.0.13-0ubuntu3.5", "i386"},
		[3]string{"tzdata", "2026a-0ubuntu0.24.04", "all"},
		[3]string{"mint-common", "2.3.1", "all"},
		[3]string{"shared", "1.0", "amd64"},
		[3]string{"local-build", "0.1", "amd64"},
		[3]string{"libssl3t64-old", "3.0.13-0ubuntu3.4", "amd64"},
		[3]string{"unsigned-claim", "1.0", "amd64"},
		[3]string{"forged-claim", "1.0", "amd64"},
		[3]string{"tampered", "1.0", "amd64"},
	)
	attachAptOrigins(t.Context(), packages, sources, maxOutputBytes)
	u, m := fingerprint(ubuntu), fingerprint(mint)
	want := map[string][]string{
		"libssl3t64/amd64": {"Ubuntu|Ubuntu|noble-security|noble|APT_RELEASE_SIGNATURE_VERIFIED|" + u, "Ubuntu|Ubuntu|noble-updates|noble|APT_RELEASE_SIGNATURE_VERIFIED|" + u},
		"libssl3t64/i386":  {"Ubuntu|Ubuntu|noble-updates|noble|APT_RELEASE_SIGNATURE_VERIFIED|" + u},
		"tzdata/all":       {"Ubuntu|Ubuntu|noble-updates|noble|APT_RELEASE_SIGNATURE_VERIFIED|" + u},
		"mint-common/all":  {"linuxmint|linuxmint|zena|zena|APT_RELEASE_SIGNATURE_VERIFIED|" + m},
		// Listed by both archives: the server must see both, never one.
		"shared/amd64": {"Ubuntu|Ubuntu|noble-updates|noble|APT_RELEASE_SIGNATURE_VERIFIED|" + u, "linuxmint|linuxmint|zena|zena|APT_RELEASE_SIGNATURE_VERIFIED|" + m},
		// Local builds and superseded versions are listed nowhere.
		"local-build/amd64":    nil,
		"libssl3t64-old/amd64": nil,
		"unsigned-claim/amd64": {"Ubuntu|Ubuntu|noble|noble|APT_RELEASE_SIGNATURE_UNSIGNED|"},
		"forged-claim/amd64":   {"Ubuntu|Ubuntu|noble|noble|APT_RELEASE_SIGNATURE_UNVERIFIED|"},
		"tampered/amd64":       {"Ubuntu|Ubuntu|noble|noble|APT_RELEASE_SIGNATURE_UNVERIFIED|"},
	}
	for _, pkg := range packages {
		key := pkg.GetName() + "/" + pkg.GetArchitecture()
		if pkg.GetOrigin().GetStatus() != success {
			t.Fatalf("%s origin status = %s", key, pkg.GetOrigin().GetStatus())
		}
		got := originStrings(pkg)
		if strings.Join(got, "\n") != strings.Join(want[key], "\n") {
			t.Errorf("%s listings:\n got %q\nwant %q", key, got, want[key])
		}
		if err := protovalidate.Validate(pkg); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
	}
}

func TestAptOriginsPopLikeLists(t *testing.T) {
	ubuntu, pop := aptKey(t, "ubuntu-archive"), aptKey(t, "pop-os")
	files := map[string][]byte{}
	// Pop!_OS mirrors Ubuntu's signed archive under its own host and serves
	// its release repository with the same codename.
	addRelease(t, files, "apt.pop-os.org_ubuntu_dists_noble", "Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble\nCodename: noble\n", ubuntu, true,
		aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{{"bash", "5.2.21-2ubuntu4", "amd64"}}, gz: true})
	addRelease(t, files, "apt.pop-os.org_release_dists_noble", "Origin: pop-os-release\nLabel: Pop!_OS Release\nSuite: noble\nCodename: noble\n", pop, true,
		aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{{"pop-default-settings", "8.0.0~1727", "all"}, {"gnome-shell", "46.0-0ubuntu5pop1", "amd64"}}})
	sources := aptFixture(t, files, ubuntu, pop)
	packages := installed(
		[3]string{"bash", "5.2.21-2ubuntu4", "amd64"},
		[3]string{"pop-default-settings", "8.0.0~1727", "all"},
		[3]string{"gnome-shell", "46.0-0ubuntu5pop1", "amd64"},
	)
	attachAptOrigins(t.Context(), packages, sources, maxOutputBytes)
	u, p := fingerprint(ubuntu), fingerprint(pop)
	want := [][]string{
		{"Ubuntu|Ubuntu|noble|noble|APT_RELEASE_SIGNATURE_VERIFIED|" + u},
		{"pop-os-release|Pop!_OS Release|noble|noble|APT_RELEASE_SIGNATURE_VERIFIED|" + p},
		{"pop-os-release|Pop!_OS Release|noble|noble|APT_RELEASE_SIGNATURE_VERIFIED|" + p},
	}
	for i, pkg := range packages {
		if got := originStrings(pkg); strings.Join(got, "\n") != strings.Join(want[i], "\n") {
			t.Errorf("%s listings = %q, want %q", pkg.GetName(), got, want[i])
		}
	}
}

func TestAptOriginFailuresNeverPublishPartialListings(t *testing.T) {
	ubuntu := aptKey(t, "ubuntu-archive")
	pkg := [3]string{"bash", "5.2.21-2ubuntu4", "amd64"}
	t.Run("missing-lists", func(t *testing.T) {
		packages := installed(pkg)
		attachAptOrigins(t.Context(), packages, aptFixture(t, nil, ubuntu), maxOutputBytes)
		if got := packages[0].GetOrigin(); got.GetStatus() != unavailable || len(got.GetListings()) != 0 {
			t.Fatalf("origin = %v", got)
		}
	})
	t.Run("undecodable-index", func(t *testing.T) {
		files := map[string][]byte{}
		addRelease(t, files, "archive.ubuntu.com_ubuntu_dists_noble", "Origin: Ubuntu\nSuite: noble\nCodename: noble\n", ubuntu, true,
			aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{pkg}})
		files["archive.ubuntu.com_ubuntu_dists_noble_universe_binary-amd64_Packages.lz4"] = []byte("lz4")
		packages := installed(pkg)
		attachAptOrigins(t.Context(), packages, aptFixture(t, files, ubuntu), maxOutputBytes)
		if got := packages[0].GetOrigin(); got.GetStatus() != unavailable || len(got.GetListings()) != 0 {
			t.Fatalf("origin = %v", got)
		}
	})
	t.Run("writable-index", func(t *testing.T) {
		// An index anyone but its owner could rewrite is not native evidence.
		files := map[string][]byte{}
		addRelease(t, files, "archive.ubuntu.com_ubuntu_dists_noble", "Origin: Ubuntu\nSuite: noble\nCodename: noble\n", ubuntu, true,
			aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{pkg}})
		sources := aptFixture(t, files, ubuntu)
		if err := os.Chmod(filepath.Join(sources.lists, "archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages"), 0o666); err != nil {
			t.Fatal(err)
		}
		packages := installed(pkg)
		attachAptOrigins(t.Context(), packages, sources, maxOutputBytes)
		if got := packages[0].GetOrigin(); got.GetStatus() == success || len(got.GetListings()) != 0 {
			t.Fatalf("origin = %v", got)
		}
	})
	t.Run("output-budget", func(t *testing.T) {
		files := map[string][]byte{}
		addRelease(t, files, "archive.ubuntu.com_ubuntu_dists_noble", "Origin: Ubuntu\nSuite: noble\nCodename: noble\n", ubuntu, true,
			aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{pkg}})
		packages := installed(pkg)
		attachAptOrigins(t.Context(), packages, aptFixture(t, files, ubuntu), 1)
		if got := packages[0].GetOrigin(); got.GetStatus() != capacity || len(got.GetListings()) != 0 {
			t.Fatalf("origin = %v", got)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		files := map[string][]byte{}
		addRelease(t, files, "archive.ubuntu.com_ubuntu_dists_noble", "Origin: Ubuntu\nSuite: noble\nCodename: noble\n", ubuntu, true,
			aptIndex{path: "main/binary-amd64/Packages", packages: [][3]string{pkg}})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		packages := installed(pkg)
		attachAptOrigins(ctx, packages, aptFixture(t, files, ubuntu), maxOutputBytes)
		if got := packages[0].GetOrigin(); got.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT || len(got.GetListings()) != 0 {
			t.Fatalf("origin = %v", got)
		}
	})
}
