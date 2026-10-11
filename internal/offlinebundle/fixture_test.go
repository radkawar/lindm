package offlinebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	bundlev1 "lindm/gen/lindm/bundle/v1"
)

type testAuthority struct {
	signer   *bundleSigner
	verifier *Verifier
	keyDir   string
}

func newTestAuthority(t *testing.T) *testAuthority {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "key")
	id, err := GenerateDevelopmentKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigningKey(SigningKey{Path: filepath.Join(directory, "bundle.pem"), KeyID: id, Custody: "development"})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := LoadVerifier(filepath.Join(directory, "bundle.pub"), id)
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthority{signer: signer, verifier: verifier, keyDir: directory}
}

// layout files satisfying checkLayout; content is arbitrary because Open and
// Stage authenticate bytes, not their semantics.
var testLayout = map[string]string{
	"release/release.json":                          `{"version":"0.1.0"}`,
	"release/release.json.dsse":                     `{}`,
	"updates/metadata/1.root.json":                  `{"signed":{}}`,
	"updates/metadata/2.targets.json":               `{"signed":{}}`,
	"updates/channels/stable.json":                  `{"ring":"stable"}`,
	"repositories/amd64/apt/dists/stable/InRelease": "-----BEGIN PGP SIGNED MESSAGE-----\nOrigin: lindm\n",
	"repositories/amd64/apt/pool/main/l/agent.deb":  "deb payload bytes",
	"advisories/fedora44":                           "<updates></updates>",
}

func writeTestBundle(t *testing.T, authority *testAuthority, sequence uint64, created time.Time, validity time.Duration) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "bundle")
	for name, content := range testLayout {
		path := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := &bundlev1.OfflineBundleManifest{
		BundleId: uuid.NewString(), Sequence: sequence, SigningKeyId: authority.signer.id, Custody: "development",
		CreatedAt: timestamppb.New(created), ExpiresAt: timestamppb.New(created.Add(validity)),
		Release:      &bundlev1.BundleRelease{Version: "0.1.0", ManifestSha256: digestOf(testLayout["release/release.json"]), AttestationKeyId: authority.signer.id, ArtifactCount: 1},
		Repositories: []*bundlev1.NativeRepository{{Format: "deb", Architecture: "amd64", SigningKeyFingerprint: "F320C2E2AFFB41F10CCCBACD5F5AFEE3FBB97A62", Packages: []string{"agent.deb"}}},
		Updates:      &bundlev1.BundleUpdates{FirstRootVersion: 1, RootVersion: 1, TargetsVersion: 2, Channels: []string{"stable"}},
		Advisories: []*bundlev1.AdvisorySnapshot{{
			Source:     &advisoryv1.FeedSource{Id: "fedora44", Distro: "fedora", Release: "44", Architecture: "x86_64", Url: "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/repomd.xml", Format: advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD, MaxAgeSeconds: 86400},
			AcquiredAt: timestamppb.New(created),
			Artifacts:  []*advisoryv1.FeedArtifact{{Url: "https://dl.fedoraproject.org/updateinfo.xml.zst", Sha256: rawDigest(testLayout["advisories/fedora44"])}},
		}},
	}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, &bundlev1.BundleFile{Path: filepath.ToSlash(relative), Sha256: digestOf(string(data)), Size: int64(len(data))})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].GetPath() < manifest.Files[j].GetPath() })
	document, err := protojson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := authority.signer.sign(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ManifestName), document, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, EnvelopeName), envelope, 0644); err != nil {
		t.Fatal(err)
	}
	return directory
}

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func rawDigest(content string) []byte {
	sum := sha256.Sum256([]byte(content))
	return sum[:]
}
