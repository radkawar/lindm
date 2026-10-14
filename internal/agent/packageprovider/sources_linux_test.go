// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/config"
)

func nobleArchive() *resourcev1.AptRepository {
	return &resourcev1.AptRepository{Uri: "https://archive.ubuntu.com/ubuntu", Suite: "noble", AdditionalSuites: []string{"noble-updates", "noble-security"}, Components: []string{"main", "universe"}, Architectures: []string{"amd64"}}
}

func TestAPTSourcesListOneLinePerSuite(t *testing.T) {
	got := aptSourcesList(nobleArchive(), "/state/approved-key.gpg")
	want := "deb [arch=amd64 signed-by=/state/approved-key.gpg] https://archive.ubuntu.com/ubuntu noble main universe\n" +
		"deb [arch=amd64 signed-by=/state/approved-key.gpg] https://archive.ubuntu.com/ubuntu noble-updates main universe\n" +
		"deb [arch=amd64 signed-by=/state/approved-key.gpg] https://archive.ubuntu.com/ubuntu noble-security main universe\n"
	if got != want {
		t.Fatalf("sources.list:\n%s\nwant:\n%s", got, want)
	}
	single := nobleArchive()
	single.AdditionalSuites = nil
	if lines := strings.Count(aptSourcesList(single, "/k"), "\n"); lines != 1 {
		t.Fatalf("single-suite source wrote %d lines", lines)
	}
}

func TestAPTEverySuiteNeedsVerifiedInRelease(t *testing.T) {
	apt := nobleArchive()
	all := map[string]bool{
		"archive.ubuntu.com_ubuntu_dists_noble_InRelease":          true,
		"archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease":  true,
		"archive.ubuntu.com_ubuntu_dists_noble-security_InRelease": true,
	}
	if err := aptSuitesVerified(apt, all); err != nil {
		t.Fatal(err)
	}
	missing := map[string]bool{"archive.ubuntu.com_ubuntu_dists_noble_InRelease": true, "archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease": true}
	if err := aptSuitesVerified(apt, missing); err == nil {
		t.Fatal("a suite without a verified InRelease was accepted")
	}
	substituted := map[string]bool{"archive.ubuntu.com_ubuntu_dists_noble_InRelease": true, "archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease": true, "archive.ubuntu.com_ubuntu_dists_noble-proposed_InRelease": true}
	if err := aptSuitesVerified(apt, substituted); err == nil {
		t.Fatal("an unapproved suite stood in for an approved one")
	}
	if name := aptListName("https://ports.ubuntu.com/ubuntu-ports/", "dists/my_suite/InRelease"); name != "ports.ubuntu.com_ubuntu-ports_dists_my%5fsuite_InRelease" {
		t.Fatalf("list name = %s", name)
	}
}

func TestAPTSeparateSecurityPocket(t *testing.T) {
	apt := &resourcev1.AptRepository{
		Uri: "https://deb.debian.org/debian", Suite: "bookworm",
		AdditionalSuites: []string{"bookworm-updates", "bookworm-security"},
		SuiteUris:        []*resourcev1.AptSuiteURI{{Suite: "bookworm-security", Uri: "https://security.debian.org/debian-security"}},
		Components:       []string{"main"}, Architectures: []string{"arm64"},
	}
	want := "deb [arch=arm64 signed-by=/k] https://deb.debian.org/debian bookworm main\n" +
		"deb [arch=arm64 signed-by=/k] https://deb.debian.org/debian bookworm-updates main\n" +
		"deb [arch=arm64 signed-by=/k] https://security.debian.org/debian-security bookworm-security main\n"
	if got := aptSourcesList(apt, "/k"); got != want {
		t.Fatalf("separate security pocket:\n%s\nwant:\n%s", got, want)
	}
	verified := map[string]bool{
		"deb.debian.org_debian_dists_bookworm_InRelease":                        true,
		"deb.debian.org_debian_dists_bookworm-updates_InRelease":                true,
		"security.debian.org_debian-security_dists_bookworm-security_InRelease": true,
	}
	if err := aptSuitesVerified(apt, verified); err != nil {
		t.Fatal(err)
	}
	delete(verified, "security.debian.org_debian-security_dists_bookworm-security_InRelease")
	if err := aptSuitesVerified(apt, verified); err == nil {
		t.Fatal("missing security pocket accepted")
	}
	verified["deb.debian.org_debian_dists_bookworm-security_InRelease"] = true
	if err := aptSuitesVerified(apt, verified); err == nil {
		t.Fatal("same suite at the wrong archive root accepted")
	}
}

func TestAPTPocketSchemaRejectsUnapprovedCoordinates(t *testing.T) {
	apt := nobleArchive()
	apt.SigningKey = &resourcev1.ArtifactRef{Sha256: bytes.Repeat([]byte{1}, 32), SizeBytes: 32, ArtifactId: "11111111-1111-4111-8111-111111111111"}
	apt.SuiteUris = []*resourcev1.AptSuiteURI{{Suite: "noble-security", Uri: "https://security.example.test/archive"}}
	apt.SigningKeyFingerprints = []string{subkeyPrimary}
	if err := validateMessage(apt); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*resourcev1.AptRepository){
		"unknown suite": func(a *resourcev1.AptRepository) { a.SuiteUris[0].Suite = "noble-proposed" },
		"duplicate suite": func(a *resourcev1.AptRepository) {
			a.SuiteUris = append(a.SuiteUris, &resourcev1.AptSuiteURI{Suite: "noble-security", Uri: "https://other.example.test/archive"})
		},
		"missing suite":     func(a *resourcev1.AptRepository) { a.SuiteUris[0].Suite = "" },
		"cleartext archive": func(a *resourcev1.AptRepository) { a.SuiteUris[0].Uri = "http://security.example.test/archive" },
		"embedded credentials": func(a *resourcev1.AptRepository) {
			a.SuiteUris[0].Uri = "https://user:secret@security.example.test/archive"
		},
		"fragment":               func(a *resourcev1.AptRepository) { a.SuiteUris[0].Uri = "https://security.example.test/archive#pocket" },
		"empty archive":          func(a *resourcev1.AptRepository) { a.SuiteUris[0].Uri = "" },
		"short key id":           func(a *resourcev1.AptRepository) { a.SigningKeyFingerprints = []string{subkeyPrimary[:16]} },
		"lowercase fingerprint":  func(a *resourcev1.AptRepository) { a.SigningKeyFingerprints = []string{strings.ToLower(subkeyPrimary)} },
		"duplicate fingerprints": func(a *resourcev1.AptRepository) { a.SigningKeyFingerprints = []string{subkeyPrimary, subkeyPrimary} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(apt)
			mutate(changed)
			if err := validateMessage(changed); err == nil {
				t.Fatal("unapproved pocket coordinates accepted")
			}
		})
	}
}

func TestAPTPinnedFingerprintsRejectOtherKeyringSigners(t *testing.T) {
	apt := nobleArchive()
	apt.SigningKeyFingerprints = []string{subkeyPrimary}
	for _, tc := range []struct {
		parse  func([]byte) ([][]byte, error)
		status string
	}{
		{validSigners, subkeySignedVALIDSIG},
		{sqvSigners, subkeySignedSQV},
	} {
		// Both parsers must bind the primary certificate, not the subkey.
		signers, err := tc.parse([]byte(tc.status))
		if err != nil {
			t.Fatal(err)
		}
		if err := aptSignersApproved(apt, signers); err != nil {
			t.Fatal(err)
		}
	}
	signers, err := sqvSigners([]byte(subkeySignedSQV))
	if err != nil {
		t.Fatal(err)
	}
	if err := aptSignersApproved(apt, signers); err != nil {
		t.Fatal(err)
	}
	other, err := signerDigest(strings.Repeat("A", 40))
	if err != nil {
		t.Fatal(err)
	}
	if err := aptSignersApproved(apt, append(signers, other)); err == nil {
		t.Fatal("an unapproved signer alongside an approved signer was accepted")
	}
	if err := aptSignersApproved(apt, [][]byte{other}); err == nil {
		t.Fatal("an unrelated signer from the broader keyring was accepted")
	}
	apt.SigningKeyFingerprints = nil
	if err := aptSignersApproved(apt, [][]byte{other}); err != nil {
		t.Fatalf("independently approved local key artifact lost its existing semantics: %v", err)
	}
}

func fedoraSource(signedMetadata bool) *agentv1.NativePackageSource {
	rpm := &resourcev1.RpmRepository{
		NativeId: "fedora", Location: &resourcev1.RpmRepository_Metalink{Metalink: "https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64"},
		RequireMetadataSignature: signedMetadata, RequirePackageSignature: true,
		AdditionalRepositories: []*resourcev1.RpmAdditionalRepository{{NativeId: "updates", Location: &resourcev1.RpmAdditionalRepository_Metalink{Metalink: "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64"}}},
	}
	return &agentv1.NativePackageSource{Repository: &resourcev1.RepositoryDesired{Source: &resourcev1.RepositoryDesired_Rpm{Rpm: rpm}}, SigningKeyFile: "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary"}
}

func TestDNFRepositoryConfigOneSectionPerNativeID(t *testing.T) {
	source := fedoraSource(false)
	got := dnfRepositoryConfig(source, source.GetSigningKeyFile())
	section := func(id, metalink string) string {
		return "[" + id + "]\nname=Lindm approved repository\nmetalink=" + metalink + "\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=0\nsslverify=1\nskip_if_unavailable=0\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary\n"
	}
	want := section("fedora", "https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64") + "\n" + section("updates", "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64")
	if got != want {
		t.Fatalf("repo config:\n%s\nwant:\n%s", got, want)
	}
	signedSource := fedoraSource(true)
	signed := dnfRepositoryConfig(signedSource, signedSource.GetSigningKeyFile())
	if strings.Contains(signed, "repo_gpgcheck=0") || strings.Count(signed, "repo_gpgcheck=1") != 2 || strings.Count(signed, "gpgcheck=1\n") != 4 {
		t.Fatalf("signed-metadata source config:\n%s", signed)
	}
	base := fedoraSource(true)
	base.Repository.GetRpm().Location = &resourcev1.RpmRepository_BaseUrls{BaseUrls: &resourcev1.RepositoryURLs{Urls: []string{"https://a.example/", "https://b.example/"}}}
	if !strings.Contains(dnfRepositoryConfig(base, base.GetSigningKeyFile()), "[fedora]\nname=Lindm approved repository\nbaseurl=https://a.example/ https://b.example/\n") {
		t.Fatal("base URLs not rendered")
	}
}

func TestDNFAcceptsEveryApprovedNativeID(t *testing.T) {
	rpm := fedoraSource(false).GetRepository().GetRpm()
	for id, want := range map[string]bool{
		"fedora": true, "updates": true,
		"@stored_transaction(fedora)": true, "@stored_transaction(updates)": true,
		"updates-testing": false, "@stored_transaction(updates-testing)": false, "@commandline": false, "": false,
		"@stored_transaction(fedora": false,
	} {
		if got := dnfApprovedRepository(rpm, id); got != want {
			t.Errorf("dnfApprovedRepository(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestCheckSourceRefusesUnpinnedUnsignedMetadata(t *testing.T) {
	source := fedoraSource(false)
	source.Repository.GetRpm().Location = &resourcev1.RpmRepository_Metalink{Metalink: "https://mirror.example.com/metalink?repo=fedora-44&arch=x86_64"}
	if err := checkSource(source); !errors.Is(err, config.ErrUnsignedMetadata) || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unpinned unsigned metadata accepted: %v", err)
	}
	base := fedoraSource(false)
	base.Repository.GetRpm().Location = &resourcev1.RpmRepository_BaseUrls{BaseUrls: &resourcev1.RepositoryURLs{Urls: []string{"https://mirrors.fedoraproject.org/pub/"}}}
	if err := checkSource(base); !errors.Is(err, config.ErrUnsignedMetadata) {
		t.Fatalf("base URL without signed metadata accepted: %v", err)
	}
}

// noble, noble-updates and noble-security are each signed by the same archive
// key; the snapshot lists that signer once, so it validates and the staging
// helper accepts it.
func TestAPTSnapshotListsSharedSuiteSignerOnce(t *testing.T) {
	archive := bytes.Repeat([]byte{0x87}, 32)
	other := bytes.Repeat([]byte{0x19}, 32)
	var signers [][]byte
	for _, suite := range [][][]byte{{archive}, {archive}, {archive, other}} {
		signers = appendUniqueSigners(signers, suite)
	}
	if len(signers) != 2 || !bytes.Equal(signers[0], archive) || !bytes.Equal(signers[1], other) {
		t.Fatalf("signers = %x", signers)
	}
	v, err := validator()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &resourcev1.RepositorySnapshot{Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "apt/8053e72a-44e8-53fc-9472-825c068cf9b5"}, MetadataSha256: archive, SignerSha256: signers}
	if err := v.Validate(&resourcev1.RepositorySnapshots{Repositories: []*resourcev1.RepositorySnapshot{snapshot}}); err != nil {
		t.Fatalf("deduplicated snapshot invalid: %v", err)
	}
}
