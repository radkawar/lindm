// SPDX-License-Identifier: Apache-2.0

//go:build linux

package rhsm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"

	"lindm/internal/platform"
)

func vendorFixture(t *testing.T, release, architecture string) (platform.VendorRepository, string) {
	t.Helper()
	row, ok := platform.Lookup(release)
	if !ok || len(row.VendorRepositories) != 1 {
		t.Fatal("missing entitled registry archive")
	}
	vendor := row.VendorRepositories[0]
	var config strings.Builder
	for _, id := range vendor.Entitled.NativeIDs[architecture] {
		config.WriteString("[" + id + "]\nname=Red Hat repository\nenabled=1\ngpgcheck=1\nsslverify=1\n")
		config.WriteString("gpgkey=file://" + vendor.KeyFile + "\nsslcacert=" + vendor.Entitled.CAFile + "\n")
		config.WriteString("baseurl=https://" + vendor.Entitled.Host + "/content/dist/rhel/$releasever/$basearch/os\n")
		config.WriteString("sslclientcert=" + vendor.Entitled.CertificateDirectory + "/123.pem\nsslclientkey=" + vendor.Entitled.CertificateDirectory + "/123-key.pem\n\n")
	}
	return vendor, config.String()
}

func TestEntitledDefinitionsIsolateArchitectureRepositories(t *testing.T) {
	for _, release := range []string{"rhel-9", "rhel-10"} {
		for _, architecture := range []string{"x86_64", "aarch64"} {
			t.Run(release+"/"+architecture, func(t *testing.T) {
				vendor, raw := vendorFixture(t, release, architecture)
				raw += "[unapproved]\nenabled=1\ngpgcheck=0\nbaseurl=https://attacker.invalid/\n"
				reads := make(map[string]bool)
				got, err := RepositoryConfig(vendor, architecture, "/private/signing-key.gpg", func(path string) ([]byte, error) {
					reads[path] = true
					if path == vendor.Entitled.File {
						return []byte(raw), nil
					}
					return []byte("local credential contents"), nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if strings.Count(got, "[rhel-") != 2 || strings.Contains(got, "unapproved") || strings.Contains(got, "attacker") || strings.Contains(got, "credential contents") || strings.Contains(got, vendor.KeyFile) {
					t.Fatalf("repository isolation failed: %s", got)
				}
				if strings.Contains(got, "$") || !strings.Contains(got, "/"+vendor.Entitled.ReleaseVersion+"/"+architecture+"/os") {
					t.Fatal("source inherited ambient DNF variable substitution")
				}
				for _, id := range vendor.Entitled.NativeIDs[architecture] {
					if !strings.Contains(got, "["+id+"]") {
						t.Fatal("missing approved repository")
					}
				}
				if len(reads) != 4 || !strings.Contains(got, "gpgkey=file:///private/signing-key.gpg") || !strings.Contains(got, "gpgcheck=1\n") || !strings.Contains(got, "sslverify=1\n") {
					t.Fatal("local credential custody or trust constraints lost")
				}
			})
		}
	}
}

func TestEntitledDefinitionsRejectTamperAndMissingRegistration(t *testing.T) {
	vendor, valid := vendorFixture(t, "rhel-9", "x86_64")
	for name, mutate := range map[string]func(string) string{
		"unregistered":       func(string) string { return "" },
		"disabled":           func(s string) string { return strings.Replace(s, "enabled=1", "enabled=0", 1) },
		"wrong architecture": func(s string) string { return strings.ReplaceAll(s, "x86_64", "aarch64") },
		"wrong stream":       func(s string) string { return strings.ReplaceAll(s, "baseos-rpms", "baseos-eus-rpms") },
		"unsigned packages":  func(s string) string { return strings.Replace(s, "gpgcheck=1", "gpgcheck=0", 1) },
		"unverified TLS":     func(s string) string { return strings.Replace(s, "sslverify=1", "sslverify=0", 1) },
		"wrong key":          func(s string) string { return strings.Replace(s, "file://"+vendor.KeyFile, "file:///tmp/key", 1) },
		"wrong CA":           func(s string) string { return strings.Replace(s, vendor.Entitled.CAFile, "/tmp/ca", 1) },
		"foreign credential": func(s string) string {
			return strings.Replace(s, vendor.Entitled.CertificateDirectory+"/123-key.pem", "/tmp/secret-key.pem", 1)
		},
		"mismatched credentials":    func(s string) string { return strings.Replace(s, "/123-key.pem", "/456-key.pem", 1) },
		"symlink shaped credential": func(s string) string { return strings.Replace(s, "/123-key.pem", "/../123-key.pem", 1) },
		"HTTP":                      func(s string) string { return strings.Replace(s, "https://", "http://", 1) },
		"foreign CDN":               func(s string) string { return strings.Replace(s, vendor.Entitled.Host, "attacker.invalid", 1) },
		"CDN lookalike": func(s string) string {
			return strings.Replace(s, vendor.Entitled.Host, vendor.Entitled.Host+".attacker.invalid", 1)
		},
		"userinfo":          func(s string) string { return strings.Replace(s, "https://", "https://secret@", 1) },
		"URL query":         func(s string) string { return strings.Replace(s, "/os\n", "/os?secret=token\n", 1) },
		"traversal":         func(s string) string { return strings.Replace(s, "/content/", "/content/../", 1) },
		"unknown expansion": func(s string) string { return strings.Replace(s, "$releasever", "$secret", 1) },
		"duplicate field":   func(s string) string { return strings.Replace(s, "sslverify=1", "sslverify=0\nsslverify=1", 1) },
		"duplicate stanza":  func(s string) string { return s + s },
		"continuation": func(s string) string {
			return strings.Replace(s, "enabled=1", "  https://attacker.invalid/\nenabled=1", 1)
		},
		"ambient authentication": func(s string) string { return strings.Replace(s, "enabled=1", "username=secret\nenabled=1", 1) },
		"proxy": func(s string) string {
			return strings.Replace(s, "enabled=1", "proxy=https://attacker.invalid\nenabled=1", 1)
		},
		"skip unavailable": func(s string) string { return strings.Replace(s, "enabled=1", "skip_if_unavailable=1\nenabled=1", 1) },
		"skip unavailable boolean": func(s string) string {
			return strings.Replace(s, "enabled=1", "skip_if_unavailable=true\nenabled=1", 1)
		},
		"misspelled UI field": func(s string) string { return strings.Replace(s, "enabled=1", "ui_repoid=releasever\nenabled=1", 1) },
		"oversized":           func(s string) string { return s + strings.Repeat("#", 1<<20) },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutate(valid)
			got, err := RepositoryConfig(vendor, "x86_64", "/private/key", func(path string) ([]byte, error) {
				if path == vendor.Entitled.File {
					return []byte(raw), nil
				}
				return []byte("secret"), nil
			})
			if !errors.Is(err, ErrRegistrationRequired) || got != "" || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "https://") {
				t.Fatalf("unsafe source admitted or diagnostics exposed: %q %v", got, err)
			}
		})
	}
	for _, missing := range []string{vendor.Entitled.File, vendor.Entitled.CAFile, vendor.Entitled.CertificateDirectory + "/123.pem", vendor.Entitled.CertificateDirectory + "/123-key.pem"} {
		if _, err := RepositoryConfig(vendor, "x86_64", "/private/key", func(path string) ([]byte, error) {
			if path == missing {
				return nil, errors.New("secret diagnostic")
			}
			if path == vendor.Entitled.File {
				return []byte(valid), nil
			}
			return []byte("secret"), nil
		}); !errors.Is(err, ErrRegistrationRequired) {
			t.Fatalf("missing local prerequisite %s accepted", missing)
		}
	}
}

func TestReleaseKeyPinsFullFingerprintAndImportsOnlySelectedKey(t *testing.T) {
	raw, err := os.ReadFile("testdata/redhat-release2.asc")
	if err != nil {
		t.Fatal(err)
	}
	vendor, _ := vendorFixture(t, "rhel-9", "x86_64")
	// The installed vendor file also has an unsupported PQ block. It must not
	// become trusted merely because a recognized RSA key exists beside it.
	keyring := append(bytes.Clone(raw), []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAA==\n-----END PGP PUBLIC KEY BLOCK-----\n")...)
	selected, fingerprint, err := ReleaseKey(keyring, vendor.RPMFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(selected, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		t.Fatal("isolated release key is not the public armor RPM import requires")
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(selected))
	if err != nil || len(entities) != 1 || strings.ToUpper(hex.EncodeToString(fingerprint)) != vendor.RPMFingerprint || !bytes.Equal(entities[0].PrimaryKey.Fingerprint, fingerprint) {
		t.Fatalf("isolated key differs from registry pin: %v", err)
	}
	for name, input := range map[string][]byte{"absent": nil, "duplicate": append(bytes.Clone(raw), raw...), "malformed": []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")} {
		if _, _, err := ReleaseKey(input, vendor.RPMFingerprint); err == nil {
			t.Fatalf("%s key accepted", name)
		}
	}
	if _, _, err := ReleaseKey(raw, strings.Repeat("A", 40)); err == nil {
		t.Fatal("unrecognized full fingerprint accepted")
	}
}

// This protects compatibility with upstream RHSM property names; the fixture
// explicitly does not claim a native registered RHEL capture.
func TestEntitledUpstreamModelFieldsAreDroppedSafely(t *testing.T) {
	raw, err := os.ReadFile("testdata/rhsm-upstream-model.repo")
	if err != nil {
		t.Fatal(err)
	}
	vendor, _ := vendorFixture(t, "rhel-9", "x86_64")
	got, err := RepositoryConfig(vendor, "x86_64", "/private/key", func(path string) ([]byte, error) {
		if path == vendor.Entitled.File {
			return raw, nil
		}
		return []byte("local credential"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "ui_repoid") || strings.Contains(got, "metadata_expire") ||
		strings.Contains(got, "skip_if_unavailable=false") || strings.Count(got, "skip_if_unavailable=0\n") != 2 ||
		!strings.Contains(got, "/content/dist/rhel9/9/x86_64/baseos/os") ||
		!strings.Contains(got, "/content/dist/rhel9/9/x86_64/appstream/os") {
		t.Fatalf("upstream/model properties changed isolated trust config: %s", got)
	}
}

// Captured by the admitted rhel9-02 proof guest after actual registration:
// registered-rhsm-public-stanzas-redacted-paths, decoded SHA-256
// afd7e9c1bbf7de72412c14d03db418f757c627f205a18217ead20a85e31fb477.
// Only the two public definitions survive; credential serials were replaced
// with 10101 before capture. No certificate/key contents are part of this test.
func TestObservedRHEL9DefinitionsKeepTLSAndDropTuningFields(t *testing.T) {
	raw, err := os.ReadFile("testdata/rhel9-registered-redacted.repo")
	if err != nil {
		t.Fatal(err)
	}
	vendor, _ := vendorFixture(t, "rhel-9", "x86_64")
	got, err := RepositoryConfig(vendor, "x86_64", "/private/signing-key.asc", func(path string) ([]byte, error) {
		if path == vendor.Entitled.File {
			return raw, nil
		}
		return []byte("local credential"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, "[rhel-9-for-x86_64-") != 2 ||
		strings.Count(got, "sslverifystatus=1\n") != 2 ||
		strings.Count(got, "sslverify=1\n") != 2 ||
		strings.Count(got, "gpgcheck=1\n") != 2 ||
		strings.Contains(got, "metadata_expire") || strings.Contains(got, "enabled_metadata") ||
		strings.Contains(got, "$releasever") || strings.Contains(got, "local credential") ||
		!strings.Contains(got, "sslclientkey=/etc/pki/entitlement/10101-key.pem\n") ||
		!strings.Contains(got, "sslclientcert=/etc/pki/entitlement/10101.pem\n") {
		t.Fatalf("observed definitions changed isolated source trust: %s", got)
	}
}
