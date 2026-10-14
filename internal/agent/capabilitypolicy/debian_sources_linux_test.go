// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capabilitypolicy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/platform"
	"lindm/internal/protodata"
)

// One signed PACKAGES grant approves all three pockets under the same stable
// identity. Fixtures replace only key bytes, not release facts or authority.
func TestDeriveDebianThreePockets(t *testing.T) {
	for _, key := range []string{"debian-12", "debian-13"} {
		for machine, native := range map[string]string{"x86_64": "amd64", "aarch64": "arm64"} {
			t.Run(key+"/"+machine, func(t *testing.T) {
				host := testHost(t, key)
				host.Architecture = machine
				release := host.Release
				vendor := release.VendorRepositories[0]
				local := &agentv1.AgentConfig{}
				effective := derive(t, local, testRecord(true, capPackages), host)
				wantStatus(t, effective, capPackages, statusEnabled, "")
				sources := effective.Config.GetPackageProvider().GetSources()
				if len(sources) != 1 {
					t.Fatalf("Debian archive split into %d identities", len(sources))
				}
				source := sources[0]
				if err := protodata.ValidateClosed(source.ProtoReflect()); err != nil {
					t.Fatalf("derived source cannot cross closed configuration custody: %v", err)
				}
				apt := source.GetRepository().GetApt()
				if source.GetRepository().GetRepositoryId() != vendor.RepositoryID || apt.GetUri() != vendor.ArchiveURIs[machine] || apt.GetSuite() != release.Codename ||
					!slices.Equal(apt.GetAdditionalSuites(), []string{release.Codename + "-updates", release.Codename + "-security"}) ||
					len(apt.GetSuiteUris()) != 1 || apt.GetSuiteUris()[0].GetSuite() != release.Codename+"-security" ||
					apt.GetSuiteUris()[0].GetUri() != vendor.SuiteURIs[release.Codename+"-security"] || !slices.Equal(apt.GetSigningKeyFingerprints(), vendor.APTFingerprints) ||
					!slices.Equal(apt.GetArchitectures(), []string{native}) || !slices.Equal(apt.GetComponents(), []string{"main"}) || source.GetSigningKeyFile() != vendor.KeyFile ||
					apt.GetSigningKey().GetArtifactId() != vendor.KeyArtifactID || !bytes.Equal(apt.GetSigningKey().GetSha256(), source.GetSigningKeySha256()) {
					t.Fatalf("Debian source lost registry authority: %v", source)
				}
				// The derived source must not share mutable registry collections.
				apt.SuiteUris[0].Uri = "https://changed.invalid/archive"
				apt.SigningKeyFingerprints[0] = "changed"
				if vendor.SuiteURIs[release.Codename+"-security"] == apt.GetSuiteUris()[0].GetUri() || vendor.APTFingerprints[0] == "changed" {
					t.Fatal("derived source mutated compiled registry facts")
				}
				if local.GetPackageProvider() != nil {
					t.Fatal("derivation mutated local configuration")
				}
			})
		}
	}
}

func TestDebianSourcesRequireActivePackageAuthority(t *testing.T) {
	for _, key := range []string{"debian-12", "debian-13"} {
		for name, record := range map[string]*agentv1.CapabilityPolicyRecord{
			"no record":       nil,
			"inactive":        testRecord(false, capPackages),
			"different grant": testRecord(true, capFiles),
		} {
			t.Run(key+"/"+name, func(t *testing.T) {
				effective := derive(t, &agentv1.AgentConfig{}, record, testHost(t, key))
				wantStatus(t, effective, capPackages, statusNotEnabled, "")
				if effective.Config.GetPackageProvider() != nil {
					t.Fatal("Debian sources derived without active PACKAGES authority")
				}
			})
		}
	}
}

func TestDebianSourcesRejectUnrecognizedKeyring(t *testing.T) {
	for _, key := range []string{"debian-12", "debian-13"} {
		for name, readKey := range map[string]func(string) ([]byte, error){
			"changed bytes": func(string) ([]byte, error) { return []byte("unrecognized keyring"), nil },
			"missing":       func(string) ([]byte, error) { return nil, errors.New("keyring absent") },
		} {
			t.Run(key+"/"+name, func(t *testing.T) {
				host := testHost(t, key)
				// Use the actual production pin rather than the fixture digest.
				host.Release, _ = platform.Lookup(key)
				host.ReadVendorKey = readKey
				effective := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages), host)
				wantStatus(t, effective, capPackages, statusUnavailable, DetailVendorKeyUnrecognized)
				if effective.Config.GetPackageProvider() != nil {
					t.Fatal("unrecognized keyring produced package authority")
				}
			})
		}
	}
}

func TestDebianLocalSourceIdentityStillWins(t *testing.T) {
	host := testHost(t, "debian-13")
	approved := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages), host).Config.GetPackageProvider().GetSources()[0]
	localSource := proto.CloneOf(approved)
	localSource.Repository.GetApt().Uri = "https://local.example.test/debian"
	local := &agentv1.AgentConfig{PackageProvider: &agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{localSource}}}
	effective := derive(t, local, testRecord(true, capPackages), host)
	sources := effective.Config.GetPackageProvider().GetSources()
	if len(sources) != 1 || !proto.Equal(sources[0], localSource) {
		t.Fatalf("registry source replaced independently approved local identity: %v", sources)
	}
}

func TestDebianRefusesRemotePackageGrant(t *testing.T) {
	for _, key := range []string{"debian-12", "debian-13"} {
		local := &agentv1.AgentConfig{CapabilityPolicy: &agentv1.CapabilityPolicyConfig{RefuseRemote: true}}
		effective := derive(t, local, testRecord(true, capPackages), testHost(t, key))
		wantStatus(t, effective, capPackages, statusNotEnabled, "")
		if effective.Config.GetPackageProvider() != nil {
			t.Fatal("local remote refusal admitted Debian archive authority")
		}
	}
}

// Exercise the complete merge into a production-custody document, not just
// Derive's protobuf validation. A map-valued pocket source passed Derive but
// failed WithProviders' closed-payload check and disabled every remote grant.
func TestEffectBindsDebianPackagePocketAuthority(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root package configuration custody")
	}
	root, err := os.MkdirTemp("/run", "lindm-debian-capability-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	keyDirectory := filepath.Join(root, "keyrings")
	if err := os.Mkdir(keyDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDirectory, "vendor-key.pgp")
	if err := os.WriteFile(keyPath, testKey, 0644); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"debian-12", "debian-13"} {
		t.Run(key, func(t *testing.T) {
			host := testHost(t, key)
			host.Release.VendorRepositories[0].KeyFile = keyPath
			host.Release.StandardFileRoots = []string{filepath.Join(root, "issue.d"), filepath.Join(root, "motd.d")}
			document := &config.Document{
				Proto: &agentv1.AgentConfig{}, ConfigDirectory: filepath.Join(root, "etc"),
				StateDirectory: filepath.Join(root, "state"), RuntimeDirectory: filepath.Join(root, "run"), SpoolDirectory: filepath.Join(root, "spool"),
			}
			effective, err := Effect(t.Context(), document, testRecord(true, capPackages, capFiles, capAccounts), host)
			if err != nil {
				t.Fatal(err)
			}
			for _, capability := range []agentv1.ManagementCapability{capPackages, capFiles, capAccounts} {
				wantStatus(t, effective, capability, statusEnabled, "")
			}
			sources := effective.Document.Proto.GetPackageProvider().GetSources()
			if len(sources) != 1 || len(sources[0].GetRepository().GetApt().GetSuiteUris()) != 1 {
				t.Fatal("Debian security pocket did not reach the effective executor document")
			}
			if document.Proto.GetPackageProvider() != nil {
				t.Fatal("effective binding mutated local executor configuration")
			}
		})
	}
}

func TestDerivePocketAuthorityFollowsSuiteOrder(t *testing.T) {
	host := testHost(t, "debian-13")
	vendor := &host.Release.VendorRepositories[0]
	vendor.SuiteURIs = map[string]string{
		"trixie-security": "https://security.example.test/archive",
		"trixie":          "https://main.example.test/archive",
		"trixie-updates":  "https://updates.example.test/archive",
	}
	first := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages), host)
	pockets := first.Config.GetPackageProvider().GetSources()[0].GetRepository().GetApt().GetSuiteUris()
	if len(pockets) != len(vendor.Suites) {
		t.Fatal("configured archive overrides were lost")
	}
	for i, pocket := range pockets {
		if pocket.GetSuite() != vendor.Suites[i] || pocket.GetUri() != vendor.SuiteURIs[vendor.Suites[i]] {
			t.Fatal("serialized pocket authority does not follow approved suite order")
		}
	}
	for range 5 {
		next := derive(t, &agentv1.AgentConfig{}, testRecord(true, capPackages), host)
		if !proto.Equal(first.Config, next.Config) {
			t.Fatal("registry map iteration changed serialized pocket authority")
		}
	}
}
