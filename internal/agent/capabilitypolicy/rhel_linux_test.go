// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capabilitypolicy

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

func entitledTestHost(t *testing.T, release, architecture string) Host {
	t.Helper()
	host := testHost(t, release)
	host.Architecture = architecture
	key, err := os.ReadFile("../rhsm/testdata/redhat-release2.asc")
	if err != nil {
		t.Fatal(err)
	}
	host.ReadVendorKey = func(string) ([]byte, error) { return bytes.Clone(key), nil }
	return host
}

func TestRHELSignedPackagesRequireLocalEntitlement(t *testing.T) {
	for _, release := range []string{"rhel-9", "rhel-10"} {
		for _, architecture := range []string{"x86_64", "aarch64"} {
			t.Run(release+"/"+architecture, func(t *testing.T) {
				host := entitledTestHost(t, release, architecture)
				local := new(agentv1.AgentConfig)
				unregistered, err := Derive(local, testRecord(true, capPackages), host)
				if err != nil {
					t.Fatal(err)
				}
				wantStatus(t, unregistered, capPackages, statusUnavailable, DetailRHSMRegistrationRequired)
				if len(unregistered.Config.GetPackageProvider().GetSources()) != 0 {
					t.Fatal("unregistered source retained")
				}
				calls := 0
				host.ReadEntitledConfig = func(vendor platform.VendorRepository, arch string) error {
					calls++
					if arch != architecture || vendor.Entitled == nil {
						t.Fatal("unexpected entitlement contract")
					}
					return nil
				}
				withoutAuthority, err := Derive(local, testRecord(false, capPackages), host)
				if err != nil {
					t.Fatal(err)
				}
				if calls != 0 || len(withoutAuthority.Config.GetPackageProvider().GetSources()) != 0 {
					t.Fatal("local entitlement substituted for signed authority")
				}
				registered, err := Derive(local, testRecord(true, capPackages), host)
				if err != nil {
					t.Fatal(err)
				}
				wantStatus(t, registered, capPackages, statusEnabled, "")
				sources := registered.Config.GetPackageProvider().GetSources()
				if len(sources) != 1 || calls != 1 {
					t.Fatal("entitled archive not derived once")
				}
				source := sources[0]
				vendor := host.Release.VendorRepositories[0]
				rpm := source.GetRepository().GetRpm()
				ids := vendor.Entitled.NativeIDs[architecture]
				if source.GetRepository().GetRepositoryId() != vendor.RepositoryID || source.GetRpmSigningKeyFingerprint() != vendor.RPMFingerprint || !rpm.GetRhsmManaged() || rpm.GetNativeId() != ids[0] || len(rpm.GetAdditionalRepositories()) != 1 || rpm.GetAdditionalRepositories()[0].GetNativeId() != ids[1] || !rpm.GetAdditionalRepositories()[0].GetRhsmManaged() || !rpm.GetRequirePackageSignature() || rpm.GetRequireMetadataSignature() {
					t.Fatalf("derived archive exceeded registry contract: %v", source)
				}
				serialized, err := proto.Marshal(source)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{vendor.Entitled.Host, vendor.Entitled.File, vendor.Entitled.CAFile, vendor.Entitled.CertificateDirectory} {
					if bytes.Contains(serialized, []byte(forbidden)) {
						t.Fatal("device entitlement material serialized in source")
					}
				}
				host.ReadEntitledConfig = func(platform.VendorRepository, string) error { return errors.New("registration removed") }
				removed, err := Derive(local, testRecord(true, capPackages), host)
				if err != nil {
					t.Fatal(err)
				}
				wantStatus(t, removed, capPackages, statusUnavailable, DetailRHSMRegistrationRequired)
				if len(removed.Config.GetPackageProvider().GetSources()) != 0 {
					t.Fatal("stale entitlement source retained")
				}
			})
		}
	}
}

func TestRHELPackageKeyCannotBeReplacedByLocalFile(t *testing.T) {
	host := entitledTestHost(t, "rhel-9", "x86_64")
	host.ReadEntitledConfig = func(platform.VendorRepository, string) error { return nil }
	host.ReadVendorKey = func(string) ([]byte, error) { return []byte("unrecognized vendor key"), nil }
	effective, err := Derive(new(agentv1.AgentConfig), testRecord(true, capPackages), host)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, effective, capPackages, statusUnavailable, DetailVendorKeyUnrecognized)
	if len(effective.Config.GetPackageProvider().GetSources()) != 0 {
		t.Fatal("unknown release key acquired authority")
	}
}
