//go:build linux

package packageprovider

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestDatabaseAuthoritativeAbsenceRequiresCompleteNativeRecords(t *testing.T) {
	tests := []struct {
		name, data string
		ecosystem  resourcev1.PackageEcosystem
		wantError  bool
	}{
		{"deb configured and residual", "ii \tbase-files\t13ubuntu10\tamd64\nrc \tproof\t1.0-1\tamd64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, false},
		{"deb held installed", "hi \tproof\t1:2.0~rc1-1\tamd64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, false},
		{"deb half configured", "iF \tproof\t1.0-1\tamd64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, true},
		{"deb unpacked", "iU \tproof\t1.0-1\tamd64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, true},
		{"deb triggers pending", "it \tproof\t1.0-1\tamd64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, true},
		{"deb reinst required", "iiR\tproof\t1.0-1\tamd64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, true},
		{"deb empty", "", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, true},
		{"deb truncated", "ii \tproof\t1.0-1\tamd64", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, true},
		{"rpm epoch", "proof\t2\t1.0\t3.fc44\tx86_64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, false},
		{"rpm failed query text", "package proof is not installed\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, true},
		{"rpm invalid epoch", "proof\t(none)\t1.0\t3.fc44\tx86_64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, true},
		{"rpm empty", "", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, true},
		{"rpm duplicate", "proof\t0\t1.0\t1\tx86_64\nproof\t0\t1.0\t1\tx86_64\n", resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, err := parseDatabase([]byte(test.data), test.ecosystem)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, want error %v", err, test.wantError)
			}
			if err == nil {
				if len(db.revision) != 32 {
					t.Fatal("database revision missing")
				}
				for _, record := range db.records {
					if record.GetProvenanceKnown() || record.GetSource() != nil || record.GetSignerSha256() != nil {
						t.Fatal("native database row fabricated provenance")
					}
				}
			}
		})
	}
	db, err := parseDatabase([]byte("ii \tbase-files\t13ubuntu10\tamd64\nrc \tproof\t1.0-1\tamd64\n"), resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	if err != nil {
		t.Fatal(err)
	}
	if db.records["proof/amd64"] != nil {
		t.Fatal("residual config-files treated as installed")
	}
}

func TestDatabaseRevisionIsOrderIndependentAndTracksAllRows(t *testing.T) {
	first := []byte("proof\t0\t1.0\t1\tx86_64\nbase\t0\t2.0\t1\tx86_64\n")
	second := []byte("base\t0\t2.0\t1\tx86_64\nproof\t0\t1.0\t1\tx86_64\n")
	a, err := parseDatabase(first, resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseDatabase(second, resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.revision, b.revision) {
		t.Fatal("native enumeration order changed revision")
	}
	c, err := parseDatabase(bytes.Replace(first, []byte("2.0"), []byte("2.1"), 1), resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.revision, c.revision) {
		t.Fatal("unrelated package change did not fence transaction")
	}
}
func TestRPMInstallonlyRowsDoNotHideOtherPackages(t *testing.T) {
	db, err := parseDatabase([]byte("kernel-core\t0\t6.18\t1.fc44\tx86_64\nkernel-core\t0\t6.19\t1.fc44\tx86_64\nproof\t0\t1\t1\tx86_64\n"), resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	if err != nil {
		t.Fatal(err)
	}
	if !db.multiple["kernel-core/x86_64"] || db.records["proof/x86_64"] == nil {
		t.Fatal("installonly database lost package distinction")
	}
}
func TestNativeVersionOrderingRefusesDowngradeNotSemver(t *testing.T) {
	for _, test := range []struct {
		before, after string
		reject        bool
	}{{"2:1.0-1", "1:99.0-1", true}, {"1.0-1", "1.0~rc1-1", true}, {"1.9-1", "1.10-1", false}, {"1.0~rc1-1", "1.0-1", false}} {
		err := checkNoDowngrade(debVersion(test.before), debVersion(test.after))
		if (err != nil) != test.reject {
			t.Fatalf("%s -> %s: %v", test.before, test.after, err)
		}
	}
	a, err := rpmVersion("2", "1", "1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := rpmVersion("1", "999", "1")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkNoDowngrade(a, b); err == nil {
		t.Fatal("RPM epoch downgrade accepted")
	}
}
func TestAPTSolverNativeRecords(t *testing.T) {
	data := []byte("Reading package lists...\nInst libproof [1.0-1] (1.1-1 Ubuntu:24.04/noble [amd64])\nInst proof:amd64 (2.0-1 Ubuntu:24.04/noble [amd64])\nConf libproof (1.1-1 Ubuntu:24.04/noble [amd64])\n")
	changes, err := parseAPTSimulation(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].name != "libproof" || changes[1].version != "2.0-1" {
		t.Fatalf("changes = %#v", changes)
	}
	for _, bad := range []string{"Inst proof unexpected\n", "Inst proof:arm64 (1.0 stable [amd64])\n", "Purg proof [1.0]\n", "E: dependency error\n"} {
		if _, err := parseAPTSimulation([]byte(bad)); err == nil {
			t.Fatalf("accepted unsafe solver result %q", bad)
		}
	}
}
func TestDNFStoredManifestIsClosedAndBounded(t *testing.T) {
	good := []byte(`{"version":"1.0","rpms":[{"nevra":"proof-2:1.0-3.fc44.x86_64","action":"Install","reason":"User","repo_id":"@stored_transaction(proof)","package_path":"./packages/proof.rpm"}]}`)
	parsed, err := parseDNFTransaction(good)
	if err != nil {
		t.Fatal(err)
	}
	identity, version, err := parseNEVRA(parsed.RPMs[0].NEVRA)
	if err != nil {
		t.Fatal(err)
	}
	if identity.GetNativeName() != "proof" || version.GetRpm().GetEpoch() != 2 {
		t.Fatal("NEVRA lost native identity")
	}
	for _, bad := range []string{`{"version":"2.0"}`, `{"version":"1.0","groups":[{}]}`, `{"version":"1.0","opaque_command":"rm"}`, `{"version":"1.0"}{}`} {
		if _, err := parseDNFTransaction([]byte(bad)); err == nil {
			t.Fatalf("accepted unbound native transaction %s", bad)
		}
	}
	for _, bad := range []string{"/tmp/evil.rpm", "../../evil.rpm", "packages/../../evil.rpm", "packages/evil.txt"} {
		if _, err := dnfPackagePath("/private", bad); err == nil {
			t.Fatalf("accepted artifact escape %s", bad)
		}
	}
}
func TestUnsignedRPMDoesNotPassDigestOnlyOutput(t *testing.T) {
	fingerprint := "12345678901234567890123456789012ABCDEFAB"
	if err := checkRPMSignature([]byte("proof.rpm:\n    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n"), fingerprint); err == nil {
		t.Fatal("digest-only RPM accepted as signed")
	}
	if err := checkRPMSignature([]byte("proof.rpm:\n    Header V4 RSA/SHA256 Signature, key ID abcdefab: OK\n"), fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := checkRPMSignature([]byte("proof.rpm:\n    Header V4 RSA/SHA256 Signature, key ID 00000000: OK\n"), fingerprint); err == nil {
		t.Fatal("foreign signer accepted")
	}
}
func TestTransactionVerificationDetectsUnmanifestedEffects(t *testing.T) {
	before, err := parseDatabase([]byte("ii \tbase\t1.0-1\tamd64\n"), resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseDatabase([]byte("ii \tbase\t1.0-1\tamd64\nii \tproof\t1.0-1\tamd64\n"), resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &resourcev1.PackageTransactionManifest{Entries: []*resourcev1.PackageTransactionEntry{{Package: after.records["proof/amd64"].GetPackage(), After: debVersion("1.0-1")}}}
	if err := transactionMatchesDatabase(manifest, before, after); err != nil {
		t.Fatal(err)
	}
	changed := &database{records: make(map[string]*resourcev1.NativePackageRecord), multiple: map[string]bool{}}
	for key, record := range after.records {
		changed.records[key] = proto.CloneOf(record)
	}
	changed.records["base/amd64"].Version = debVersion("2.0-1")
	if err := transactionMatchesDatabase(manifest, before, changed); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("hidden upgrade error = %v", err)
	}
	delete(changed.records, "base/amd64")
	if err := transactionMatchesDatabase(manifest, before, changed); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("hidden removal error = %v", err)
	}
}

func TestDependencyCannotReplaceSignedAgentPackage(t *testing.T) {
	db, err := parseDatabase([]byte("ii \tlindm-agent\t1.0-1\tamd64\n"), resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	if err != nil {
		t.Fatal(err)
	}
	desired := &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "proof", Architecture: "amd64"}}
	entry := &resourcev1.PackageTransactionEntry{Package: db.records["lindm-agent/amd64"].GetPackage(), Before: debVersion("1.0-1"), After: debVersion("2.0-1")}
	if err := validateEntries([]*resourcev1.PackageTransactionEntry{entry}, desired, db); err == nil {
		t.Fatal("dependency resolution bypassed signed agent self-update")
	}
}
