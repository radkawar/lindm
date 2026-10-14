// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativeexec"
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
func TestRPMSignatureRequiresApprovedSignerAndEveryDigest(t *testing.T) {
	const fingerprint = "567E347AD0044ADE55BA8A5F199E2F91FD431D51"
	const approved = "    Header V4 RSA/SHA256 Signature, key ID fd431d51: OK\n"
	const secondary = "    Header V6 ML-DSA-87+Ed448/SHA512 Signature, key ID 05707a62: NOKEY\n"
	const digests = "    Header SHA256 digest: OK\n    Header SHA1 digest: OK\n    Payload SHA256 digest: OK\n    MD5 digest: OK\n"
	exitOne := &nativeexec.ExitError{Program: "rpmkeys", Code: 1}
	full := "    Header OpenPGP V4 RSA/SHA256 signature, key fingerprint: 567e347ad0044ade55ba8a5f199e2f91fd431d51: OK\n"
	for _, tc := range []struct {
		name, output, stderr string
		runErr               error
		accepted             bool
	}{
		{"approved RSA", "proof.rpm:\n" + approved + digests, "", nil, true},
		{"approved full fingerprint", "proof.rpm:\n" + full + digests, "", nil, true},
		// Actual rhel10-03 perl-Git-2.52.0-1.el10.noarch verification shape.
		{"approved plus unknown secondary", "proof.rpm:\n" + secondary + approved + digests, "", exitOne, true},
		{"approved plus verified secondary", "proof.rpm:\n" + strings.ReplaceAll(secondary, "NOKEY", "OK") + approved + digests, "", nil, true},
		{"approved plus bad secondary", "proof.rpm:\n" + strings.ReplaceAll(secondary, "NOKEY", "BAD") + approved + digests, "", exitOne, false},
		{"unknown secondary only", "proof.rpm:\n" + secondary + digests, "", exitOne, false},
		{"unapproved verified signer only", "proof.rpm:\n" + strings.ReplaceAll(secondary, "NOKEY", "OK") + digests, "", nil, false},
		{"unapproved full fingerprint only", "proof.rpm:\n" + strings.ReplaceAll(full, "567e347a", "00000000") + digests, "", nil, false},
		{"digest only", "proof.rpm:\n" + digests, "", nil, false},
		{"header digest failure", "proof.rpm:\n" + approved + strings.ReplaceAll(digests, "Header SHA256 digest: OK", "Header SHA256 digest: BAD"), "", exitOne, false},
		{"payload digest failure", "proof.rpm:\n" + approved + strings.ReplaceAll(digests, "Payload SHA256 digest: OK", "Payload SHA256 digest: BAD"), "", exitOne, false},
		{"missing header digest", "proof.rpm:\n" + approved + "    Payload SHA256 digest: OK\n", "", nil, false},
		{"missing payload digest", "proof.rpm:\n" + approved + "    Header SHA256 digest: OK\n", "", nil, false},
		{"duplicate digest", "proof.rpm:\n" + approved + digests + "    Payload SHA256 digest: OK\n", "", nil, false},
		{"approved unknown key", "proof.rpm:\n" + strings.ReplaceAll(approved, "OK", "NOKEY") + digests, "", exitOne, false},
		{"bad approved signature", "proof.rpm:\n" + strings.ReplaceAll(approved, "OK", "BAD") + secondary + digests, "", exitOne, false},
		{"failed secondary verification", "proof.rpm:\n" + strings.ReplaceAll(secondary, "NOKEY", "NOT OK") + approved + digests, "", exitOne, false},
		{"unknown status", "proof.rpm:\n" + strings.ReplaceAll(secondary, "NOKEY", "UNKNOWN") + approved + digests, "", exitOne, false},
		{"unknown line", "proof.rpm:\n" + approved + digests + "    unrecognized check: OK\n", "", nil, false},
		{"unknown algorithm", "proof.rpm:\n" + strings.ReplaceAll(approved, "RSA/SHA256", "unknown/SHA256") + digests, "", nil, false},
		{"malformed signer", "proof.rpm:\n" + strings.ReplaceAll(approved, "fd431d51", "fd431d5z") + digests, "", nil, false},
		{"truncated output", strings.TrimSuffix("proof.rpm:\n"+secondary+approved+digests, "\n"), "", exitOne, false},
		{"warning", "proof.rpm:\n" + secondary + approved + digests, "unexpected warning\n", exitOne, false},
		{"unexplained exit one", "proof.rpm:\n" + approved + digests, "", exitOne, false},
		{"wrong executable exit", "proof.rpm:\n" + secondary + approved + digests, "", &nativeexec.ExitError{Program: "rpm", Code: 1}, false},
		{"other exit code", "proof.rpm:\n" + secondary + approved + digests, "", &nativeexec.ExitError{Program: "rpmkeys", Code: 2}, false},
		{"joined output limit", "proof.rpm:\n" + secondary + approved + digests, "", errors.Join(exitOne, nativeexec.ErrOutputLimit), false},
		{"joined deadline", "proof.rpm:\n" + secondary + approved + digests, "", errors.Join(exitOne, nativeexec.ErrDeadline), false},
		{"joined descriptor failure", "proof.rpm:\n" + secondary + approved + digests, "", errors.Join(exitOne, errors.New("descriptor failure")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRPMSignature(nativeResult{stdout: []byte(tc.output), stderr: []byte(tc.stderr)}, tc.runErr, fingerprint)
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%t, want %t: %v", err == nil, tc.accepted, err)
			}
		})
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
	if err := (&Provider{}).validateEntries([]*resourcev1.PackageTransactionEntry{entry}, desired, db); err == nil {
		t.Fatal("dependency resolution bypassed signed agent self-update")
	}
}
