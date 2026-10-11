//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func rollingDesired(alpm bool) *resourcev1.NativePackageDesired {
	identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: "proof", Architecture: "x86_64"}
	version := &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Rpm{Rpm: &resourcev1.RPMVersion{Version: "2.0", Release: "1"}}}
	if alpm {
		identity.Ecosystem = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM
		version = &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Alpm{Alpm: &resourcev1.ALPMVersion{Pkgver: "2.0", Pkgrel: "1"}}}
	}
	return &resourcev1.NativePackageDesired{Package: identity, Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Exact{Exact: version}, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "rpm/67e587cd-1fc8-4969-87b9-e569d5829c85"}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA}
}

func TestRollingPinsPreserveForeignConfiguration(t *testing.T) {
	for _, alpm := range []bool{false, true} {
		d := rollingDesired(alpm)
		ref := packageRef(d.GetPackage())
		original := []byte("# external\ntype: package\nmatch_type: exact\nsolvable_name: other\n\n")
		if alpm {
			original = []byte("# external\n[options]\nIgnorePkg = other\nInclude = /etc/pacman.d/options\n[core]\nInclude = /etc/pacman.d/mirrorlist\n")
		}
		pin, err := renderRollingPin(ref, d, original, alpm)
		if err != nil || !rollingPinMatches(ref, d, pin, alpm) {
			t.Fatalf("render pin: %s, %v", pin, err)
		}
		again, err := renderRollingPin(ref, d, pin, alpm)
		if err != nil || !bytes.Equal(pin, again) {
			t.Fatalf("idempotency: %q != %q: %v", pin, again, err)
		}
		d.Version = &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}
		removed, err := renderRollingPin(ref, d, pin, alpm)
		if err != nil || !bytes.Equal(bytes.TrimSpace(original), bytes.TrimSpace(removed)) {
			t.Fatalf("foreign bytes lost: %q: %v", removed, err)
		}
	}
}

func TestRollingPinsRejectForeignOverlapAndDamagedMarkers(t *testing.T) {
	for _, test := range []struct {
		alpm bool
		data string
	}{
		{true, "[options]\nIgnorePkg = pro*\n[core]\n"},
		{false, "solvable_name: pro*\nmatch_type: glob\n"},
		{false, "query_string: proof\nsolvable_name:\n"},
		{false, "solvable_name: proof\nmatch_type: exact\nversion: > 9.0\n"},
	} {
		d := rollingDesired(test.alpm)
		if _, err := renderRollingPin(packageRef(d.GetPackage()), d, []byte(test.data), test.alpm); err == nil {
			t.Fatalf("accepted foreign lock %q", test.data)
		}
	}
	d := rollingDesired(true)
	ref := packageRef(d.GetPackage())
	pin := []byte("[options]\n# " + pinMarker(ref) + " begin\nIgnorePkg = proof\n")
	if _, err := renderRollingPin(ref, d, pin, true); err == nil {
		t.Fatal("accepted truncated ownership block")
	}
}

func TestALPMVersionAndDatabaseIdentity(t *testing.T) {
	version, err := alpmVersion("3:1.2.0-4.1")
	if err != nil || nativeVersion(version) != "3:1.2.0-4.1" {
		t.Fatalf("native epoch lost: %v, %v", version, err)
	}
	old, err := alpmVersion("3:1.2.0-3")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkNoDowngrade(version, old); err == nil {
		t.Fatal("ALPM downgrade accepted")
	}
	valid := []byte("%NAME%\nproof\n\n%VERSION%\n3:1.2.0-4.1\n\n%ARCH%\nx86_64\n\n%INSTALLDATE%\n1700000000\n\n")
	record, err := alpmDesc(valid)
	if err != nil || !proto.Equal(record.GetVersion(), version) {
		t.Fatalf("ALPM identity: %v, %v", record, err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(valid), []byte("%NAME%\nother\n\n")...), []byte("%NAME%\nproof\n\n"), valid[:len(valid)-2]} {
		if _, err := alpmDesc(bad); err == nil {
			t.Fatalf("accepted incomplete or duplicate ALPM identity %q", bad)
		}
	}
}

func TestALPMDatabaseBusyAndForeignEdit(t *testing.T) {
	root := rootPackageFixtureDirectory(t)
	pkg := filepath.Join(root, "local", "proof-1.0-1")
	if err := os.MkdirAll(pkg, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pkg, "desc")
	data := []byte("%NAME%\nproof\n\n%VERSION%\n1.0-1\n\n%ARCH%\nx86_64\n\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := alpmDatabase(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("%INSTALLDATE%\n9\n\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := alpmDatabase(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before.revision, after.revision) {
		t.Fatal("external same-version reinstall identity ignored")
	}
	if err := os.WriteFile(filepath.Join(root, "db.lck"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := alpmDatabase(context.Background(), root); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy database: %v", err)
	}
}

func TestALPMSolverRejectsUnsignedReplacementAndForeignSource(t *testing.T) {
	valid := "proof\t2.0-1\tx86_64\tproof.pkg.tar.zst\t12\t" + strings.Repeat("ab", 32) + "\t" + base64.StdEncoding.EncodeToString([]byte("signed")) + "\tapproved\t\tbase\n"
	if _, err := parseALPMSelection([]byte(valid), "approved", false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(valid, "approved", "foreign", 1), strings.Replace(valid, "\t\tbase\n", "\tother\tbase\n", 1), strings.Replace(valid, base64.StdEncoding.EncodeToString([]byte("signed")), "", 1), valid + valid} {
		if _, err := parseALPMSelection([]byte(bad), "approved", false); err == nil {
			t.Fatalf("unsafe solver result accepted: %q", bad)
		}
	}
}

func TestZypperSummaryRejectsHiddenEffects(t *testing.T) {
	d := rollingDesired(false)
	db := &database{records: map[string]*resourcev1.NativePackageRecord{}, multiple: map[string]bool{}}
	valid := `<stream><install-summary packages-to-change="1" download-size="12"><to-install><solvable type="package" name="proof" edition="2.0-1" arch="x86_64" repository="approved"/></to-install></install-summary></stream>`
	entries, size, err := parseZypperSummary([]byte(valid), d, db, "approved")
	if err != nil || len(entries) != 1 || size != 12 {
		t.Fatalf("native summary: %v, %d, %v", entries, size, err)
	}
	for _, bad := range []string{strings.ReplaceAll(valid, "to-install", "to-downgrade"), strings.Replace(valid, "approved", "foreign", 1), strings.Replace(valid, `packages-to-change="1"`, `packages-to-change="2"`, 1), strings.Replace(valid, `type="package"`, `type="pattern"`, 1), strings.Replace(valid, "</stream>", `<message type="warning">incomplete</message></stream>`, 1)} {
		if _, _, err := parseZypperSummary([]byte(bad), d, db, "approved"); err == nil {
			t.Fatalf("unsafe summary accepted: %q", bad)
		}
	}
}

func TestALPMArchitectureReplacementRejectedForEveryEntry(t *testing.T) {
	for _, archs := range [][2]string{{"any", "x86_64"}, {"x86_64", "any"}} {
		for _, dependency := range []bool{false, true} {
			d := rollingDesired(true)
			d.Package.Architecture = archs[1]
			incoming := &resourcev1.NativePackageRecord{Package: proto.CloneOf(d.GetPackage()), Version: proto.CloneOf(d.GetExact())}
			if dependency {
				incoming.Package.NativeName = "independently-owned-dependency"
			}
			installed := proto.CloneOf(incoming)
			installed.Package.Architecture = archs[0]
			installed.Version.GetAlpm().Pkgver = "3.0"
			db := &database{records: map[string]*resourcev1.NativePackageRecord{packageKey(installed.GetPackage()): installed}}
			entry := rollingEntry(incoming, d, db, false)
			if err := validateEntries([]*resourcev1.PackageTransactionEntry{entry}, d, db); err == nil {
				t.Fatalf("accepted native-name replacement %s -> %s, dependency=%t", archs[0], archs[1], dependency)
			}
		}
	}
}

func TestALPMExternalIgnoreGroupRejectsInitialAndUpgradeSelections(t *testing.T) {
	valid := "proof\t2.0-1\tx86_64\tproof.pkg.tar.zst\t12\t" + strings.Repeat("ab", 32) + "\t" + base64.StdEncoding.EncodeToString([]byte("signed")) + "\tapproved\t\tbase protected\n"
	selected, err := parseALPMSelection([]byte(valid), "approved", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"IgnoreGroup = protected\n", "IgnoreGroup = prot*\n", "IgnorePkg = proof\n"} {
		if err := checkALPMHolds(policy, selected[0], false); err == nil {
			t.Fatalf("direct signed selection bypassed %q", policy)
		}
	}
	if err := checkALPMHolds("IgnoreGroup = unrelated\n", selected[0], false); err != nil {
		t.Fatal(err)
	}
}

func TestALPMHoldDefersNativeBracketGrammar(t *testing.T) {
	// libc [!a] excludes a; Go's pathname grammar treats ! as a member.
	// The held transaction must perform the complete native fnmatch check.
	selection := alpmSelection{groups: []string{"kernel-a"}}
	if err := checkALPMHolds("IgnoreGroup = kernel-[!a]\n", selection, false); err != nil {
		t.Fatalf("Go pathname semantics rejected a native non-match: %v", err)
	}
}

func TestZypperOwnedPinUsesOneConjunctiveNamePredicate(t *testing.T) {
	d := rollingDesired(false)
	block := rollingPinBlock(packageRef(d.GetPackage()), d, false)
	if strings.Contains(string(block), "solvable_arch:") || !strings.Contains(string(block), "complex: AttrMatchData solvable:name proof T SolvableRange\\ !=\\ 0:2.0-1\\ x86_64") {
		t.Fatalf("native lock attributes are disjunctive: %s", block)
	}
	for _, test := range []struct {
		name, arch string
		overlap    bool
	}{
		{"proof", "x86_64", true}, {"proof", "noarch", false}, {"unrelated", "x86_64", false},
	} {
		identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: test.name, Architecture: test.arch}
		if got := checkZypperExternalLocks(block, identity) != nil; got != test.overlap {
			t.Fatalf("predicate overlap %s/%s=%t", test.name, test.arch, got)
		}
	}
	if err := checkZypperExternalLocks([]byte("type: package\nsolvable_name: unrelated\nsolvable_arch: x86_64\n"), d.GetPackage()); err == nil {
		t.Fatal("ORed external architecture matcher dismissed as unrelated name")
	}
}
