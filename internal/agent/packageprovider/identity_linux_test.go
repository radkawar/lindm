// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/dnf"
)

// neutralFixture is desiredFixture with the architecture left to the device.
func neutralFixture(ecosystem resourcev1.PackageEcosystem) *resourcev1.ResourceDesiredState {
	d := desiredFixture(ecosystem)
	d.GetNativePackage().GetPackage().Architecture = ""
	d.GetRef().CanonicalKey = packageRef(d.GetNativePackage().GetPackage()).GetCanonicalKey()
	return d
}

func TestNativeArchitectureComesFromThePackageTool(t *testing.T) {
	for _, test := range []struct {
		ecosystem  resourcev1.PackageEcosystem
		executable string
		args       []string
		output     string
	}{
		{resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, "/usr/bin/dpkg", []string{"--print-architecture"}, "arm64\n"},
		{resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, "/usr/bin/rpm", []string{"--eval", "%{_arch}"}, "aarch64\n"},
	} {
		var stdout, stderr string
		calls := 0
		p := &Provider{ecosystem: test.ecosystem, run: func(_ context.Context, executable string, args []string, _ string, _ []string) (nativeResult, error) {
			calls++
			if executable != test.executable || !slices.Equal(args, test.args) {
				t.Fatalf("native architecture probe = %s %q", executable, args)
			}
			return nativeResult{stdout: []byte(stdout), stderr: []byte(stderr)}, nil
		}}
		stdout = test.output
		if err := p.resolveNativeArchitecture(context.Background()); err != nil || p.native != strings.TrimSpace(test.output) || calls != 1 {
			t.Fatalf("native architecture = %q, %v", p.native, err)
		}
		independent := architectureIndependent(test.ecosystem) + "\n"
		for _, bad := range []string{"", "\n", "amd64", "amd64\ni386\n", "%{_arch}\n", "am d64\n", independent} {
			stdout, p.native = bad, ""
			if err := p.resolveNativeArchitecture(context.Background()); err == nil || p.native != "" {
				t.Fatalf("accepted native architecture output %q", bad)
			}
		}
		stdout, stderr = test.output, "warning: database damaged\n"
		if err := p.resolveNativeArchitecture(context.Background()); err == nil {
			t.Fatal("accepted a native architecture probe that warned")
		}
		stderr = ""
	}
	alpm := func(architectures ...string) *Provider {
		p := &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM, config: Config{Native: &agentv1.NativePackageProviderConfig{}}}
		for _, architecture := range architectures {
			p.config.Native.Sources = append(p.config.Native.Sources, &agentv1.NativePackageSource{Repository: &resourcev1.RepositoryDesired{Source: &resourcev1.RepositoryDesired_Alpm{Alpm: &resourcev1.AlpmRepository{Architecture: architecture}}}})
		}
		return p
	}
	for architectures, want := range map[string]string{"x86_64": "x86_64", "x86_64 x86_64": "x86_64", "x86_64 aarch64": "", "": ""} {
		p := alpm(strings.Fields(architectures)...)
		if err := p.resolveNativeArchitecture(context.Background()); err != nil || p.native != want {
			t.Fatalf("ALPM sources %q native = %q, %v", architectures, p.native, err)
		}
	}
}

func TestNeutralPackageResolvesToOneNativeRecord(t *testing.T) {
	p := &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, native: "amd64"}
	neutral := neutralFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB).GetNativePackage().GetPackage()
	resolve := func(rows string) (*resourcev1.PackageIdentity, *resourcev1.PackageIdentity, error) {
		t.Helper()
		db, err := parseDatabase([]byte("ii \tbase\t1.0\tamd64\n"+rows), resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
		if err != nil {
			t.Fatal(err)
		}
		target, err := p.nativeTarget(db, neutral)
		if err != nil {
			return nil, nil, err
		}
		resolved, err := p.resolveIdentity(db, neutral)
		return target, resolved, err
	}
	for rows, want := range map[string]string{"ii \tproof\t1.0\tamd64\n": "amd64", "ii \tproof\t1.0\tall\n": "all"} {
		target, resolved, err := resolve(rows)
		if err != nil || target.GetArchitecture() != want || !proto.Equal(target, resolved) {
			t.Fatalf("installed %q resolved to %v / %v, %v", rows, target, resolved, err)
		}
	}
	// Not installed natively (nothing, or only a foreign architecture): the
	// solver gets the bare name; evidence names the native architecture.
	for _, rows := range []string{"", "ii \tproof\t1.0\ti386\n"} {
		target, resolved, err := resolve(rows)
		if err != nil || target.GetArchitecture() != "" || resolved.GetArchitecture() != "amd64" || resolved.GetNativeName() != "proof" {
			t.Fatalf("uninstalled resolved to %v / %v, %v", target, resolved, err)
		}
	}
	db := &database{records: map[string]*resourcev1.NativePackageRecord{
		"proof/x86_64": {Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: "proof", Architecture: "x86_64"}},
		"proof/noarch": {Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: "proof", Architecture: "noarch"}},
	}}
	rpm := &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, native: "x86_64"}
	if _, err := rpm.resolveIdentity(db, neutralFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM).GetNativePackage().GetPackage()); !errors.Is(err, ErrConflict) {
		t.Fatalf("ambiguous native and architecture-independent records = %v", err)
	}
	pinned := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM).GetNativePackage().GetPackage()
	if resolved, err := rpm.resolveIdentity(db, pinned); err != nil || !proto.Equal(resolved, pinned) || resolved == pinned {
		t.Fatalf("pinned identity resolved to %v, %v", resolved, err)
	}
	if _, err := (&Provider{}).resolveIdentity(db, neutral); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unresolved native architecture = %v", err)
	}
}

func TestNeutralPackageAcceptsOnlyNativeSolverSelections(t *testing.T) {
	p := &Provider{ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, native: "arm64"}
	d := neutralFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB).GetNativePackage()
	d.Version = &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}
	db := &database{records: map[string]*resourcev1.NativePackageRecord{}, multiple: map[string]bool{}}
	entry := func(name, architecture string, direct bool) *resourcev1.PackageTransactionEntry {
		return &resourcev1.PackageTransactionEntry{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: name, Architecture: architecture}, After: debVersion("1.0-1"), DirectRequest: direct}
	}
	for _, architecture := range []string{"arm64", "all"} {
		if !p.requests(d.GetPackage(), entry("proof", architecture, true).GetPackage()) {
			t.Fatalf("native %s selection is not the requested package", architecture)
		}
		if err := p.validateEntries([]*resourcev1.PackageTransactionEntry{entry("proof", architecture, true), entry("libproof", "arm64", false)}, d, db); err != nil {
			t.Fatalf("native %s selection refused: %v", architecture, err)
		}
	}
	for name, entries := range map[string][]*resourcev1.PackageTransactionEntry{
		"foreign architecture":       {entry("proof", "amd64", true)},
		"foreign as dependency":      {entry("proof", "amd64", false)},
		"provider substitute":        {entry("proof-provider", "arm64", false)},
		"native and independent":     {entry("proof", "arm64", true), entry("proof", "all", true)},
		"unflagged native selection": {entry("proof", "arm64", false)},
	} {
		if err := p.validateEntries(entries, d, db); err == nil {
			t.Fatalf("%s accepted for a native-architecture package", name)
		}
	}
	pinned := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB).GetNativePackage()
	if p.requests(pinned.GetPackage(), entry("proof", "all", true).GetPackage()) || !p.requests(pinned.GetPackage(), entry("proof", "amd64", true).GetPackage()) {
		t.Fatal("pinned package matched another architecture")
	}
}

func TestNeutralPackageNativeSpecs(t *testing.T) {
	deb := neutralFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB).GetNativePackage()
	rpm := neutralFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM).GetNativePackage()
	installed := func(d *resourcev1.NativePackageDesired, architecture string) *resourcev1.PackageIdentity {
		identity := proto.CloneOf(d.GetPackage())
		identity.Architecture = architecture
		return identity
	}
	for _, test := range []struct{ got, want string }{
		{aptSpec(deb, deb.GetPackage()), "proof=1:2.0-1"},
		{aptSpec(deb, installed(deb, "all")), "proof:all=1:2.0-1"},
		{dnfSpec(rpm, rpm.GetPackage()), "proof-1:2.0-1.fc44"},
		{dnfSpec(rpm, installed(rpm, "noarch")), "proof-1:2.0-1.fc44.noarch"},
		{zypperTarget(rpm, rpm.GetPackage()), "proof=1:2.0-1.fc44"},
		{zypperTarget(rpm, installed(rpm, "x86_64")), "proof.x86_64=1:2.0-1.fc44"},
		{dnf4LockEntry(rpm), "proof-1:2.0-1.fc44"},
		{packageRef(rpm.GetPackage()).GetCanonicalKey(), "rpm/proof"},
	} {
		if test.got != test.want {
			t.Errorf("native spec = %q, want %q", test.got, test.want)
		}
	}
	pinned := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM).GetNativePackage()
	if got := dnfSpec(pinned, pinned.GetPackage()); got != "proof-1:2.0-1.fc44.x86_64" {
		t.Errorf("pinned DNF spec = %q", got)
	}
}

func TestNeutralPackagePinsFollowTheDesiredPackageOnly(t *testing.T) {
	deb := neutralFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB)
	pin := aptPin(deb.GetNativePackage())
	if !bytes.Contains(pin, []byte("\nPackage: proof\n")) || !pinMatches(resourcev1.Backend_BACKEND_APT, deb.GetRef(), deb.GetNativePackage(), pin) {
		t.Fatalf("native-architecture APT pin = %s", pin)
	}
	rpm := neutralFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	pin, err := renderDNFPin(rpm.GetRef(), rpm.GetNativePackage(), nil)
	if err != nil {
		t.Fatal(err)
	}
	document, err := dnf.ParseVersionlock(pin)
	if err != nil || len(document.Packages) != 1 || len(document.Packages[0].Conditions) != 1 || document.Packages[0].Conditions[0].Key != "evr" || document.Packages[0].Comment != pinMarker(rpm.GetRef()) {
		t.Fatalf("native-architecture DNF versionlock = %s, %v", pin, err)
	}
	if !pinMatches(resourcev1.Backend_BACKEND_DNF5, rpm.GetRef(), rpm.GetNativePackage(), pin) {
		t.Fatal("native-architecture DNF versionlock not converged")
	}
	pinned := desiredFixture(resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM)
	pinnedLock, err := renderDNFPin(pinned.GetRef(), pinned.GetNativePackage(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if pinMatches(resourcev1.Backend_BACKEND_DNF5, rpm.GetRef(), rpm.GetNativePackage(), bytes.ReplaceAll(pinnedLock, []byte("rpm/proof/x86_64"), []byte("rpm/proof"))) {
		t.Fatal("an architecture-pinned lock converged a native-architecture package")
	}
	d := rollingDesired(false)
	d.Package.Architecture = ""
	ref := packageRef(d.GetPackage())
	locks, err := renderRollingPin(ref, d, nil, false)
	if err != nil || !bytes.Contains(locks, []byte("solvable_name: proof\nversion: != 0:2.0-1\n")) || !rollingPinMatches(ref, d, locks, false) {
		t.Fatalf("native-architecture zypp lock = %s, %v", locks, err)
	}
	external := []byte("type: package\nmatch_type: exact\ncase_sensitive: on\ncomplex: AttrMatchData solvable:name proof T SolvableRange\\ !=\\ 0:1.0-1\\ i586\n")
	if _, err := renderRollingPin(ref, d, external, false); err == nil {
		t.Fatal("native-architecture lock ignored an external lock on another architecture")
	}
	if _, err := renderRollingPin(packageRef(rollingDesired(false).GetPackage()), rollingDesired(false), external, false); err != nil {
		t.Fatalf("pinned x86_64 lock refused an unrelated i586 lock: %v", err)
	}
}
