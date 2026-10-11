//go:build linux

package vmlab

import (
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// mintPolicyTruth is apt-cache policy presentation for a Mint-like guest:
// Ubuntu pockets, the Mint archive, and one version listed by both.
const mintPolicyTruth = `Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://packages.linuxmint.com zena/main amd64 Packages
     release v=22.3,o=linuxmint,a=zena,n=zena,l=linuxmint,c=main,b=amd64
     origin packages.linuxmint.com
 500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=main,b=amd64
     origin archive.ubuntu.com
 500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-security,n=noble,l=Ubuntu,c=main,b=amd64
     origin security.ubuntu.com
 500 http://archive.ubuntu.com/ubuntu noble/main i386 Packages
     release v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu,c=main,b=i386
     origin archive.ubuntu.com
Pinned packages:
@@MAP@@
amd64
openssl:amd64	openssl	3.0.13-0ubuntu3.5	amd64
libc6:i386	libc6	2.39-0ubuntu8	i386
mint-common	mint-common	2.3.1	all
shared	shared	1.0	amd64
local-build	local-build	0.1	amd64
@@PACKAGES@@
openssl:
  Installed: 3.0.13-0ubuntu3.5
  Candidate: 3.0.13-0ubuntu3.5
  Version table:
 *** 3.0.13-0ubuntu3.5 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
        100 /var/lib/dpkg/status
     3.0.13-0ubuntu3 500
        500 http://archive.ubuntu.com/ubuntu noble/main i386 Packages
libc6:i386:
  Installed: 2.39-0ubuntu8
  Candidate: 2.39-0ubuntu8
  Version table:
 *** 2.39-0ubuntu8 500
        500 http://archive.ubuntu.com/ubuntu noble/main i386 Packages
        100 /var/lib/dpkg/status
mint-common:
  Installed: 2.3.1
  Candidate: 2.3.1
  Version table:
 *** 2.3.1 500
        500 http://packages.linuxmint.com zena/main amd64 Packages
        100 /var/lib/dpkg/status
shared:
  Installed: 1.0
  Candidate: 1.0
  Version table:
 *** 1.0 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
        100 /var/lib/dpkg/status
     1.0 500
        500 http://packages.linuxmint.com zena/main amd64 Packages
local-build:
  Installed: 0.1
  Candidate: 0.1
  Version table:
 *** 0.1 100
        100 /var/lib/dpkg/status
`

func TestAptOriginOracleMatchesAgentListings(t *testing.T) {
	truth, err := parseAptOriginTruth([]byte(mintPolicyTruth))
	if err != nil {
		t.Fatal(err)
	}
	verified := inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED
	ubuntu := func(suite string) *inventoryv1.AptListing {
		return &inventoryv1.AptListing{Origin: "Ubuntu", Label: "Ubuntu", Suite: suite, Codename: "noble", Signature: verified, Signer: ubuntuArchiveSigner}
	}
	mint := &inventoryv1.AptListing{Origin: "linuxmint", Label: "linuxmint", Suite: "zena", Codename: "zena", Signature: verified, Signer: strings.Repeat("AB", 20)}
	pkg := func(name, version, arch string, listings ...*inventoryv1.AptListing) *inventoryv1.Package {
		return &inventoryv1.Package{Name: name, Version: version, Architecture: arch, Manager: "dpkg", Origin: &inventoryv1.PackageOrigin{Status: truthSuccess, Listings: listings}}
	}
	agent := func() []*inventoryv1.Package {
		return []*inventoryv1.Package{
			pkg("openssl", "3.0.13-0ubuntu3.5", "amd64", ubuntu("noble-security"), ubuntu("noble-updates")),
			pkg("libc6", "2.39-0ubuntu8", "i386", ubuntu("noble")),
			pkg("mint-common", "2.3.1", "all", mint),
			pkg("shared", "1.0", "amd64", ubuntu("noble-updates"), mint),
			pkg("local-build", "0.1", "amd64"),
		}
	}
	if err := compareAptOrigins(truth, agent()); err != nil {
		t.Fatalf("matching origins rejected: %v", err)
	}
	for name, mutate := range map[string]func([]*inventoryv1.Package){
		"dropped ambiguous listing": func(p []*inventoryv1.Package) { p[3].Origin.Listings = p[3].Origin.Listings[:1] },
		"invented listing":          func(p []*inventoryv1.Package) { p[4].Origin.Listings = []*inventoryv1.AptListing{ubuntu("noble")} },
		"wrong pocket":              func(p []*inventoryv1.Package) { p[1].Origin.Listings[0].Suite = "noble-updates" },
		"unverified stock source": func(p []*inventoryv1.Package) {
			p[2].Origin.Listings[0].Signature, p[2].Origin.Listings[0].Signer = inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_UNVERIFIED, ""
		},
		"foreign Ubuntu signer": func(p []*inventoryv1.Package) { p[0].Origin.Listings[0].Signer = strings.Repeat("CD", 20) },
		"failed collection":     func(p []*inventoryv1.Package) { p[0].Origin = &inventoryv1.PackageOrigin{Status: truthUnavailable} },
		"missing package":       func(p []*inventoryv1.Package) { p[4].Manager = "rpm" },
	} {
		packages := agent()
		mutate(packages)
		if err := compareAptOrigins(truth, packages); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, bad := range map[string]string{
		"undeclared file": strings.Replace(mintPolicyTruth, " 500 http://packages.linuxmint.com zena/main amd64 Packages\n     release", " 500 http://elsewhere zena/main amd64 Packages\n     release", 1),
		"unknown package": strings.Replace(mintPolicyTruth, "mint-common:\n", "other:\n", 1),
		"missing map":     strings.Replace(mintPolicyTruth, "@@MAP@@\n", "", 1),
		"omitted package": strings.Replace(mintPolicyTruth, "local-build:\n  Installed: 0.1\n  Candidate: 0.1\n  Version table:\n *** 0.1 100\n        100 /var/lib/dpkg/status\n", "", 1),
	} {
		if _, err := parseAptOriginTruth([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// popPolicyTruth is apt-cache policy as printed on Pop!_OS 24.04, whose
// pop-default-settings pins o=pop-os-release at 1001: four-digit priorities
// shift package-file lines to indent 7 (and to indent 0 in the global list).
const popPolicyTruth = `Package files:
 100 /var/lib/dpkg/status
     release a=now
1001 http://apt.pop-os.org/release noble/main amd64 Packages
     release v=24.04,o=pop-os-release,a=noble,n=noble,l=Pop!_OS Release,c=main,b=amd64
     origin apt.pop-os.org
 500 http://apt.pop-os.org/ubuntu noble-updates/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=main,b=amd64
     origin apt.pop-os.org
Pinned packages:
@@MAP@@
amd64
gnome-shell:amd64	gnome-shell	46.0-0ubuntu5pop1	amd64
bash	bash	5.2.21-2ubuntu4	amd64
@@PACKAGES@@
gnome-shell:
  Installed: 46.0-0ubuntu5pop1
  Candidate: 46.0-0ubuntu5pop1
  Version table:
 *** 46.0-0ubuntu5pop1 1001
       1001 http://apt.pop-os.org/release noble/main amd64 Packages
        100 /var/lib/dpkg/status
     46.0-0ubuntu5 500
        500 http://apt.pop-os.org/ubuntu noble-updates/main amd64 Packages
bash:
  Installed: 5.2.21-2ubuntu4
  Candidate: 5.2.21-2ubuntu4
  Version table:
 *** 5.2.21-2ubuntu4 500
        500 http://apt.pop-os.org/ubuntu noble-updates/main amd64 Packages
        100 /var/lib/dpkg/status
`

func TestAptOriginOracleAcceptsFourDigitPins(t *testing.T) {
	truth, err := parseAptOriginTruth([]byte(popPolicyTruth))
	if err != nil {
		t.Fatal(err)
	}
	pop := aptRelease{origin: "pop-os-release", label: "Pop!_OS Release", suite: "noble", codename: "noble"}
	ubuntu := aptRelease{origin: "Ubuntu", label: "Ubuntu", suite: "noble-updates", codename: "noble"}
	if got := truth[aptPackageKey{"gnome-shell", "46.0-0ubuntu5pop1", "amd64"}]; len(got) != 1 || got[0] != pop {
		t.Fatalf("pinned vendor version origins = %v", got)
	}
	if got := truth[aptPackageKey{"bash", "5.2.21-2ubuntu4", "amd64"}]; len(got) != 1 || got[0] != ubuntu {
		t.Fatalf("Ubuntu version origins = %v", got)
	}
	bad := strings.Replace(popPolicyTruth, "       1001 http://apt.pop-os.org/release", "       high http://apt.pop-os.org/release", 1)
	if _, err := parseAptOriginTruth([]byte(bad)); err == nil {
		t.Fatal("a package-file line without a numeric priority was accepted")
	}
}
