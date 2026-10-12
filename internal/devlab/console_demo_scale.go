package devlab

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// consoleDemoSyntheticUpdates is the number of synthetic security updates the
// console demo's controlled Fedora repository publishes beside its recorded
// vendor node. Each update covers consoleDemoSubpackages binary packages, so
// a host carrying every affected build reports 2,000 AFFECTED findings. Their
// base names start at consoleDemoUpdateBase, above any bulk package index.
const (
	consoleDemoSyntheticUpdates = 500
	consoleDemoSubpackages      = 4
	consoleDemoUpdateBase       = 20000
)

// ConsoleDemoPackage is one synthetic binary RPM the console demo's controlled
// Fedora repository fixes: installed at Installed it is AFFECTED until Fixed.
type ConsoleDemoPackage struct {
	Name, Installed, Fixed string
}

// consoleDemoUpdate is one synthetic, explicitly labelled security update.
type consoleDemoUpdate struct {
	id, severity, issued string
	packages             []ConsoleDemoPackage
}

var syntheticPackageStems = []string{
	"aurora", "basalt", "cobalt", "delta", "ember", "fjord", "garnet", "harbor", "indigo", "juniper",
	"kelvin", "lumen", "meridian", "nimbus", "onyx", "prism", "quartz", "raven", "sierra", "tundra",
	"umbra", "vertex", "willow", "xenon", "yarrow", "zephyr", "codec", "crypto", "parser", "render",
	"sched", "stream", "vector", "widget", "yaml", "json", "xml", "http", "tls", "sql",
	"zstd", "dbus", "gtk4", "qt6", "audio", "camera", "printer", "bluetooth", "firmware", "modules",
	"spell", "fonts", "locale", "geo", "math", "image", "pdf", "office", "search", "sync",
}

var syntheticPackagePrefixes = map[string][]string{
	"dpkg": {"lib", "python3-", "golang-", "node-", "ruby-", "r-cran-", "texlive-", "fonts-", "gir1.2-", "librust-", "libghc-", "php-"},
	"rpm":  {"lib", "python3-", "golang-github-", "nodejs-", "rubygem-", "R-", "texlive-", "google-noto-", "perl-", "rust-", "ghc-", "php-pecl-"},
}

var syntheticPackageSuffixes = map[string][]string{
	"dpkg": {"", "-dev", "-doc", "-common", "-data", "-utils", "-tools", "-bin", "-plugins", "0", "1t64", "-dbgsym"},
	"rpm":  {"", "-devel", "-doc", "-libs", "-common", "-data", "-utils", "-tools", "-plugins", "-tests", "-static", "-debuginfo"},
}

// syntheticPackageBase returns the index-th unique base name for manager
// "dpkg" or "rpm" (mixed radix over prefix and two stems, unique below
// 43,200). Every 97th base is a long multi-component name (over 100
// characters) so console layouts meet the overflow cases real catalogs contain.
func syntheticPackageBase(manager string, index int) string {
	prefixes, stems := syntheticPackagePrefixes[manager], syntheticPackageStems
	prefix := prefixes[index%len(prefixes)]
	first, second := stems[(index/len(prefixes))%len(stems)], stems[(index/len(prefixes)/len(stems))%len(stems)]
	if index%97 != 13 {
		return prefix + first + "-" + second
	}
	parts := []string{first, second}
	for part := range 12 {
		parts = append(parts, stems[(index+part*7)%len(stems)])
	}
	return prefix + strings.Join(parts, "-")
}

// SyntheticPackageName returns the index-th deterministic, unique synthetic
// package name for manager "dpkg" or "rpm".
func SyntheticPackageName(manager string, index int) string {
	suffixes := syntheticPackageSuffixes[manager]
	return syntheticPackageBase(manager, index) + suffixes[(index/7)%len(suffixes)]
}

// SyntheticPackageVersion returns a deterministic version string; every 89th
// is a long upstream snapshot version of the kind distribution backports use.
func SyntheticPackageVersion(manager string, index int) string {
	long := index%89 == 7
	switch {
	case manager == "rpm" && long:
		return fmt.Sprintf("0:%d.%d.0~rc%d^20261012git1729d34db33fcafe%04d.cuda12.8.nvidia570-%d.fc44.1.snapshot.backport", 1+index%9, index%31, 1+index%4, index, 1+index%5)
	case manager == "rpm":
		return fmt.Sprintf("0:%d.%d.%d-%d.fc44", 1+index%9, index%31, index%17, 1+index%5)
	case long:
		return fmt.Sprintf("2:%d.%d.0~rc%d+git20261012.1729.gd34db33fcafe%04d+dfsg1-0ubuntu0.24.04.%d~ppa%d+build.synthetic", 1+index%9, index%31, 1+index%4, index, 1+index%5, 1+index%7)
	default:
		return fmt.Sprintf("%d.%d.%d-%dubuntu%d", 1+index%9, index%31, index%17, 1+index%5, index%3)
	}
}

// consoleDemoUpdates returns the deterministic synthetic updates. Severities
// cycle so every severity filter and sort has many rows.
func consoleDemoUpdates() []consoleDemoUpdate {
	severities := []string{"Critical", "Important", "Important", "Moderate", "Moderate", "Moderate", "Low", "Low"}
	suffixes := []string{"", "-libs", "-devel", "-doc"}[:consoleDemoSubpackages]
	updates := make([]consoleDemoUpdate, consoleDemoSyntheticUpdates)
	for i := range updates {
		base := syntheticPackageBase("rpm", consoleDemoUpdateBase+i)
		version, release := fmt.Sprintf("%d.%d.%d", 1+i%9, i%31, i%17), 1+i%5
		update := consoleDemoUpdate{id: fmt.Sprintf("FEDORA-2026-SYNTHETIC-%04d", i+1), severity: severities[i%len(severities)], issued: fmt.Sprintf("2026-%02d-%02d 08:%02d:00", 1+i%9, 1+i%28, i%60)}
		for _, suffix := range suffixes {
			update.packages = append(update.packages, ConsoleDemoPackage{Name: base + suffix, Installed: fmt.Sprintf("0:%s-%d.fc44", version, release), Fixed: fmt.Sprintf("0:%s-%d.fc44", version, release+1)})
		}
		updates[i] = update
	}
	return updates
}

// ConsoleDemoAffectedPackages lists every binary package the synthetic
// updates fix, at the installed build that each update reports AFFECTED.
func ConsoleDemoAffectedPackages() []ConsoleDemoPackage {
	var packages []ConsoleDemoPackage
	for _, update := range consoleDemoUpdates() {
		packages = append(packages, update.packages...)
	}
	return packages
}

// consoleDemoUpdateinfo renders the synthetic updates as updateinfo <update>
// nodes for the controlled Fedora repository. Titles and descriptions say they
// are synthetic; they cite no CVE so no real identifier is fabricated.
func consoleDemoUpdateinfo() ([]byte, error) {
	var out bytes.Buffer
	for _, update := range consoleDemoUpdates() {
		fmt.Fprintf(&out, `<update from="synthetic@lindm.invalid" status="stable" type="security" version="2.0"><id>%s</id><title>Synthetic demo update %s</title><issued date="%s"/><release>Fedora 44</release><severity>%s</severity><summary>Synthetic console demo security update, not a Fedora advisory</summary><description>Synthetic fixture for console scale review.</description><references/><pkglist><collection short="F44"><name>Fedora 44</name>`, update.id, update.id, update.issued, update.severity)
		for _, pkg := range update.packages {
			var name bytes.Buffer
			if err := xml.EscapeText(&name, []byte(pkg.Name)); err != nil {
				return nil, err
			}
			epoch, evr, _ := strings.Cut(pkg.Fixed, ":")
			version, release, _ := strings.Cut(evr, "-")
			fmt.Fprintf(&out, `<package name="%s" version="%s" release="%s" epoch="%s" arch="x86_64"><filename>%s-%s-%s.x86_64.rpm</filename></package>`, name.String(), version, release, epoch, name.String(), version, release)
		}
		out.WriteString("</collection></pkglist></update>")
	}
	return out.Bytes(), nil
}
