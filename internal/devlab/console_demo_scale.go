// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"fmt"
	"strings"
)

// Synthetic package catalog for console demo scale fixtures. No vendor feed
// claims these packages; they only exercise inventory volume and layout.
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
