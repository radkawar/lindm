//go:build linux

package vmlab

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// aptOriginTruthCommand derives package origins through APT's own resolver,
// independently of the agent's direct reading of /var/lib/apt/lists:
// `apt-cache policy` names each package file's Release (o=, l=, a=, n=), and
// per-package policy names the package files listing each version. dpkg maps
// apt-cache's package names back to exact installed identities; apt-cache
// omits the native-architecture qualifier dpkg's binary:Package carries for
// Multi-Arch: same packages, so the native architecture is reported first.
const aptOriginTruthCommand = `env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -c 'set -eu
/usr/bin/apt-cache policy
printf "@@MAP@@\n"
/usr/bin/dpkg --print-architecture
/usr/bin/dpkg-query --show --showformat="\${db:Status-Status}\t\${binary:Package}\t\${Package}\t\${Version}\t\${Architecture}\n" | /bin/sed -n "s/^installed\t//p"
printf "@@PACKAGES@@\n"
/usr/bin/dpkg-query --show --showformat="\${db:Status-Status}\t\${binary:Package}\n" | /bin/sed -n "s/^installed\t//p" | /usr/bin/xargs -r /usr/bin/apt-cache policy'`

// ubuntuArchiveSigner is the oracle's own copy of the key that signs every
// Ubuntu 24.04 pocket (Ubuntu Archive Automatic Signing Key (2018)).
const ubuntuArchiveSigner = "F6ECB3762474EDA9D21B7022871920D1991BC93C"

type aptPackageKey struct{ name, version, architecture string }

// aptRelease is the Release identity apt-cache reports for one package file.
type aptRelease struct{ origin, label, suite, codename string }

// parseAptOriginTruth returns, for each installed package, the set of Release
// identities whose package files list its exact installed version.
func parseAptOriginTruth(data []byte) (map[aptPackageKey][]aptRelease, error) {
	text := string(data)
	policy, rest, ok := strings.Cut(text, "@@MAP@@\n")
	if !ok {
		return nil, errors.New("apt origin truth missing package map")
	}
	mapping, packages, ok := strings.Cut(rest, "@@PACKAGES@@\n")
	if !ok || strings.ContainsAny(text, "\x00\r") {
		return nil, errors.New("invalid apt origin truth shape")
	}
	files, err := parseAptPackageFiles(policy)
	if err != nil {
		return nil, err
	}
	native, mapping, ok := strings.Cut(mapping, "\n")
	if !ok || native == "" || strings.ContainsAny(native, ": \t") {
		return nil, errors.New("invalid apt origin truth native architecture")
	}
	binary := map[string]aptPackageKey{}
	for _, line := range strings.Split(strings.TrimSuffix(mapping, "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || fields[0] == "" || fields[1] == "" || fields[2] == "" || fields[3] == "" {
			return nil, errors.New("invalid apt origin truth package map")
		}
		name := strings.TrimSuffix(fields[0], ":"+native)
		if _, duplicate := binary[name]; duplicate {
			return nil, errors.New("duplicate apt origin truth package")
		}
		binary[name] = aptPackageKey{name: fields[1], version: fields[2], architecture: fields[3]}
	}
	result := make(map[aptPackageKey][]aptRelease, len(binary))
	var current aptPackageKey
	var inPackage, matching bool
	for _, line := range strings.Split(packages, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		switch {
		case line == "":
		case indent == 0:
			key, known := binary[strings.TrimSuffix(line, ":")]
			if !strings.HasSuffix(line, ":") || !known {
				return nil, fmt.Errorf("apt origin truth names an unknown package")
			}
			if _, repeated := result[key]; repeated {
				return nil, errors.New("apt origin truth repeats a package")
			}
			current, inPackage, matching = key, true, false
			result[key] = []aptRelease{}
		case !inPackage:
			return nil, errors.New("apt origin truth line outside a package")
		case indent == 2:
			// Installed:, Candidate:, Version table:
		case strings.HasPrefix(line, " *** ") || indent == 5:
			version, _, _ := strings.Cut(strings.TrimPrefix(trimmed, "*** "), " ")
			matching = version == current.version
		case indent >= 6:
			// apt-cache prints a package-file line as seven spaces and a
			// width-4 pin priority, so 1001 and -100 pins sit at indent 7 and
			// 500 or 100 at indent 8: recognize the priority, not the width.
			priority, file, ok := strings.Cut(trimmed, " ")
			if _, err := strconv.Atoi(priority); !ok || err != nil || file == "" {
				return nil, errors.New("invalid apt origin truth source line")
			}
			if !matching {
				continue
			}
			if file == "/var/lib/dpkg/status" {
				continue
			}
			release, known := files[file]
			if !known {
				return nil, errors.New("apt origin truth lists an undeclared package file")
			}
			if !slices.Contains(result[current], release) {
				result[current] = append(result[current], release)
			}
		default:
			return nil, errors.New("unexpected apt origin truth indentation")
		}
	}
	if len(result) != len(binary) {
		return nil, errors.New("apt origin truth omitted installed packages")
	}
	return result, nil
}

// parseAptPackageFiles reads the "Package files:" section of `apt-cache policy`.
func parseAptPackageFiles(policy string) (map[string]aptRelease, error) {
	files := map[string]aptRelease{}
	section, _, _ := strings.Cut(policy, "Pinned packages:")
	_, section, ok := strings.Cut(section, "Package files:\n")
	if !ok {
		return nil, errors.New("apt origin truth missing package files")
	}
	file := ""
	for _, line := range strings.Split(section, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
		case strings.HasPrefix(trimmed, "release "):
			if file == "" {
				return nil, errors.New("apt origin truth release without a package file")
			}
			var release aptRelease
			for _, pair := range strings.Split(strings.TrimPrefix(trimmed, "release "), ",") {
				key, value, ok := strings.Cut(pair, "=")
				if !ok {
					return nil, errors.New("invalid apt origin truth release")
				}
				switch key {
				case "o":
					release.origin = value
				case "l":
					release.label = value
				case "a":
					release.suite = value
				case "n":
					release.codename = value
				}
			}
			files[file] = release
		case strings.HasPrefix(trimmed, "origin "):
		default:
			_, name, ok := strings.Cut(trimmed, " ")
			if !ok {
				return nil, errors.New("invalid apt origin truth package file")
			}
			file = name
			files[file] = aptRelease{}
		}
	}
	return files, nil
}

// compareAptOrigins requires the agent's per-package listings to name exactly
// APT's Release identities, every listing of a stock lab source to carry a
// verified signature, and every Ubuntu-origin listing to be signed by the
// Ubuntu archive key the advisory matcher pins.
func compareAptOrigins(expected map[aptPackageKey][]aptRelease, packages []*inventoryv1.Package) error {
	if expected == nil {
		return errors.New("apt origin truth unavailable")
	}
	seen := 0
	for _, pkg := range packages {
		if pkg.GetManager() != "dpkg" {
			continue
		}
		seen++
		want, ok := expected[aptPackageKey{name: pkg.GetName(), version: pkg.GetVersion(), architecture: pkg.GetArchitecture()}]
		if !ok {
			return errors.New("agent package missing from apt origin truth")
		}
		origin := pkg.GetOrigin()
		if origin.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
			return fmt.Errorf("agent APT origin collection did not succeed: %s", origin.GetStatus())
		}
		var got []aptRelease
		for _, listing := range origin.GetListings() {
			if listing.GetSignature() != inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED {
				return fmt.Errorf("stock APT source listing not verified: %s", listing.GetSignature())
			}
			if listing.GetOrigin() == "Ubuntu" && listing.GetSigner() != ubuntuArchiveSigner {
				return errors.New("an Ubuntu-origin listing is not signed by the Ubuntu archive key")
			}
			release := aptRelease{origin: listing.GetOrigin(), label: listing.GetLabel(), suite: listing.GetSuite(), codename: listing.GetCodename()}
			if !slices.Contains(got, release) {
				got = append(got, release)
			}
		}
		if len(got) != len(want) {
			return fmt.Errorf("apt origin comparison failed for an installed package: %d listed releases, want %d", len(got), len(want))
		}
		for _, release := range want {
			if !slices.Contains(got, release) {
				return errors.New("apt origin comparison failed: a Release listing the installed version is missing")
			}
		}
	}
	if seen != len(expected) {
		return errors.New("apt origin truth and agent package sets differ")
	}
	return nil
}
