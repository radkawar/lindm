//go:build linux

package vmlab

import (
	"errors"
	"strings"

	labv1 "lindm/gen/lindm/lab/v1"
)

// debianInstallerImage installs from the signed netinst ISO, never from unsigned
// Debian cloud metadata. Packages come from signed Debian repositories at
// installation time.
func debianInstallerImage(m *labv1.ImageManifest) (*installerImage, error) {
	if m.Distribution != "debian" || (m.Version != "12" && m.Version != "13") || m.Edition != "netinst" || !strings.HasSuffix(m.ImageFilename, "-netinst.iso") || m.ChecksumMode != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512 {
		return nil, errors.New("debian installed image requires a signed Debian 12 or 13 netinst manifest")
	}
	version := m.Version
	return &installerImage{
		label:     "debian",
		media:     "debian",
		cache:     "debian-installed",
		version:   debianInstallerRecipeVersion,
		memoryMiB: 2048,
		recipe: func(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
			return debianInstallerRecipe(version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic)
		},
		probes: []installedProbe{
			{"distribution", ". /etc/os-release; test \"$ID\" = debian"},
			{"version", ". /etc/os-release; test \"$VERSION_ID\" = " + nativeQuote(m.Version)},
			{"source_marker", installerSourceMarkerProbe(installerSourceMarkerPath, m.Sha256)},
			{"root_filesystem", "test \"$(findmnt -n -o FSTYPE /)\" = ext4"},
			{"package_tool", "command -v dpkg-query >/dev/null"},
			{"privilege_tool", "command -v sudo >/dev/null"},
		},
	}, nil
}
