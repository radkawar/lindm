//go:build linux

package vmlab

import (
	"errors"
	"strings"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// debianInstallerImage installs from the signed netinst ISO, never from unsigned
// Debian cloud metadata. Packages come from signed Debian repositories at
// installation time.
func debianInstallerImage(m *labv1.ImageManifest) (*installerImage, error) {
	release := platform.ForManifest(m.Distribution, m.Version)
	if release.Lab.Installer != platform.DebianInstaller || m.Edition != "netinst" || !strings.HasSuffix(m.ImageFilename, "-netinst.iso") || m.ChecksumMode != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512 {
		return nil, errors.New("debian installed image requires a signed netinst manifest of a release maintained with debian-installer")
	}
	version := m.Version
	return &installerImage{
		label:     release.Key,
		installer: platform.DebianInstaller,
		cache:     "debian-installed",
		version:   debianInstallerRecipeVersion,
		memoryMiB: 2048,
		recipe: func(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
			return debianInstallerRecipe(version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic)
		},
		probes: []installedProbe{
			{"distribution", ". /etc/os-release; test \"$ID\" = " + nativeQuote(release.ID)},
			{"version", ". /etc/os-release; test \"$VERSION_ID\" = " + nativeQuote(m.Version)},
			{"source_marker", installerSourceMarkerProbe(installerSourceMarkerPath, m.Sha256)},
			{"root_filesystem", "test \"$(findmnt -n -o FSTYPE /)\" = ext4"},
			{"package_tool", "command -v dpkg-query >/dev/null"},
			{"privilege_tool", "command -v sudo >/dev/null"},
		},
	}, nil
}
