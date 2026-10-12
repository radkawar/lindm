//go:build linux

package vmlab

import (
	"context"
	"os"
	"path/filepath"

	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// exerciseUpdateRepository reinstalls the signed initial package from lindmd's
// own HTTPS native repository before the independently signed TUF update. Native
// repository metadata and package signatures remain mandatory; the lab CA only
// authenticates transport and is never imported as a package signer.
func exerciseUpdateRepository(ctx context.Context, p *nativeGuestPackages, repository string, artifact packaging.Artifact) error {
	if p.backend != platform.BackendPacman && p.backend != platform.BackendZypper {
		return nil
	}
	ca, err := os.ReadFile(filepath.Join(devlab.FixturePath(repository), "transport-ca.crt"))
	if err != nil {
		return err
	}
	caPath := nativeGuestDir + "/repository-ca.pem"
	if err := p.uploadBytes(ctx, caPath, ca); err != nil {
		return err
	}
	if p.backend == platform.BackendPacman {
		config := "[options]\nArchitecture = auto\nGPGDir = " + nativeGuestDir + "/pacman-gnupg\nCacheDir = " + nativeGuestDir + "/https-archives\nSigLevel = PackageRequired DatabaseRequired TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nXferCommand = /usr/bin/curl --fail --silent --show-error --cacert " + caPath + " --output %o %u\n[lindm]\nServer = https://localhost:18444/repo/arch\n"
		if err := p.uploadBytes(ctx, nativeGuestDir+"/https-pacman.conf", []byte(config)); err != nil {
			return err
		}
		command := "install -d -m 0755 " + nativeGuestDir + "/https-archives; pacman --noconfirm --config " + nativeGuestDir + "/https-pacman.conf -Syy lindm/lindm-agent"
		if err := p.command(ctx, "reinstall from lindmd signed HTTPS pacman repository", command, nil); err != nil {
			return err
		}
	} else {
		// libzypp accepts no per-repository CA file (only ssl_capath; an
		// unknown ssl_cacert parameter leaves the lab CA untrusted). As the
		// console's zypper command, add the transport CA to the system store.
		repos := nativeGuestDir + "/https-repos"
		if err := p.command(ctx, "trust lindmd transport CA and prepare isolated HTTPS zypper repository", "install -m 0644 "+caPath+" /etc/pki/trust/anchors/lindm-update-fixture.crt; update-ca-certificates; install -d -m 0755 "+repos, nil); err != nil {
			return err
		}
		config := "[lindm]\nname=lindm signed update fixture\nenabled=1\nautorefresh=0\nbaseurl=https://localhost:18444/repo/rpm\ngpgcheck=1\nrepo_gpgcheck=1\npkg_gpgcheck=1\n"
		if err := p.uploadBytes(ctx, repos+"/lindm.repo", []byte(config)); err != nil {
			return err
		}
		zypper := "zypper --non-interactive --reposd-dir " + repos + " --cache-dir " + nativeGuestDir + "/https-zypp-cache "
		command := zypper + "refresh --force lindm; " + zypper + "--no-refresh install --force --no-recommends --from lindm " + nativeQuote("lindm-agent="+artifact.Version+"-"+packaging.RPMRelease)
		if err := p.command(ctx, "reinstall from lindmd signed HTTPS zypper repository", command, nil); err != nil {
			return err
		}
	}
	return p.assertVersion(ctx, artifact)
}
