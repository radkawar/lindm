//go:build linux

package vmlab

import (
	"context"
	"time"
)

func resourceFixtureEvidence(ctx context.Context, packages *nativeGuestPackages) ([]VMResourceNativeRecord, error) {
	command := "cd " + resourceFixtureRoot + "; cat keys.colons; sha256sum repository.asc repository.gpg https.crt; "
	if packages.backend.DNF() {
		command += "gpgv --keyring " + resourceFixtureRoot + "/repository.gpg repo/repodata/repomd.xml.asc repo/repodata/repomd.xml; sha256sum repo/repodata/* repo/*.rpm; rpm --version; " +
			// Fedora's DNF5 versus EL's DNF4 with its versionlock plugin and entrypoint interpreter.
			"if command -v dnf5 >/dev/null; then dnf5 --version; python3 -c 'import libdnf5; print(libdnf5.__file__)'; else dnf --version; head -1 /usr/bin/dnf; rpm -q dnf python3-dnf python3-dnf-plugin-versionlock rpm-plugin-selinux; cat /etc/dnf/plugins/versionlock.conf; fi"
	} else {
		// A gpgv-free guest (Debian 13 after the lab's gnupg is purged) checks
		// the fixture signature with APT 3's own verifier, sqv.
		command += "if command -v gpgv >/dev/null; then gpgv --keyring " + resourceFixtureRoot + "/repository.gpg repo/dists/stable/InRelease; else out=$(mktemp -u); sqv --keyring " + resourceFixtureRoot + "/repository.gpg --cleartext --output \"$out\" repo/dists/stable/InRelease; rm -f \"$out\"; fi; " +
			"sha256sum repo/dists/stable/InRelease repo/dists/stable/Release repo/dists/stable/Release.gpg repo/dists/stable/main/binary-*/Packages repo/*.deb; dpkg --version; apt-get --version; " +
			"printf 'image verifiers before lab tools:\\n'; cat image-verifiers.txt; printf 'verifiers after fixture signing:\\n'; cat fixture-verifiers.txt; if test -e purged-verifiers.txt; then cat purged-verifiers.txt; fi"
	}
	record, err := resourceOracle(ctx, packages.vm, "native-signed-repository-toolchain", command)
	if err != nil {
		return nil, err
	}
	// This root-local protobuf config contains public source trust and allowed
	// roots, not keys or enrollment secrets. It is distinct from signed policy.
	config, err := packages.vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 128<<10, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return []VMResourceNativeRecord{record, resourceNativeRecord("root-provisioned-public-resource-config", config)}, nil
}
