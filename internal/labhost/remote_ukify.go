// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"fmt"
	"path/filepath"
	"strings"
)

// The Sparks (Ubuntu 24.04, systemd 255.4-1ubuntu8.12) do not install
// systemd-ukify, which builds the owned-boot recovery UKI on the lab host. The
// lab provisions that exact Ubuntu package privately: digest and size from
// Launchpad's published binary (getPublishedBinaries, binaryFileUrls), never a
// system package installation or PATH change. ukify is a Python script; its
// only further dependency, python3-pefile, must already be installed.
const (
	ukifyPackageVersion = "255.4-1ubuntu8.12"
	ukifyPackageURL     = "https://launchpad.net/ubuntu/+archive/primary/+files/systemd-ukify_" + ukifyPackageVersion + "_all.deb"
	ukifyPackageSHA256  = "f5bb84d1a68be0d5ca8373d003e9b05aa1f1314332a2e9345fd9d6f9ad31f285"
)

// recoveryUkifyLane reports whether a lane builds the owned-boot recovery UKI:
// every device-actions wipe run that includes an original-device recovery phase.
func recoveryUkifyLane(args []string) bool {
	if len(args) < 2 || args[1] != "device-actions" || FlagValue(args, "scenario") != "wipe" {
		return false
	}
	phase := FlagValue(args, "wipe-phase")
	return phase == "" || strings.HasPrefix(phase, "recovery-")
}

// recoveryUkify returns the absolute path of the host's private pinned ukify.
func (s *remoteStage) recoveryUkify(work string) (string, error) {
	tools := filepath.Join(work, "tools")
	root := filepath.Join(tools, "systemd-ukify-"+ukifyPackageVersion)
	ukify := filepath.Join(root, "usr", "bin", "ukify")
	download := filepath.Join(s.remote, "systemd-ukify.deb")
	staging := filepath.Join(s.remote, "systemd-ukify")
	script := "set -euo pipefail\numask 077\nmkdir -p -- " + QuoteShell(tools) + "\nexec 9>" + QuoteShell(filepath.Join(tools, ".install.lock")) + "\nflock 9\n" +
		"if ! test -x " + QuoteShell(ukify) + "; then\n" +
		"curl --fail --location --proto '=https' --tlsv1.2 --output " + QuoteShell(download) + " " + QuoteShell(ukifyPackageURL) + "\n" +
		"printf '%s  %s\\n' " + QuoteShell(ukifyPackageSHA256) + " " + QuoteShell(download) + " | sha256sum --check --strict\n" +
		"dpkg-deb --extract " + QuoteShell(download) + " " + QuoteShell(staging) + "\n" +
		"mv -- " + QuoteShell(staging) + " " + QuoteShell(root) + "\nfi\n" +
		"python3 -c 'import pefile'\n" + QuoteShell(ukify) + " --version"
	cmd := executionCommand(s.ctx, s.alias, script)
	cmd.Stdout, cmd.Stderr = s.stderr, s.stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("prepare private ukify %s (python3-pefile must already exist): %w", ukifyPackageVersion, err)
	}
	return ukify, nil
}
