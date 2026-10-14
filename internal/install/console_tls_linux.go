// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"fmt"
	"io"
	"net"

	configv1 "lindm/gen/lindm/config/v1"
)

const browserCompatibleUpgradeBoundary = "This installation predates the browser-compatible console certificate. Install fresh and re-enroll devices."

type browserCompatibleUpgradeRefusal struct{}

func (browserCompatibleUpgradeRefusal) Error() string {
	return browserCompatibleUpgradeBoundary
}

// No customer release predates this boundary. An old quorum-signed bootstrap
// pins only the shared device CA, so replacing it would break new enrollment.
// Refuse before any package, database or persisted configuration changes.
func requireBrowserCompatibleUpgrade() error {
	uid, _, err := account("lindmd")
	if err != nil {
		return err
	}
	cfg, _, err := loadNativeConfig("/etc/lindm/server.json", uid)
	if err != nil {
		return err
	}
	return browserCompatibleUpgradeConfig(cfg)
}

func browserCompatibleUpgradeConfig(cfg *configv1.ServerConfig) error {
	if cfg.GetAdminTls() == nil || cfg.GetAdminCaFile() == "" {
		return browserCompatibleUpgradeRefusal{}
	}
	return nil
}

func warnConsoleDNSRequirement(host string, output io.Writer) {
	if net.ParseIP(host) != nil {
		_, _ = fmt.Fprintln(output, "Warning: an IP-address console URL cannot be a WebAuthn relying-party ID. Use a DNS name and a matching HTTPS certificate before first-owner password and passkey setup.")
	}
}
