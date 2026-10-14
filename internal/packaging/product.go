// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import "os"

const (
	// CLIPackageName is the separately installed administrative client.
	CLIPackageName = "lindmctl"
	// ServerPackageName is the native control-plane package name.
	ServerPackageName = "lindmd"
	// ServerBinaryPath is the packaged control-plane executable.
	ServerBinaryPath = "/usr/bin/lindmd"
	// ServerConfigPath is the operator-provisioned runtime configuration.
	ServerConfigPath = "/etc/lindm/server.json"
	// ServerMigrationConfigPath is readable only by the explicit migrator.
	ServerMigrationConfigPath = "/etc/lindm/migrate/server.json"
)

type product struct {
	name, binary, lifecycle, lifecycleAsset, summary, description string
	units, userUnits, dirs                                        []string
	// Weak dependencies of optional features, per native format.
	debRecommends, rpmRecommends, archOptdepends []string
}

func agentProduct() product {
	return product{
		name: PackageName, binary: BinaryPath, lifecycle: lifecyclePath, lifecycleAsset: "lifecycle.sh",
		summary:     "Lindm protected agent",
		description: "Versioned agent binary with a root executor and an unprivileged network service.\nRemove and purge retain identity and spool state. This package does not grant a root shell.",
		units:       []string{executorUnit, agentUnit, poweroffUnit, firewallRestoreUnit, connectivityGuardUnit, connectivityProbeUnit, osUpdateUnit, osUpdateNowUnit, osUpdateStatusUnit},
		userUnits:   []string{sessionUnit},
		dirs:        []string{"usr/libexec/lindm", "etc/lindm", "usr/share/doc/lindm-agent"},
		// Remote assistance captures through the PipeWire GStreamer source and
		// encodes VP8 with gst-launch-1.0. Without them it ends UNAVAILABLE.
		debRecommends:  []string{"gstreamer1.0-pipewire", "gstreamer1.0-plugins-good", "gstreamer1.0-tools"},
		rpmRecommends:  []string{"pipewire-gstreamer", "gstreamer1-plugins-good", "gstreamer1"},
		archOptdepends: []string{"gst-plugin-pipewire: remote assistance screen capture", "gst-plugins-good: remote assistance VP8 encoding", "gstreamer: remote assistance gst-launch-1.0"},
	}
}

func serverProduct() product {
	return product{
		name: ServerPackageName, binary: ServerBinaryPath, lifecycle: "/usr/libexec/lindmd/lifecycle", lifecycleAsset: "server-lifecycle.sh",
		summary:     "Lindm control-plane server",
		description: "Control-plane server with its embedded console. Configuration and keys are operator-owned.\nInstallation never starts services, migrates the database or bootstraps an owner.\nRemoval and purge retain operator configuration, keys, accounts and database.",
		units:       []string{"lindmd.service", "lindmd-migrate.service"},
		dirs:        []string{"usr/libexec/lindmd", "etc/lindm", "usr/share/doc/lindmd"},
	}
}

func cliProduct() product {
	return product{
		name: CLIPackageName, binary: "/usr/bin/lindmctl",
		summary:     "Lindm administrative client",
		description: "Browser-authorized administrative client. No services, credentials or configuration are installed.",
		dirs:        []string{"usr/share/doc/lindmctl"},
	}
}

type payloadFile struct {
	rel  string
	mode os.FileMode
	conf bool
	body []byte
	name string
}

func (p product) payloadFiles() ([]payloadFile, error) {
	if p.name == CLIPackageName {
		return []payloadFile{
			{rel: "usr/share/doc/lindmctl/copyright", mode: 0o644, name: "copyright"},
			{rel: "usr/share/doc/lindmctl/LICENSE", mode: 0o644, name: "LICENSE"},
			{rel: "usr/share/doc/lindmctl/NOTICE", mode: 0o644, name: "NOTICE"},
			{rel: "usr/share/doc/lindmctl/THIRD-PARTY-LICENSES", mode: 0o644, name: "THIRD-PARTY-LICENSES"},
		}, nil
	}
	if p.name == ServerPackageName {
		return []payloadFile{
			{rel: "usr/lib/systemd/system/lindmd.service", mode: 0o644, name: "lindmd.service"},
			{rel: "usr/lib/systemd/system/lindmd-migrate.service", mode: 0o644, name: "lindmd-migrate.service"},
			{rel: "usr/lib/sysusers.d/lindmd.conf", mode: 0o644, name: "server-sysusers.conf"},
			{rel: p.lifecycle[1:], mode: 0o755, name: p.lifecycleAsset},
			{rel: "usr/share/doc/lindmd/copyright", mode: 0o644, name: "copyright"},
			{rel: "usr/share/doc/lindmd/LICENSE", mode: 0o644, name: "LICENSE"},
			{rel: "usr/share/doc/lindmd/NOTICE", mode: 0o644, name: "NOTICE"},
			{rel: "usr/share/doc/lindmd/THIRD-PARTY-LICENSES", mode: 0o644, name: "THIRD-PARTY-LICENSES"},
		}, nil
	}
	config, err := AgentConfigJSON()
	if err != nil {
		return nil, err
	}
	return []payloadFile{
		{rel: "usr/lib/systemd/system/" + executorUnit, mode: 0o644, name: executorUnit},
		{rel: "usr/lib/systemd/system/" + agentUnit, mode: 0o644, name: agentUnit},
		{rel: "usr/lib/systemd/system/" + poweroffUnit, mode: 0o644, name: poweroffUnit},
		{rel: "usr/lib/systemd/system/" + firewallRestoreUnit, mode: 0o644, name: firewallRestoreUnit},
		{rel: "usr/lib/systemd/system/" + connectivityGuardUnit, mode: 0o644, name: connectivityGuardUnit},
		{rel: "usr/lib/systemd/system/" + connectivityProbeUnit, mode: 0o644, name: connectivityProbeUnit},
		{rel: "usr/lib/systemd/system/" + osUpdateUnit, mode: 0o644, name: osUpdateUnit},
		{rel: "usr/lib/systemd/system/" + osUpdateNowUnit, mode: 0o644, name: osUpdateNowUnit},
		{rel: "usr/lib/systemd/system/" + osUpdateStatusUnit, mode: 0o644, name: osUpdateStatusUnit},
		{rel: "usr/lib/systemd/user/" + sessionUnit, mode: 0o644, name: sessionUnit},
		{rel: sessionAutostartPath[1:], mode: 0o644, conf: true, name: "lindm-session-autostart.desktop"},
		{rel: "usr/lib/tmpfiles.d/lindm.conf", mode: 0o644, name: "tmpfiles.conf"},
		{rel: "usr/lib/sysusers.d/lindm.conf", mode: 0o644, name: "sysusers.conf"},
		{rel: p.lifecycle[1:], mode: 0o755, name: p.lifecycleAsset},
		{rel: "usr/share/doc/lindm-agent/copyright", mode: 0o644, name: "copyright"},
		{rel: "usr/share/doc/lindm-agent/LICENSE", mode: 0o644, name: "LICENSE"},
		{rel: "usr/share/doc/lindm-agent/NOTICE", mode: 0o644, name: "NOTICE"},
		{rel: "usr/share/doc/lindm-agent/THIRD-PARTY-LICENSES", mode: 0o644, name: "THIRD-PARTY-LICENSES"},
		{rel: "etc/lindm/executor.json", mode: 0o640, conf: true, body: config},
		{rel: "etc/lindm/agent.json", mode: 0o644, conf: true, body: config},
	}, nil
}

func supportedProduct(name string) bool {
	return name == PackageName || name == ServerPackageName || name == CLIPackageName
}
