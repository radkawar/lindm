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
	units, dirs                                                   []string
}

func agentProduct() product {
	return product{
		name: PackageName, binary: BinaryPath, lifecycle: lifecyclePath, lifecycleAsset: "lifecycle.sh",
		summary:     "Lindm protected agent",
		description: "Versioned agent binary with a root executor and an unprivileged network service.\nRemove and purge retain identity and spool state. This package does not grant a root shell.",
		units:       []string{executorUnit, agentUnit, poweroffUnit},
		dirs:        []string{"usr/libexec/lindm", "etc/lindm", "usr/share/doc/lindm-agent"},
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
		return []payloadFile{{rel: "usr/share/doc/lindmctl/copyright", mode: 0o644, name: "copyright"}}, nil
	}
	if p.name == ServerPackageName {
		return []payloadFile{
			{rel: "usr/lib/systemd/system/lindmd.service", mode: 0o644, name: "lindmd.service"},
			{rel: "usr/lib/systemd/system/lindmd-migrate.service", mode: 0o644, name: "lindmd-migrate.service"},
			{rel: "usr/lib/sysusers.d/lindmd.conf", mode: 0o644, name: "server-sysusers.conf"},
			{rel: p.lifecycle[1:], mode: 0o755, name: p.lifecycleAsset},
			{rel: "usr/share/doc/lindmd/copyright", mode: 0o644, name: "copyright"},
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
		{rel: "usr/lib/tmpfiles.d/lindm.conf", mode: 0o644, name: "tmpfiles.conf"},
		{rel: "usr/lib/sysusers.d/lindm.conf", mode: 0o644, name: "sysusers.conf"},
		{rel: p.lifecycle[1:], mode: 0o755, name: p.lifecycleAsset},
		{rel: "usr/share/doc/lindm-agent/copyright", mode: 0o644, name: "copyright"},
		{rel: "etc/lindm/executor.json", mode: 0o640, conf: true, body: config},
		{rel: "etc/lindm/agent.json", mode: 0o644, conf: true, body: config},
	}, nil
}

func supportedProduct(name string) bool {
	return name == PackageName || name == ServerPackageName || name == CLIPackageName
}
