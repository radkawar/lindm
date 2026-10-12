//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

type actionNativePackage struct {
	work     string
	artifact packaging.Artifact
	// upgrade is the later version a reference-repair lane installs over the
	// legacy artifact through the same native manager; zero elsewhere.
	upgrade packaging.Artifact
	// legacyRevision is the resolved commit artifact was compiled from when
	// the set carries an upgrade.
	legacyRevision string
	apt            *packaging.APTRepository
	arch           []*packaging.ArchRepository
	publicKey      string
	fingerprint    string
}

// The reference-repair lane's legacy agent and the current agent it upgrades to.
const (
	actionLegacyAgentVersion  = "0.1.0"
	actionCurrentAgentVersion = "0.1.1"
)

func nativePackageArchitecture(architecture string) (string, error) {
	switch architecture {
	case "amd64", "x86_64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", errors.New("native action package requires an explicit supported guest architecture")
	}
}

func buildActionNativePackage(ctx context.Context, manifest *labv1.ImageManifest, repository, workDir string) (*actionNativePackage, error) {
	return buildActionPackages(ctx, manifest, repository, "", workDir)
}

// buildActionPackages builds the current agent from repository. With a legacy
// revision it first exports that commit of repository (read-only git) into the
// private package work directory and builds it as the installed version; the
// current source becomes the later upgrade. Both are signed by one development
// signer and published together: one APT archive holding both versions, or one
// signed pacman repository per version.
func buildActionPackages(ctx context.Context, manifest *labv1.ImageManifest, repository, legacyRevision, workDir string) (_ *actionNativePackage, err error) {
	architecture, err := nativePackageArchitecture(manifest.GetArchitecture())
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(workDir, "lindm-device-action-packages-")
	if err != nil {
		return nil, err
	}
	p := &actionNativePackage{work: work}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.Close())
		}
	}()
	signer, err := packaging.GenerateDevelopmentSigner(ctx, work)
	if err != nil {
		return nil, err
	}
	format := packaging.Format(platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion()).Native().Packages.Backend.PackageFormat())
	if format != packaging.FormatDEB && format != packaging.FormatRPM && format != packaging.FormatArch {
		return nil, errors.New("native action package requires a DEB, RPM or pacman guest")
	}
	type source struct{ repository, revision, version string }
	sources := []source{{repository, "encrypted-device-actions-lab", "0.1.0"}}
	if legacyRevision != "" {
		var legacy string
		p.legacyRevision, legacy, err = exportLegacySource(ctx, repository, legacyRevision, work)
		if err != nil {
			return nil, err
		}
		sources = []source{{legacy, p.legacyRevision, actionLegacyAgentVersion}, {repository, "encrypted-device-actions-lab", actionCurrentAgentVersion}}
	}
	artifacts := make([]packaging.Artifact, 0, len(sources))
	for _, s := range sources {
		output := work
		if len(sources) > 1 {
			output = filepath.Join(work, "agent-"+s.version)
			if err := os.Mkdir(output, 0700); err != nil {
				return nil, err
			}
		}
		built, err := packaging.BuildSource(ctx, packaging.SourceRequest{Repository: s.repository, Revision: s.revision, BuildRequest: packaging.BuildRequest{Version: s.version, TargetArchitecture: architecture, OutputDir: output, Formats: []packaging.Format{format}, Signer: *signer}})
		if err != nil {
			return nil, err
		}
		if len(built.Artifacts) != 1 {
			return nil, errors.New("device action lane requires one native package artifact per version")
		}
		artifacts = append(artifacts, built.Artifacts[0])
		p.publicKey = built.PublicKey
	}
	p.artifact, p.fingerprint = artifacts[0], signer.Fingerprint
	if len(artifacts) > 1 {
		p.upgrade = artifacts[1]
	}
	if format == packaging.FormatDEB {
		output := filepath.Join(work, "apt")
		if err := os.Mkdir(output, 0700); err != nil {
			return nil, err
		}
		debs := make([]string, 0, len(artifacts))
		for _, artifact := range artifacts {
			debs = append(debs, artifact.Path)
		}
		p.apt, err = packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: output, DEBs: debs, Signer: *signer})
		if err != nil {
			return nil, err
		}
		p.publicKey = p.apt.PublicKeyArmor
	}
	if format == packaging.FormatArch {
		// A pacman repository holds one version per package name.
		for _, artifact := range artifacts {
			output := filepath.Join(work, "arch-repo")
			if len(artifacts) > 1 {
				output += "-" + artifact.Version
			}
			if err := os.Mkdir(output, 0700); err != nil {
				return nil, err
			}
			repo, err := packaging.PublishArch(ctx, packaging.ArchRequest{OutputDir: output, Packages: []string{artifact.Path}, Signer: *signer})
			if err != nil {
				return nil, err
			}
			p.arch, p.publicKey = append(p.arch, repo), repo.PublicKeyArmor
		}
	}
	return p, nil
}

func (p *actionNativePackage) Close() error { return os.RemoveAll(p.work) }

func (p *actionNativePackage) Install(ctx context.Context, vm *guestVM, labBinary string) error {
	packages, err := p.installFirst(ctx, vm, labBinary)
	if err != nil {
		return err
	}
	return packages.Close()
}

// installFirst installs the set's first version and returns its still-open
// native manager: the pinned trust and signed source a later upgrade reuses.
func (p *actionNativePackage) installFirst(ctx context.Context, vm *guestVM, labBinary string) (_ *nativeGuestPackages, err error) {
	second := p.artifact
	if p.upgrade.Path != "" {
		second = p.upgrade
	}
	packages, err := newNativeGuestPackages(ctx, vm, p.artifact, second, p.apt, p.publicKey, p.fingerprint, p.arch...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, packages.Close())
		}
	}()
	if err := packages.InstallFirst(ctx); err != nil {
		return nil, err
	}
	if err := uploadLifecycleProbe(ctx, vm, labBinary); err != nil {
		return nil, err
	}
	return packages, nil
}

// actionGuestConnection owns only guest-to-isolated-server forwarding. Reopen it
// after each cold boot; neither the guest identity nor enrollment is recreated.
type actionGuestConnection struct{ forwards []*guestForward }

func connectActionGuest(ctx context.Context, vm *guestVM, fixture *devlab.AuthorityFixture) (*actionGuestConnection, error) {
	connection := &actionGuestConnection{}
	for _, address := range []string{fixture.AdminAddress, fixture.DeviceAddress} {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != "127.0.0.1" {
			return nil, errors.Join(errors.New("action fixture listener is not isolated loopback"), err, connection.Close())
		}
		forward, err := newGuestForward(ctx, vm, net.JoinHostPort("127.0.0.1", port), address)
		if err != nil {
			return nil, errors.Join(err, connection.Close())
		}
		connection.forwards = append(connection.forwards, forward)
	}
	return connection, nil
}

func (c *actionGuestConnection) Close() error { return closeLifecycleForwards(c.forwards) }

func enrollActionGuest(ctx context.Context, vm *guestVM, control *vmControlPlane, delegation *agentv1.UpdateExecutionTrustRequest) (_ *labv1.InterruptedBootstrapEvidence, _ *vmBootstrapMaterial, err error) {
	finishDiagnostics, err := observeActionGuest(ctx, vm)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = finishDiagnostics(err) }()
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED); err != nil {
		return nil, nil, err
	}
	material, err := control.BootstrapMaterial(ctx)
	if err != nil {
		return nil, nil, err
	}
	issued, err := interruptBootstrap(ctx, vm, material)
	clear(material.GrantSecret)
	material.GrantSecret = nil
	if err != nil {
		return nil, nil, err
	}
	if err := control.TrackDevice(issued.GetDeviceId()); err != nil {
		return nil, nil, err
	}
	if err := lifecycleCommand(ctx, vm, "resume packaged action enrollment", packaging.BinaryPath+" resume"); err != nil {
		return nil, nil, err
	}
	if err := lifecycleCommand(ctx, vm, "start packaged action relay", "systemctl restart lindm-agent.service"); err != nil {
		return nil, nil, err
	}
	authority, err := control.executionAuthority(ctx)
	if err != nil {
		return nil, nil, err
	}
	if _, err := waitVMExecutionTrust(ctx, vm, authority, delegation); err != nil {
		return nil, nil, err
	}
	return issued, material, nil
}

func configureActionGuest(ctx context.Context, vm *guestVM, provider *agentv1.DeviceActionProviderConfig, recovery *agentv1.RecoveryBootConfig) error {
	data, err := vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 1<<20, 10*time.Second)
	if err != nil {
		return err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, config); err != nil {
		return err
	}
	config.ActionProvider = provider
	config.RecoveryBoot = recovery
	data, err = protojson.Marshal(config)
	if err != nil {
		return err
	}
	// The network process never receives the opt-in storage allowlist. This is
	// a local operator action against a disposable VM, not remote authority.
	command := "sudo -n sh -eu -c " + nativeQuote("umask 077; cat > /etc/lindm/executor.json; chown root:root /etc/lindm/executor.json; chmod 0600 /etc/lindm/executor.json; "+packaging.BinaryPath+" action-sandbox -install; systemctl daemon-reload; systemctl restart lindm-executor.service")
	configured, err := vm.runResult(ctx, command, bytes.NewReader(data), 16<<10, time.Minute)
	if err != nil {
		return fmt.Errorf("install exact local action qualification: %w", err)
	}
	if configured.ExitCode != 0 {
		return fmt.Errorf("install exact local action qualification: exit %d: %s", configured.ExitCode, configured.Stderr)
	}
	return nil
}

// A scope executes locally after cgroup admission: SSH stdin is never passed
// through D-Bus (which SELinux correctly refuses for sshd_session_t pipes).
func actionSecretScopeCommand(command string) string {
	return "sudo -n sh -eu -c " + nativeQuote("ulimit -c 0; exec systemd-run --quiet --scope -p MemorySwapMax=0 "+command)
}

func supplyActionCredential(ctx context.Context, vm *guestVM, actionID string, secret []byte) error {
	if !vmValidID(actionID) {
		return errors.New("invalid credential action identity")
	}
	// The installed root-only CLI consumes exact stdin bytes, including no
	// implicit newline. A secret is never an argv, environment or file value.
	_, err := vm.run(ctx, actionSecretScopeCommand(packaging.BinaryPath+" action-credential -action "+nativeQuote(actionID)), bytes.NewReader(secret), 4096, 15*time.Second)
	return err
}

// installActionPrerequisites installs the release's action prerequisites. Only
// a disposable clone is quiesced; a persistent organization device keeps its
// vendor updaters for its own OS-update policy, and its caller waits for any
// running vendor package run instead.
func installActionPrerequisites(ctx context.Context, vm *guestVM, manifest *labv1.ImageManifest, disposable bool) error {
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	command, err := labInstallCommand(release, release.Lab.Guest.Actions)
	if err != nil {
		return fmt.Errorf("native action prerequisites: %w", err)
	}
	if release.Lab.Entitlement {
		// An unregistered entitled system has no repository. Its encrypted
		// golden installed these from the vendor-authenticated Binary DVD;
		// require them rather than reaching an unentitled or third-party source.
		command = "rpm -q " + strings.Join(release.Lab.Guest.Actions, " ")
	}
	// The disposable clone's vendor updaters are quiesced first, as in the
	// cloud fixture: Ubuntu's persistent apt-daily-upgrade timer may fire
	// within its 60-minute randomized delay of a golden's first boot, and the
	// wait for a running updater could consume the whole bound (aarch64 24.04
	// live-actions exceeded it four times). Stopping lets unattended-upgrade
	// finish its current package; the golden itself is unchanged.
	// Vendor-configured signature verification remains enabled. Network access
	// is explicit disposable-QEMU user egress, never host routing or namespaces.
	if disposable {
		command = labQuiescePackageUnits + "; " + command
	}
	result, err := vm.runResult(ctx, "sudo -n env DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), nil, 1<<20, 20*time.Minute)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("install native action prerequisites: guest exit %d: %s", result.ExitCode, result.Stderr)
	}
	return nil
}

// labInstallCommand installs maintained lab packages with the release's native
// backend. Vendor-configured signature verification remains enabled.
func labInstallCommand(release *platform.Release, packages []string) (string, error) {
	if len(packages) == 0 {
		return "", fmt.Errorf("no maintained lab package recipe for %s", release.Name)
	}
	switch backend := release.Native().Packages.Backend; {
	case backend == platform.BackendAPT:
		// GNOME Software's PackageKit refreshes APT lists right after login and
		// holds the lists lock, which apt-get update cannot wait for (debian 13
		// arm64 encryption-03). Runtime-mask it in this disposable guest; the
		// mask lives in /run, and dpkg's frontend lock is waited for. A vendor
		// boot-time apt-get (Pop!_OS 24.04 pop2404-lock-quarantine-01) holds the
		// same lists lock, so any running apt is waited for, bounded, first.
		// Packages the golden already installed skip that wait and refresh: a
		// first-boot unattended-upgrades run outlasted the 10 min setup bound
		// with nothing to install (ubuntu24-tier1-07, amd64 and arm64).
		return fmt.Sprintf("export DEBIAN_FRONTEND=noninteractive; if [ \"$(dpkg-query -W -f='${db:Status-Status}\\n' %[1]s 2>/dev/null | grep -cx installed)\" = %[2]d ]; then exit 0; fi; ", strings.Join(packages, " "), len(packages)) +
			"if systemctl cat packagekit.service >/dev/null 2>&1; then systemctl mask --runtime --now packagekit.service; fi; " +
			"for i in $(seq 600); do pgrep -x apt-get >/dev/null || pgrep -x apt >/dev/null || pgrep -x unattended-upgr >/dev/null || break; sleep 1; done; " +
			"apt-get -q -o DPkg::Lock::Timeout=600 update; apt-get -q -y -o DPkg::Lock::Timeout=600 install " + strings.Join(packages, " "), nil
	case backend.DNF():
		return "dnf -y install " + strings.Join(packages, " "), nil
	case backend == platform.BackendPacman:
		// Rolling goldens provision the prerequisites from their pinned source.
		// Do not refresh to a different snapshot merely to prepare an action.
		return "pacman -Q " + strings.Join(packages, " "), nil
	case backend == platform.BackendZypper:
		return "rpm -q " + strings.Join(packages, " "), nil
	default:
		return "", fmt.Errorf("no lab package installer for %s", release.Name)
	}
}
