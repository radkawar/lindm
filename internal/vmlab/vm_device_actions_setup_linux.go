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
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
)

type actionNativePackage struct {
	work        string
	artifact    packaging.Artifact
	apt         *packaging.APTRepository
	publicKey   string
	fingerprint string
}

func buildActionNativePackage(ctx context.Context, manifest *labv1.ImageManifest, repository, workDir string) (_ *actionNativePackage, err error) {
	architecture := ""
	switch manifest.GetArchitecture() {
	case "amd64", "x86_64":
		architecture = "amd64"
	case "arm64", "aarch64":
		architecture = "arm64"
	default:
		return nil, errors.New("native action package requires an explicit supported guest architecture")
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
	format := packaging.FormatDEB
	if manifest.GetDistribution() == "fedora" {
		format = packaging.FormatRPM
	}
	built, err := packaging.BuildSource(ctx, packaging.SourceRequest{Repository: repository, Revision: "encrypted-device-actions-lab", BuildRequest: packaging.BuildRequest{Version: "0.1.0", TargetArchitecture: architecture, OutputDir: work, Formats: []packaging.Format{format}, Signer: *signer}})
	if err != nil {
		return nil, err
	}
	if len(built.Artifacts) != 1 {
		return nil, errors.New("device action lane requires one native package artifact")
	}
	p.artifact, p.publicKey, p.fingerprint = built.Artifacts[0], built.PublicKey, signer.Fingerprint
	if format == packaging.FormatDEB {
		output := filepath.Join(work, "apt")
		if err := os.Mkdir(output, 0700); err != nil {
			return nil, err
		}
		p.apt, err = packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: output, DEBs: []string{p.artifact.Path}, Signer: *signer})
		if err != nil {
			return nil, err
		}
		p.publicKey = p.apt.PublicKeyArmor
	}
	return p, nil
}

func (p *actionNativePackage) Close() error { return os.RemoveAll(p.work) }

func (p *actionNativePackage) Install(ctx context.Context, vm *guestVM, labBinary string) (err error) {
	packages, err := newNativeGuestPackages(ctx, vm, p.artifact, p.artifact, p.apt, p.publicKey, p.fingerprint)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, packages.Close()) }()
	if err := packages.InstallFirst(ctx); err != nil {
		return err
	}
	return uploadLifecycleProbe(ctx, vm, labBinary)
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

func installActionPrerequisites(ctx context.Context, vm *guestVM, distribution string) error {
	var command string
	switch distribution {
	case "ubuntu":
		command = "apt-get -q update && apt-get -q -y install cryptsetup nftables iproute2 iputils-ping tpm2-tools dnsutils curl"
	case "fedora":
		command = "dnf -y install cryptsetup nftables iproute iputils systemd-udev tpm2-tools bind-utils curl"
	default:
		return errors.New("native action prerequisites require maintained Ubuntu or Fedora")
	}
	// Vendor-configured signature verification remains enabled. Network access
	// is explicit disposable-QEMU user egress, never host routing or namespaces.
	result, err := vm.runResult(ctx, "sudo -n env DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), nil, 1<<20, 10*time.Minute)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("install native action prerequisites: guest exit %d: %s", result.ExitCode, result.Stderr)
	}
	return nil
}
