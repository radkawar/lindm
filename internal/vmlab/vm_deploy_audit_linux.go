// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/deploylab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

type VMDeployAuditOptions struct {
	CacheDir, WorkDir, EvidenceDir, Release, ReleasePublicKey, ReleaseKeyID, RedHatTokenFile, LabBinary string
	BaselineVerifier, BaselineVerifierSHA256                                                            string
	PackagePublicKeySHA256                                                                              string
	Signer                                                                                              packaging.SigningKey
	Browser                                                                                             func(context.Context, deploylab.BrowserRequest) (*deploylab.BrowserEvidence, error)
}

type VMDeployAuditResult struct {
	StartedAt                time.Time                  `json:"started_at"`
	FinishedAt               time.Time                  `json:"finished_at"`
	Passed                   bool                       `json:"passed"`
	Failure                  string                     `json:"failure,omitempty"`
	ImageID                  string                     `json:"image_id"`
	ImageSHA256              string                     `json:"image_sha256,omitempty"`
	Runtime                  *vmRuntimeEvidence         `json:"runtime,omitempty"`
	ReleaseVersion           string                     `json:"release_version"`
	SigningCustody           string                     `json:"signing_custody"`
	BaselineVerifierRevision string                     `json:"baseline_verifier_revision"`
	BaselineVerifierSHA256   string                     `json:"baseline_verifier_sha256"`
	NativePackageSHA256      string                     `json:"native_package_sha256"`
	PackagePublicKeySHA256   string                     `json:"package_public_key_sha256,omitempty"`
	InitialPrerequisites     []string                   `json:"initial_prerequisites"`
	TurnkeyInstallerPresent  bool                       `json:"turnkey_installer_present"`
	Operations               []deploylab.Operation      `json:"operations"`
	Friction                 []deploylab.Friction       `json:"friction"`
	Browser                  *deploylab.BrowserEvidence `json:"browser,omitempty"`
	ManualCommands           int                        `json:"manual_commands"`
	ManualDecisions          int                        `json:"manual_decisions"`
	FailedOperations         int                        `json:"failed_operations"`
	RedHat                   *VMRedHatEvidence          `json:"redhat,omitempty"`
	OwnedCleanupComplete     bool                       `json:"owned_cleanup_complete"`
}

// DeployAuditVM executes the historical native installation, not a description
// of seven runbook headings. Its command observer counts actual invocations and
// its browser observer counts actual controls. Neither includes private inputs.
func DeployAuditVM(ctx context.Context, manifest *labv1.ImageManifest, options VMDeployAuditOptions) (result *VMDeployAuditResult, err error) {
	result = &VMDeployAuditResult{StartedAt: time.Now().UTC(), ImageID: manifest.GetId()}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		result.ManualCommands, result.ManualDecisions, result.FailedOperations = deploylab.Counts(result.Operations)
		if err != nil {
			result.Passed = false
			result.Failure = "baseline_install_audit_failed"
		}
	}()
	if manifest == nil || options.Browser == nil || options.Release == "" || options.ReleasePublicKey == "" || options.ReleaseKeyID == "" {
		return result, errors.New("baseline audit requires image, signed release and browser")
	}
	release := manifestRelease(manifest)
	if err := release.LabLaneOn(platform.LaneDeploy, manifest.GetArchitecture()); err != nil {
		return result, err
	}
	if release.Version.Rule == platform.VersionMajor && manifest.GetVersion() == release.Version.Value {
		return result, errors.New("baseline audit requires an exact minor base image")
	}
	releaseDirectory, _, err := openDeployAuditProtected(options.Release, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, releaseDirectory.Close()) }()
	verified, err := verifyDeployAuditRelease(ctx, options, releaseDirectory)
	if err != nil {
		return result, err
	}
	result.ReleaseVersion = verified.GetVersion()
	result.SigningCustody = verified.GetCustody()
	result.BaselineVerifierRevision = deployAuditBaselineRevision
	result.BaselineVerifierSHA256 = options.BaselineVerifierSHA256
	if _, statErr := os.Stat(filepath.Join(deployAuditDescriptorPath(releaseDirectory), "install.sh")); statErr == nil {
		result.TurnkeyInstallerPresent = true
		return result, errors.New("baseline audit requires immutable pre-turnkey release without install.sh")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return result, statErr
	}
	result.Friction = append(result.Friction, deploylab.Friction{Operation: "signed release bundle", Observation: "Authenticated pre-turnkey export has no install.sh or bundled host dependency snapshot; the operator must follow the native installation runbook.", Remedy: "Signed turnkey installer with authenticated connected vendor dependency provisioning by default, and independently authenticated platform add-ons when airgap installation is requested."})
	private, err := os.MkdirTemp(options.WorkDir, "deploy-audit-private-")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(private)) }()
	format := release.Packages.Backend.PackageFormat()
	inputs, err := snapshotDeployAuditNativeInputs(ctx, deployAuditDescriptorPath(releaseDirectory), private, format, options.PackagePublicKeySHA256, options.Signer.Fingerprint, verified)
	if err != nil {
		return result, err
	}
	result.NativePackageSHA256 = inputs.PackageSHA256
	result.PackagePublicKeySHA256 = inputs.PublicKeySHA256
	admin, err := newDeployRoute(ctx, "127.0.0.1:18444")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, admin.close()) }()
	device, err := newDeployRoute(ctx, "127.0.0.1:18445")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, device.close()) }()
	vm, image, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, false, &VMHardwareOptions{Architecture: "x86_64", Accelerator: "kvm", AllowNetwork: true})
	if err != nil {
		return result, err
	}
	result.ImageSHA256 = image.SHA256
	defer func() {
		closeErr := vm.close()
		result.OwnedCleanupComplete = closeErr == nil
		err = errors.Join(err, closeErr)
	}()
	if err = vm.connect(ctx); err != nil {
		return result, err
	}
	if _, err = vm.run(ctx, "sudo -n cloud-init status --wait", nil, 64<<10, 5*time.Minute); err != nil {
		return result, err
	}
	if _, err = deployGuestOS(ctx, vm, manifest.Distribution, manifest.Version); err != nil {
		return result, err
	}
	result.Runtime, err = vm.runtimeEvidence(ctx)
	if err != nil {
		return result, err
	}
	result.InitialPrerequisites, err = deployBootstrapInventory(ctx, vm)
	if err != nil {
		return result, err
	}
	observe := func(step string, started, finished time.Time, passed bool) {
		result.Operations = append(result.Operations, deploylab.Operation{Name: step, Kind: "command", StartedAt: started, FinishedAt: finished, Passed: passed})
	}
	vm.serverCommandObserver = observe
	registrationOptions := VMConsoleEnrollmentOptions{LabBinary: options.LabBinary, RedHatTokenFile: options.RedHatTokenFile}
	if release.Lab.Entitlement {
		if options.RedHatTokenFile == "" {
			return result, errors.New("entitled RHEL audit requires protected Red Hat input")
		}
		result.RedHat = &VMRedHatEvidence{}
		started := time.Now().UTC()
		registration, registerErr := registerConsoleEnrollmentRedHat(ctx, vm, registrationOptions, result.RedHat)
		observe("register entitled RHEL vendor repositories", started, time.Now().UTC(), registerErr == nil)
		if registerErr != nil {
			return result, registerErr
		}
		defer func() {
			err = errors.Join(err, releaseConsoleEnrollmentRedHat(context.Background(), vm, options.LabBinary, registration))
		}()
	}
	started := time.Now().UTC()
	err = installServerPostgres(ctx, vm)
	observe("install vendor PostgreSQL prerequisites", started, time.Now().UTC(), err == nil)
	if err != nil {
		return result, err
	}
	artifact := inputs.PackagePath
	if format == "deb" {
		if err := os.Mkdir(filepath.Join(private, "signed-apt"), 0700); err != nil {
			return result, err
		}
		started = time.Now().UTC()
		repository, publishErr := packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: filepath.Join(private, "signed-apt"), DEBs: []string{artifact}, Signer: options.Signer, SourceDateEpoch: verified.GetSourceDateEpoch()})
		observe("publish independently signed local APT repository", started, time.Now().UTC(), publishErr == nil)
		if publishErr != nil {
			return result, publishErr
		}
		if err = uploadDeployDirectory(ctx, vm, repository.Root, "/var/lib/lindm-lab-server-repository"); err != nil {
			return result, err
		}
		key, readErr := os.ReadFile(repository.PublicKeyArmor)
		if readErr != nil {
			return result, readErr
		}
		if _, err = serverGuestCommand(ctx, vm, "install pinned package public key", "install -d -m 0755 /etc/apt/keyrings; cat > /etc/apt/keyrings/lindm-lab.asc; chmod 0644 /etc/apt/keyrings/lindm-lab.asc", bytes.NewReader(key)); err != nil {
			return result, err
		}
		source, sourceErr := packaging.APTSources("/var/lib/lindm-lab-server-repository", "/etc/apt/keyrings/lindm-lab.asc")
		if sourceErr != nil {
			return result, sourceErr
		}
		if _, err = serverGuestCommand(ctx, vm, "configure isolated authenticated APT source", "find /var/lib/lindm-lab-server-repository -type d -exec chmod 0755 {} +; find /var/lib/lindm-lab-server-repository -type f -exec chmod 0644 {} +; cat > /etc/apt/sources.list.d/lindm-lab.sources", strings.NewReader(source)); err != nil {
			return result, err
		}
		if _, err = serverGuestCommand(ctx, vm, "verify uploaded DEB matches authenticated release manifest", "printf '%s  %s\\n' "+nativeQuote(inputs.PackageSHA256)+" "+nativeQuote("/var/lib/lindm-lab-server-repository/pool/main/l/lindmd/"+filepath.Base(artifact))+" | sha256sum -c -", nil); err != nil {
			return result, err
		}
		if _, err = serverGuestCommand(ctx, vm, "install native server through authenticated APT", "apt-get -q -y -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false update && apt-get -q -y --no-install-recommends install lindmd="+nativeQuote(result.ReleaseVersion), nil); err != nil {
			return result, err
		}
	} else {
		if err = uploadDeployPath(ctx, vm, artifact, "/root/lindmd-baseline.rpm"); err != nil {
			return result, err
		}
		if err = uploadDeployPath(ctx, vm, inputs.PublicKeyPath, "/root/lindm-package-signing.asc"); err != nil {
			return result, err
		}
		if _, err = serverGuestCommand(ctx, vm, "verify uploaded RPM and independently pinned public key", "printf '%s  %s\\n' "+nativeQuote(inputs.PackageSHA256)+" /root/lindmd-baseline.rpm "+nativeQuote(inputs.PublicKeySHA256)+" /root/lindm-package-signing.asc | sha256sum -c -", nil); err != nil {
			return result, err
		}
		if _, err = serverGuestCommand(ctx, vm, "install pinned RPM public key", "rpm --import /root/lindm-package-signing.asc", nil); err != nil {
			return result, err
		}
		if _, err = serverGuestCommand(ctx, vm, "verify native RPM signature", "rpm --checksig --verbose /root/lindmd-baseline.rpm", nil); err != nil {
			return result, err
		}
		if _, err = serverGuestCommand(ctx, vm, "install native server with mandatory RPM signature gates", "dnf -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 install /root/lindmd-baseline.rpm", nil); err != nil {
			return result, err
		}
	}
	if _, err = serverGuestCommand(ctx, vm, "confirm package does not silently configure or start service", "! systemctl is-active --quiet lindmd.service && test ! -e /etc/lindm/server.json && test \"$(/usr/bin/lindmd version)\" = "+nativeQuote(result.ReleaseVersion), nil); err != nil {
		return result, err
	}
	files, err := deploylab.CertificateFiles()
	if err != nil {
		return result, err
	}
	caPath := filepath.Join(private, "transport-ca.crt")
	if err = os.WriteFile(caPath, files["transport-ca.crt"], 0600); err != nil {
		return result, err
	}
	if err = prepareServerGuestOrigins(ctx, vm, admin.origin(), device.origin(), files); err != nil {
		return result, err
	}
	result.Friction = append(result.Friction, deploylab.Friction{Operation: "configure TLS and database", Observation: "Native package leaves listener/configuration, TLS material, separate PostgreSQL runtime/migrator roles, SCRAM passwords, verify-full CA paths and protected migration configuration to the operator.", Remedy: "Protected turnkey provisioning retaining verify-full and runtime-no-DDL gates."})
	if _, err = serverGuestCommand(ctx, vm, "run explicit native schema migration", "systemctl start lindmd-migrate.service", nil); err != nil {
		return result, err
	}
	if _, err = serverGuestCommand(ctx, vm, "protect historical migration metadata from runtime", "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d lindm", strings.NewReader(historicalAuditMigrationMetadataSQL)); err != nil {
		return result, err
	}
	username := "audit-" + strings.ToLower(rand.Text())
	output, err := serverGuestCommand(ctx, vm, "mint private one-use owner enrollment", "runuser -u lindmd -- /usr/bin/lindmd bootstrap-owner -config /etc/lindm/server.json -username "+nativeQuote(username), nil)
	if err != nil {
		return result, err
	}
	_, tail, found := bytes.Cut(output, []byte("Enrollment secret (shown once): "))
	if !found {
		return result, errors.New("historical native bootstrap did not produce private owner enrollment")
	}
	secret := strings.Fields(string(tail))
	if len(secret) == 0 {
		return result, errors.New("empty historical private bootstrap enrollment")
	}
	if _, err = serverGuestCommand(ctx, vm, "enable and start configured native server", "systemctl enable --now lindmd.service", nil); err != nil {
		return result, err
	}
	admin.activate(vm)
	device.activate(vm)
	request := deploylab.BrowserRequest{Phase: "setup", SetupMethod: "native-bootstrap", Origin: admin.origin(), Username: username, Password: rand.Text() + "!Aa9", SetupCode: secret[0], CAFile: caPath, PrivateDirectory: private, CredentialPath: filepath.Join(private, "owner-passkey.json"), EvidenceDirectory: options.EvidenceDir, ResultPath: filepath.Join(private, "setup-result.json")}
	result.Browser, err = options.Browser(ctx, request)
	request.Password = ""
	request.SetupCode = ""
	clear(output)
	if result.Browser != nil {
		result.Operations = append(result.Operations, result.Browser.Operations...)
	}
	if err != nil {
		return result, err
	}
	if err = deploylab.ValidateBrowserEvidence(request, result.Browser); err != nil {
		return result, err
	}
	result.Friction = append(result.Friction, deploylab.Friction{Operation: "owner browser enrollment", Observation: "The operator must privately transport the one-use native CLI enrollment secret to the browser and separately complete password plus user-verifying passkey enrollment before the console is usable.", Remedy: "Single protected first-run browser setup with expiring custody-protected code."})
	result.Passed = true
	return result, nil
}

func (r *deployRoute) origin() string {
	return "https://" + strings.Replace(r.listener.Addr().String(), "127.0.0.1", "localhost", 1)
}

// Frozen historical schema contract: this audit intentionally runs the
// immutable pre-turnkey package, never recovery/setup tables added afterward.
const historicalAuditMigrationMetadataSQL = `REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.goose_db_version FROM lindm_runtime;
DO $$ DECLARE sequence_name text := pg_get_serial_sequence('public.goose_db_version', 'id');
BEGIN IF sequence_name IS NOT NULL THEN
EXECUTE 'REVOKE ALL ON SEQUENCE ' || sequence_name || ' FROM lindm_runtime';
END IF; END $$;`
