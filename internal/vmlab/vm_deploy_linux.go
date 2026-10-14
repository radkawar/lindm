// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/deploylab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
	"lindm/internal/releasebuild"
)

const deployServerDiskBytes int64 = 32 << 30

// VMDeployOptions consumes independently authenticated private release exports.
// Browser drives visible production controls; Recovery signs independently
// retained post-backup security state using the exported offline quorum custody.
// Neither callback may replace the native install, enrollment or restore CLI.
type VMDeployOptions struct {
	Repository, CacheDir, WorkDir, EvidenceDirectory, LabBinary  string
	FirstRelease, UpgradeRelease, ReleasePublicKey, ReleaseKeyID string
	BackupRecipientFile, BackupIdentityFile, TUFRootFile         string
	CustodyEscrowRecipientFile                                   string
	RedHatTokenFile                                              string
	BackupIdentityPassphrase                                     []byte `json:"-"`
	Browser                                                      func(context.Context, deploylab.BrowserRequest) (*deploylab.BrowserEvidence, error)
	VerifyBackup                                                 func(context.Context, string) error
	Recovery                                                     func(context.Context, string, string, []byte) (checkpoint, update string, err error)
}

// VMDeployResult retains failed runs too. Passed is set only after a fresh
// restored server manages the original enrolled VM with a new completed action.
type VMDeployResult struct {
	StartedAt                        time.Time                    `json:"started_at"`
	FinishedAt                       time.Time                    `json:"finished_at"`
	Passed                           bool                         `json:"passed"`
	Failure                          string                       `json:"failure,omitempty"`
	ImageID                          string                       `json:"image_id"`
	ImageSHA256                      string                       `json:"image_sha256"`
	GuestOS                          []string                     `json:"guest_os"`
	Runtime                          *vmRuntimeEvidence           `json:"runtime,omitempty"`
	RestoreRuntime                   *vmRuntimeEvidence           `json:"restore_runtime,omitempty"`
	ServerMinimumDiskBytes           int64                        `json:"server_minimum_disk_bytes"`
	ReleaseVersion                   string                       `json:"release_version"`
	UpgradeVersion                   string                       `json:"upgrade_version"`
	Custody                          string                       `json:"custody"`
	BackupSHA256                     string                       `json:"encrypted_backup_sha256,omitempty"`
	SecurityBackupSHA256             string                       `json:"fenced_security_backup_sha256,omitempty"`
	RecoveryCustodySHA256            string                       `json:"off_server_recovery_custody_sha256,omitempty"`
	RestoredCurrentSecuritySnapshot  bool                         `json:"restored_current_security_snapshot"`
	DeviceID                         string                       `json:"device_id,omitempty"`
	Enrollment                       *VMConsoleEnrollmentResult   `json:"enrollment,omitempty"`
	Browser                          []*deploylab.BrowserEvidence `json:"browser"`
	EvidenceFiles                    []string                     `json:"evidence_files"`
	TLS                              []*VMDeployTLSEvidence       `json:"tls"`
	RuntimeSQLGates                  []VMDeploySQLGate            `json:"runtime_sql_gates"`
	DatabaseCredentialGates          []string                     `json:"database_credential_gates"`
	IntegrationDestinationID         string                       `json:"integration_destination_id,omitempty"`
	IntegrationSecretSHA256          string                       `json:"integration_secret_sha256,omitempty"`
	IntegrationSecretGates           []string                     `json:"integration_secret_gates"`
	InitialPrerequisites             []string                     `json:"initial_prerequisites"`
	RestorePrerequisites             []string                     `json:"restore_initial_prerequisites"`
	FreshDatabaseCustodySHA256       string                       `json:"fresh_database_custody_sha256,omitempty"`
	InitialPostgresGate              bool                         `json:"initial_postgres_gate"`
	UpgradePostgresGate              bool                         `json:"upgrade_postgres_gate"`
	RestorePostgresGate              bool                         `json:"restore_postgres_gate"`
	CustodyConfirmationSHA256        string                       `json:"custody_confirmation_sha256,omitempty"`
	RestoreCustodyConfirmationSHA256 string                       `json:"restore_custody_confirmation_sha256,omitempty"`
	CustodianIdentity                string                       `json:"custodian_identity"`
	Operations                       []deploylab.Operation        `json:"operations"`
	Friction                         []deploylab.Friction         `json:"friction"`
	ManualCommands                   int                          `json:"manual_commands"`
	OperatorDecisions                int                          `json:"operator_decisions"`
	ObservedFailures                 int                          `json:"observed_failures"`
	RedHat                           *VMRedHatEvidence            `json:"redhat,omitempty"`
	RestoreRedHat                    *VMRedHatEvidence            `json:"restore_redhat,omitempty"`
	OwnedCleanupComplete             bool                         `json:"owned_cleanup_complete"`
}

// DeployVM runs three fresh x86 guests under one caller-owned FIFO reservation:
// the server, the console-enrolled device, and the fresh restore destination.
// It never opens the shared development database or imports a fixture owner.
func DeployVM(ctx context.Context, manifest *labv1.ImageManifest, options VMDeployOptions) (result *VMDeployResult, err error) {
	result = &VMDeployResult{StartedAt: time.Now().UTC(), ImageID: manifest.GetId(), ServerMinimumDiskBytes: deployServerDiskBytes}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		result.ManualCommands, result.OperatorDecisions, result.ObservedFailures = deploylab.Counts(result.Operations)
		if err != nil {
			result.Passed = false
			result.OwnedCleanupComplete = false
			result.Failure = "native_deployment_failed"
		}
	}()
	if err := validateManifest(manifest); err != nil {
		return result, err
	}
	release := manifestRelease(manifest)
	if err := release.LabLaneOn(platform.LaneDeploy, manifest.Architecture); err != nil {
		return result, err
	}
	if release.Version.Rule == platform.VersionMajor && manifest.Version == release.Version.Value {
		return result, errors.New("deploy requires an exact minor base image")
	}
	if options.Browser == nil || options.Recovery == nil || options.VerifyBackup == nil || options.EvidenceDirectory == "" || options.LabBinary == "" {
		return result, errors.New("deploy requires real browser, offline backup drill and independently signed restore reconciliation")
	}
	if release.Lab.Entitlement && options.RedHatTokenFile == "" {
		return result, errors.New("deploy requires protected Red Hat entitlement input")
	}
	first, err := releasebuild.Verify(ctx, options.FirstRelease, options.ReleasePublicKey, options.ReleaseKeyID)
	if err != nil {
		return result, err
	}
	next, err := releasebuild.Verify(ctx, options.UpgradeRelease, options.ReleasePublicKey, options.ReleaseKeyID)
	if err != nil {
		return result, err
	}
	if packaging.UpgradeOrdered(first.GetVersion(), next.GetVersion()) != nil || first.GetCustody() != next.GetCustody() {
		return result, errors.New("deploy requires a strictly newer signed build with the same custody")
	}
	result.ReleaseVersion, result.UpgradeVersion, result.Custody = first.GetVersion(), next.GetVersion(), first.GetCustody()
	private, err := os.MkdirTemp(options.EvidenceDirectory, ".lindm-deploy-private-")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(private)) }()
	caPath := filepath.Join(private, "console-ca.crt")
	custodyPassphrase := []byte(rand.Text() + rand.Text())
	defer clear(custodyPassphrase)
	if err := encryptDeployEvidence(options.CustodyEscrowRecipientFile, filepath.Join(options.EvidenceDirectory, "source-custody-passphrase.age"), custodyPassphrase); err != nil {
		return result, err
	}
	result.CustodianIdentity = "development lab operator fixture; not independent human custodians"
	result.EvidenceFiles = append(result.EvidenceFiles, "source-custody-passphrase.age")
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
	origin := "https://localhost:" + strings.Split(admin.listener.Addr().String(), ":")[1]
	deviceOrigin := "https://localhost:" + strings.Split(device.listener.Addr().String(), ":")[1]
	request := deploylab.BrowserRequest{Origin: origin, Username: "deploy-" + strings.ToLower(rand.Text()), Password: rand.Text() + rand.Text(), CAFile: caPath, PrivateDirectory: private, EvidenceDirectory: options.EvidenceDirectory, CredentialPath: filepath.Join(private, "passkey.json"), Platform: release.Name}
	defer func() { request.Password, request.SetupCode = "", "" }()
	op := func(name, kind string, run func() error) error {
		observed := deploylab.Operation{Name: name, Kind: kind, StartedAt: time.Now().UTC()}
		operationErr := run()
		observed.FinishedAt, observed.Passed = time.Now().UTC(), operationErr == nil
		if operationErr != nil {
			observed.Failure = "operation_failed"
			result.Friction = append(result.Friction, deploylab.Friction{Operation: name, Observation: "The real operation failed; private secret-bearing output was withheld.", Remedy: "Correct the reported prerequisite, preserving trust and identity checks; never bypass verification."})
		}
		result.Operations = append(result.Operations, observed)
		return operationErr
	}
	browser := func(phase, id string) error {
		request.Phase, request.DeviceID = phase, id
		request.ResultPath = filepath.Join(options.EvidenceDirectory, fmt.Sprintf("browser-%02d-%s.json", len(result.Browser), phase))
		return op("browser "+phase, "harness", func() error {
			observed, runErr := options.Browser(ctx, request)
			if observed != nil {
				result.Browser = append(result.Browser, observed)
				result.Operations = append(result.Operations, observed.Operations...)
				if phase == "integration" {
					result.IntegrationDestinationID = observed.IntegrationDestinationID
					result.IntegrationSecretSHA256 = observed.IntegrationSecretSHA256
				}
			}
			return errors.Join(runErr, deploylab.ValidateBrowserEvidence(request, observed))
		})
	}
	server, image, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, false, deployServerHardware(false))
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, server.close()) }()
	result.ImageSHA256 = image.SHA256
	if err := server.connect(ctx); err != nil {
		return result, err
	}
	if _, err := server.run(ctx, "sudo -n cloud-init status --wait", nil, 64<<10, 5*time.Minute); err != nil {
		return result, err
	}
	result.GuestOS, err = deployGuestOS(ctx, server, manifest.Distribution, manifest.Version)
	if err != nil {
		return result, err
	}
	result.Runtime, err = server.runtimeEvidence(ctx)
	if err != nil {
		return result, err
	}
	result.InitialPrerequisites, err = deployBootstrapInventory(ctx, server)
	if err != nil {
		return result, err
	}
	registration, err := prepareDeployEntitlement(ctx, server, options, &result.RedHat)
	if err != nil {
		return result, err
	}
	if registration != nil {
		defer func() {
			err = errors.Join(err, releaseConsoleEnrollmentRedHat(ctx, server, options.LabBinary, registration))
		}()
	}
	if err := prepareDeployInputs(ctx, server, options); err != nil {
		return result, err
	}
	if err := op("install signed turnkey bundle", "command", func() error {
		return installDeployRelease(ctx, server, options, options.FirstRelease, "/root/lindm-release-first", origin, deviceOrigin, first.GetVersion(), custodyPassphrase, false)
	}); err != nil {
		return result, err
	}
	if err := op("prove initial hardened owned PostgreSQL", "command", func() error { return proveDeployPostgres(ctx, server, release) }); err != nil {
		return result, err
	}
	result.InitialPostgresGate = true
	if err := op("prove installed root-only database credentials", "harness", func() error { return proveDeployDatabaseCredentials(ctx, server) }); err != nil {
		return result, err
	}
	result.DatabaseCredentialGates = append(result.DatabaseCredentialGates, "installed")
	admin.activate(server)
	device.activate(server)
	if err := op("verify installer-generated browser TLS", "harness", func() error {
		return observeDeployTLS(ctx, server, &request, "installed", nil, &result.TLS)
	}); err != nil {
		return result, err
	}
	if err := completeDeployOwner(ctx, server, &request, func() error { return browser("setup", "") }); err != nil {
		return result, err
	}
	if err := op("real runtime SQL security gates", "harness", func() error {
		var proofErr error
		result.RuntimeSQLGates, proofErr = proveDeployRuntimePrivileges(ctx, server)
		return proofErr
	}); err != nil {
		return result, err
	}
	if err := exportDeployOfflineCustody(ctx, server, private, &result.RecoveryCustodySHA256); err != nil {
		return result, err
	}
	if err := copyDeployEvidence(ctx, filepath.Join(private, "recovery-custody.age"), filepath.Join(options.EvidenceDirectory, "recovery-custody.age"), 8<<20, result.RecoveryCustodySHA256); err != nil {
		return result, err
	}
	result.EvidenceFiles = append(result.EvidenceFiles, "recovery-custody.age")
	custodyStatus, err := readDeployCustodyStatus(ctx, server, origin, deviceOrigin, map[string]string{"canonical_authority": result.RecoveryCustodySHA256})
	if err != nil {
		return result, err
	}
	request.CustodySHA256 = custodyStatus.ConfirmationSHA256
	request.CustodyExports = deployCustodyExports(custodyStatus)
	result.CustodyConfirmationSHA256 = request.CustodySHA256
	if err := browser("custody", ""); err != nil {
		return result, err
	}
	if err := browser("integration", ""); err != nil {
		return result, err
	}
	var integrationProof *DeployIntegrationProof
	if err := op("prove browser-created encrypted integration secret", "harness", func() error {
		var proofErr error
		integrationProof, proofErr = observeGuestDeployIntegration(ctx, server, result.IntegrationDestinationID, result.IntegrationSecretSHA256, nil, false)
		return proofErr
	}); err != nil {
		return result, err
	}
	defer clear(integrationProof.Ciphertext)
	result.IntegrationSecretGates = append(result.IntegrationSecretGates, "installed")
	request.CommandPath = filepath.Join(private, "console-command")
	result.Enrollment, err = EnrollFromConsoleVM(ctx, manifest, VMConsoleEnrollmentOptions{CacheDir: options.CacheDir, WorkDir: options.WorkDir, LabBinary: options.LabBinary, CommandFile: request.CommandPath, AdminAddress: admin.listener.Addr().String(), DeviceAddress: device.listener.Addr().String(), DiagnosticsDir: options.EvidenceDirectory, FailureRecipientFile: options.CustodyEscrowRecipientFile, RedHatTokenFile: options.RedHatTokenFile, CompletionTimeout: 3 * time.Hour, Hardware: &VMHardwareOptions{Architecture: "x86_64", Accelerator: "kvm"}, Ready: func() error { return browser("copy", "") }, VerifyEnrollment: func(ctx context.Context, enrolled *VMConsoleEnrollmentResult) (callbackErr error) {
		result.DeviceID = enrolled.DeviceID
		if err := browser("manage", enrolled.DeviceID); err != nil {
			return errors.Join(err, saveDeployFailureJournal(ctx, server, options.CustodyEscrowRecipientFile, options.EvidenceDirectory, "management-server-journal"))
		}
		admin.fence()
		device.fence()
		if err := op("encrypted backup", "command", func() error { return createDeployBackup(ctx, server, private, "backup.age", &result.BackupSHA256) }); err != nil {
			return err
		}
		if err := copyDeployEvidence(ctx, filepath.Join(private, "backup.age"), filepath.Join(options.EvidenceDirectory, "original-backup.tar.age"), 2<<30, result.BackupSHA256); err != nil {
			return err
		}
		result.EvidenceFiles = append(result.EvidenceFiles, "original-backup.tar.age")
		if err := op("offline encrypted backup drill", "command", func() error { return options.VerifyBackup(ctx, filepath.Join(private, "backup.age")) }); err != nil {
			return err
		}
		if err := op("upgrade signed turnkey bundle", "command", func() error {
			return installDeployRelease(ctx, server, options, options.UpgradeRelease, "/root/lindm-release-next", origin, deviceOrigin, next.GetVersion(), custodyPassphrase, false)
		}); err != nil {
			return err
		}
		if err := op("prove upgraded hardened owned PostgreSQL", "command", func() error { return proveDeployPostgres(ctx, server, release) }); err != nil {
			return err
		}
		result.UpgradePostgresGate = true
		if err := op("prove upgraded root-only database credentials", "harness", func() error { return proveDeployDatabaseCredentials(ctx, server) }); err != nil {
			return err
		}
		result.DatabaseCredentialGates = append(result.DatabaseCredentialGates, "upgraded")
		if err := op("prove upgrade retained integration key and ciphertext", "harness", func() error {
			proof, proofErr := observeGuestDeployIntegration(ctx, server, result.IntegrationDestinationID, result.IntegrationSecretSHA256, integrationProof.Ciphertext, false)
			if proofErr != nil {
				return proofErr
			}
			if proof.EncryptionKeySHA256 != integrationProof.EncryptionKeySHA256 {
				return errors.New("upgrade replaced the integration encryption key")
			}
			return nil
		}); err != nil {
			return err
		}
		result.IntegrationSecretGates = append(result.IntegrationSecretGates, "upgraded")
		admin.activate(server)
		device.activate(server)
		if err := op("prove upgrade retained console and device transport CAs", "harness", func() error {
			return observeDeployTLS(ctx, server, &request, "upgraded", result.TLS[0], &result.TLS)
		}); err != nil {
			return err
		}
		if err := browser("manage", enrolled.DeviceID); err != nil {
			return err
		}
		admin.fence()
		device.fence()
		if _, runErr := serverGuestCommand(ctx, server, "fence original server", "systemctl stop lindmd.service", nil); runErr != nil {
			return runErr
		}
		if runErr := op("fenced security snapshot backup", "command", func() error {
			return createDeployBackup(ctx, server, private, "security-backup.age", &result.SecurityBackupSHA256)
		}); runErr != nil {
			return runErr
		}
		if err := copyDeployEvidence(ctx, filepath.Join(private, "security-backup.age"), filepath.Join(options.EvidenceDirectory, "current-fenced-security.tar.age"), 2<<30, result.SecurityBackupSHA256); err != nil {
			return err
		}
		result.EvidenceFiles = append(result.EvidenceFiles, "current-fenced-security.tar.age")
		var checkpoint, update string
		if runErr := op("offline higher-epoch delegation and checkpoint quorum signing", "harness", func() error {
			var signErr error
			checkpoint, update, signErr = options.Recovery(ctx, private, options.EvidenceDirectory, custodyPassphrase)
			return signErr
		}); runErr != nil {
			return runErr
		}
		for _, name := range []string{"execution-root.json", "bootstrap.dsse.json", "execution-delegation.json", "recovery-delegation.dsse.json", "execution-update.json", "security-checkpoint.dsse.json", "transport-ca.crt"} {
			if err := copyDeployEvidence(ctx, filepath.Join(private, name), filepath.Join(options.EvidenceDirectory, name), 8<<20, ""); err != nil {
				return err
			}
			result.EvidenceFiles = append(result.EvidenceFiles, name)
		}
		restored, _, runErr := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, false, deployServerHardware(false))
		if runErr != nil {
			return runErr
		}
		defer func() { callbackErr = errors.Join(callbackErr, restored.close()) }()
		if runErr := restored.connect(ctx); runErr != nil {
			return runErr
		}
		if _, runErr := restored.run(ctx, "sudo -n cloud-init status --wait", nil, 64<<10, 5*time.Minute); runErr != nil {
			return runErr
		}
		if _, runErr := deployGuestOS(ctx, restored, manifest.Distribution, manifest.Version); runErr != nil {
			return runErr
		}
		result.RestoreRuntime, runErr = restored.runtimeEvidence(ctx)
		if runErr != nil {
			return runErr
		}
		result.RestorePrerequisites, runErr = deployBootstrapInventory(ctx, restored)
		if runErr != nil {
			return runErr
		}
		restoreRegistration, runErr := prepareDeployEntitlement(ctx, restored, options, &result.RestoreRedHat)
		if runErr != nil {
			return runErr
		}
		if restoreRegistration != nil {
			defer func() {
				callbackErr = errors.Join(callbackErr, releaseConsoleEnrollmentRedHat(ctx, restored, options.LabBinary, restoreRegistration))
			}()
		}
		if runErr := prepareDeployInputs(ctx, restored, options); runErr != nil {
			return runErr
		}
		freshCustodyPassphrase := []byte(rand.Text() + rand.Text())
		defer clear(freshCustodyPassphrase)
		if runErr := encryptDeployEvidence(options.CustodyEscrowRecipientFile, filepath.Join(options.EvidenceDirectory, "fresh-database-custody-passphrase.age"), freshCustodyPassphrase); runErr != nil {
			return runErr
		}
		result.EvidenceFiles = append(result.EvidenceFiles, "fresh-database-custody-passphrase.age")
		if runErr := installDeployRelease(ctx, restored, options, options.UpgradeRelease, "/root/lindm-release-restore", origin, deviceOrigin, next.GetVersion(), freshCustodyPassphrase, false); runErr != nil {
			return runErr
		}
		if runErr := op("prove fresh restore hardened owned PostgreSQL", "command", func() error { return proveDeployPostgres(ctx, restored, release) }); runErr != nil {
			return runErr
		}
		result.RestorePostgresGate = true
		if runErr := op("prove fresh destination root-only database credentials", "harness", func() error { return proveDeployDatabaseCredentials(ctx, restored) }); runErr != nil {
			return runErr
		}
		result.DatabaseCredentialGates = append(result.DatabaseCredentialGates, "fresh_destination")
		if runErr := op("prove fresh key cannot decrypt original integration secret", "harness", func() error {
			proof, proofErr := observeGuestDeployIntegration(ctx, restored, result.IntegrationDestinationID, result.IntegrationSecretSHA256, integrationProof.Ciphertext, true)
			if proofErr != nil {
				return proofErr
			}
			if proof.EncryptionKeySHA256 == integrationProof.EncryptionKeySHA256 {
				return errors.New("fresh restore destination reused source integration key")
			}
			return nil
		}); runErr != nil {
			return runErr
		}
		result.IntegrationSecretGates = append(result.IntegrationSecretGates, "fresh_key_rejected")
		if runErr := copyDeployRecoveryCustody(ctx, restored, "/var/lib/lindmd-operations/recovery-custody.age", filepath.Join(private, "fresh-database-recovery-custody.age"), &result.FreshDatabaseCustodySHA256); runErr != nil {
			return runErr
		}
		if runErr := copyDeployEvidence(ctx, filepath.Join(private, "fresh-database-recovery-custody.age"), filepath.Join(options.EvidenceDirectory, "fresh-database-recovery-custody.age"), 8<<20, result.FreshDatabaseCustodySHA256); runErr != nil {
			return runErr
		}
		result.EvidenceFiles = append(result.EvidenceFiles, "fresh-database-recovery-custody.age")
		if _, runErr := serverGuestCommand(ctx, restored, "fence fresh restore destination preserving its database custody", "systemctl stop lindmd.service; rm -- /root/lindm-deploy-input/setup-code", nil); runErr != nil {
			return runErr
		}
		for name, path := range map[string]string{"backup.age": filepath.Join(private, "backup.age"), "security-backup.age": filepath.Join(private, "security-backup.age"), "execution-root.json": filepath.Join(private, "execution-root.json"), "backup-identity": options.BackupIdentityFile, "security-checkpoint": checkpoint, "execution-update": update} {
			if runErr := uploadDeployPath(ctx, restored, path, "/root/lindm-deploy-input/"+name); runErr != nil {
				return runErr
			}
		}
		if runErr := op("restore encrypted backup into fresh VM", "command", func() error {
			input := io.MultiReader(bytes.NewReader(options.BackupIdentityPassphrase), strings.NewReader("\n"))
			_, restoreErr := serverGuestCommand(ctx, restored, "restore encrypted backup into fresh VM", "cat | lindmd restore -archive /root/lindm-deploy-input/backup.age -security-archive /root/lindm-deploy-input/security-backup.age -identity-file /root/lindm-deploy-input/backup-identity -identity-passphrase-fd 0 -root-file /root/lindm-deploy-input/execution-root.json -config /etc/lindm/migrate/server.json -security-checkpoint /root/lindm-deploy-input/security-checkpoint -execution-update /root/lindm-deploy-input/execution-update -confirm-fenced -reason 'Maintained lab fenced fresh-host recovery drill' && rm -- /root/lindm-deploy-input/backup-identity && systemctl start lindmd.service", input)
			return restoreErr
		}); runErr != nil {
			return runErr
		}
		if runErr := op("prove restored root-only database credentials", "harness", func() error { return proveDeployDatabaseCredentials(ctx, restored) }); runErr != nil {
			return runErr
		}
		result.DatabaseCredentialGates = append(result.DatabaseCredentialGates, "restored")
		if runErr := op("prove restored original integration key decrypts original destination", "harness", func() error {
			proof, proofErr := observeGuestDeployIntegration(ctx, restored, result.IntegrationDestinationID, result.IntegrationSecretSHA256, integrationProof.Ciphertext, false)
			if proofErr != nil {
				return proofErr
			}
			if proof.EncryptionKeySHA256 != integrationProof.EncryptionKeySHA256 {
				return errors.New("restore did not recover original integration key")
			}
			return nil
		}); runErr != nil {
			return runErr
		}
		result.IntegrationSecretGates = append(result.IntegrationSecretGates, "restored")
		restoreCustody, runErr := readDeployCustodyStatus(ctx, restored, origin, deviceOrigin, map[string]string{"canonical_authority": result.RecoveryCustodySHA256, "fresh_database": result.FreshDatabaseCustodySHA256})
		if runErr != nil {
			return runErr
		}
		for _, export := range restoreCustody.Exports {
			if export.Kind != "fresh_database" {
				continue
			}
			var copied string
			if runErr := copyDeployRecoveryCustody(ctx, restored, export.Path, filepath.Join(private, "preserved-fresh-database-custody.age"), &copied); runErr != nil {
				return runErr
			}
			if copied != result.FreshDatabaseCustodySHA256 {
				return errors.New("restore changed the off-server fresh database custody export")
			}
			var caDigest string
			if runErr := copyDeploySealedDatabaseCA(ctx, restored, filepath.Join(filepath.Dir(export.Path), "sealed-pki-ca.age"), filepath.Join(options.EvidenceDirectory, "fresh-database-sealed-pki-ca.age"), &caDigest); runErr != nil {
				return runErr
			}
			result.EvidenceFiles = append(result.EvidenceFiles, "fresh-database-sealed-pki-ca.age")
		}
		request.CustodySHA256 = restoreCustody.ConfirmationSHA256
		request.CustodyExports = deployCustodyExports(restoreCustody)
		result.RestoreCustodyConfirmationSHA256 = request.CustodySHA256
		admin.activate(restored)
		device.activate(restored)
		if runErr := op("prove restore recovered console and device transport CAs", "harness", func() error {
			return observeDeployTLS(ctx, restored, &request, "restored", result.TLS[0], &result.TLS)
		}); runErr != nil {
			return runErr
		}
		if runErr := browser("custody", ""); runErr != nil {
			return runErr
		}
		if runErr := browser("manage", enrolled.DeviceID); runErr != nil {
			return runErr
		}
		result.RestoredCurrentSecuritySnapshot = true
		admin.fence()
		device.fence()
		return nil
	}})
	if err != nil {
		return result, err
	}
	result.Passed, result.OwnedCleanupComplete = true, true
	return result, nil
}

func prepareDeployEntitlement(ctx context.Context, guest *guestVM, options VMDeployOptions, evidence **VMRedHatEvidence) (*vmRedHatRegistration, error) {
	if !guest.release.Lab.Entitlement {
		return nil, nil
	}
	*evidence = new(VMRedHatEvidence)
	return registerConsoleEnrollmentRedHat(ctx, guest, VMConsoleEnrollmentOptions{LabBinary: options.LabBinary, RedHatTokenFile: options.RedHatTokenFile}, *evidence)
}

func prepareDeployInputs(ctx context.Context, guest *guestVM, options VMDeployOptions) error {
	if _, err := serverGuestCommand(ctx, guest, "create protected deployment inputs", "install -d -m 0700 /root/lindm-deploy-input", nil); err != nil {
		return err
	}
	for name, path := range map[string]string{"release-key": options.ReleasePublicKey, "backup-recipient": options.BackupRecipientFile, "tuf-root": options.TUFRootFile, "lab-helper": options.LabBinary} {
		if err := uploadDeployPath(ctx, guest, path, "/root/lindm-deploy-input/"+name); err != nil {
			return err
		}
	}
	return nil
}

func uploadDeployPath(ctx context.Context, guest *guestVM, source, destination string) (err error) {
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return uploadDeployFile(ctx, guest, destination, file)
}

func installDeployRelease(ctx context.Context, guest *guestVM, options VMDeployOptions, source, destination, origin, deviceOrigin, version string, passphrase []byte, airgap bool) error {
	if err := uploadDeployDirectory(ctx, guest, source, destination); err != nil {
		return err
	}
	command := deployInstallerCommand(options, destination, origin, deviceOrigin, version, airgap)
	input := io.MultiReader(bytes.NewReader(passphrase), strings.NewReader("\n"), bytes.NewReader(passphrase), strings.NewReader("\n"))
	return executeDeployInstaller(ctx, guest, options, destination, command, input)
}

func deployInstallerCommand(options VMDeployOptions, destination, origin, deviceOrigin, version string, airgap bool) string {
	command := "cmp -s /root/lindm-deploy-input/tuf-root " + nativeQuote(destination+"/release-root.json") + " && cat | sh " + nativeQuote(destination+"/install.sh") + " --custody-passphrase-fd 0 --release-key-file /root/lindm-deploy-input/release-key --release-key-id " + nativeQuote(options.ReleaseKeyID) + " --origin " + nativeQuote(origin) + " --device-origin " + nativeQuote(deviceOrigin) + " --backup-recipient-file /root/lindm-deploy-input/backup-recipient --setup-code-file /root/lindm-deploy-input/setup-code"
	if airgap {
		command += " --airgap"
	}
	return command + " && test \"$(/usr/bin/lindmd version)\" = " + nativeQuote(version)
}

func exportDeployOfflineCustody(ctx context.Context, guest *guestVM, private string, digest *string) error {
	for _, name := range []string{"execution-root.json", "bootstrap.dsse.json", "execution-delegation.json"} {
		data, err := serverGuestCommand(ctx, guest, "transfer public deployment trust", "cat "+nativeQuote("/etc/lindm/"+name), nil)
		if err != nil {
			return err
		}
		path := filepath.Join(private, filepath.Base(name))
		writeErr := os.WriteFile(path, data, 0600)
		clear(data)
		if writeErr != nil {
			return writeErr
		}
	}
	const source = "/var/lib/lindmd-operations/recovery-custody.age"
	if _, err := serverGuestCommand(ctx, guest, "generated custody has no plaintext execution roots", "test ! -e /etc/lindm/offline/execution-root-0.key; test ! -e /etc/lindm/offline/execution-root-1.key; test ! -e /etc/lindm/offline/execution-root-2.key; test \"$(stat -c %a "+source+")\" = 640; test \"$(stat -c %u "+source+")\" = 0; test \"$(stat -c %a /etc/lindm/offline)\" = 700; test \"$(find /etc/lindm/offline -maxdepth 1 -type f | wc -l)\" = 4; for name in root-key-1.age root-key-2.age root-key-3.age sealed-pki-ca.age; do test \"$(stat -c %u /etc/lindm/offline/$name)\" = 0; test \"$(stat -c %a /etc/lindm/offline/$name)\" = 600; done", nil); err != nil {
		return err
	}
	return copyDeployRecoveryCustody(ctx, guest, source, filepath.Join(private, "recovery-custody.age"), digest)
}

func copyDeployRecoveryCustody(ctx context.Context, guest *guestVM, source, destination string, digest *string) error {
	sourceHash, err := serverGuestCommand(ctx, guest, "hash root-protected encrypted recovery custody", "test \"$(stat -c %u "+nativeQuote(source)+")\" = 0; test \"$(stat -c %a "+nativeQuote(source)+")\" = 640; sha256sum "+nativeQuote(source), nil)
	if err != nil {
		return err
	}
	if err := copyDeployBackup(ctx, guest, source, destination, digest); err != nil {
		return err
	}
	fields := strings.Fields(string(sourceHash))
	if len(fields) != 2 || fields[0] != *digest || fields[1] != source {
		return errors.New("off-server encrypted recovery export digest does not match root-protected source")
	}
	return nil
}

func createDeployBackup(ctx context.Context, guest *guestVM, private, name string, digest *string) error {
	directory := "/root/lindm-deploy-input/" + strings.TrimSuffix(name, ".age")
	fenced := ""
	if name == "security-backup.age" {
		fenced = " -confirm-fenced"
	}
	path, err := serverGuestCommand(ctx, guest, "create encrypted backup", "lindmd backup -config /etc/lindm/server.json -output-dir "+nativeQuote(directory)+" -recipient-file /root/lindm-deploy-input/backup-recipient"+fenced, nil)
	if err != nil {
		return err
	}
	source := strings.TrimSpace(string(path))
	if !strings.HasPrefix(source, directory+"/lindmd-") || !strings.HasSuffix(source, ".tar.age") || strings.ContainsAny(source, "\r\n") {
		return errors.New("deploy backup did not return one archive path in its owned directory")
	}
	return copyDeployBackup(ctx, guest, source, filepath.Join(private, name), digest)
}

func copyDeployBackup(ctx context.Context, guest *guestVM, source, destination string, digest *string) (err error) {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	session, err := guest.client.NewSession()
	if err != nil {
		return err
	}
	defer func() { err = closeDeployTransfer(err, session) }()
	hash := sha256.New()
	bounded := &deployBackupWriter{writer: io.MultiWriter(file, hash)}
	session.Stdout = bounded
	session.Stderr = io.Discard
	transfer, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	interrupt := context.AfterFunc(transfer, func() { _ = session.Close() })
	defer interrupt()
	if err := session.Run("sudo -n cat " + nativeQuote(source)); err != nil {
		return errors.New("deploy encrypted backup transfer failed")
	}
	if bounded.bytes == 0 {
		return errors.New("deploy backup archive is empty")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	*digest = hex.EncodeToString(hash.Sum(nil))
	return nil
}

func closeDeployTransfer(current error, transfer io.Closer) error {
	closeErr := transfer.Close()
	if errors.Is(closeErr, io.EOF) {
		// A completed SSH Run closes the remote channel before deferred cleanup.
		return current
	}
	return errors.Join(current, closeErr)
}

func saveDeployFailureJournal(ctx context.Context, guest *guestVM, recipient, directory, label string) error {
	if recipient == "" || directory == "" || guest.client == nil || guest.processError() != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	output, err := guest.runResult(ctx, "sudo -n journalctl --no-pager -u lindmd.service -u lindm-agent.service -u lindm-executor.service -n 1500 -o short-iso-precise", nil, deployInstallerDiagnosticLimit, 10*time.Second)
	defer clear(output.Stdout)
	defer clear(output.Stderr)
	return errors.Join(err, writeDeployInstallerDiagnostics(recipient, directory, label, output.Stdout, output.Stderr))
}

type deployBackupWriter struct {
	writer io.Writer
	bytes  int64
}

func (w *deployBackupWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > (2<<30)-w.bytes {
		return 0, errors.New("deploy encrypted backup exceeds 2GiB transfer bound")
	}
	n, err := w.writer.Write(data)
	w.bytes += int64(n)
	return n, err
}
