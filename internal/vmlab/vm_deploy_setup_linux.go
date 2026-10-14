// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/deploylab"
	"lindm/internal/platform"
	"lindm/internal/releasebuild"
)

type VMDeploySetupOptions struct {
	Repository, CacheDir, WorkDir, EvidenceDirectory, LabBinary      string
	FirstRelease, ReleasePublicKey, ReleaseKeyID, TUFRootFile        string
	BackupRecipientFile, CustodyEscrowRecipientFile, RedHatTokenFile string
	Airgap                                                           bool
	Browser                                                          func(context.Context, deploylab.BrowserRequest) (*deploylab.BrowserEvidence, error)
}

type VMDeploySetupResult struct {
	Scope                  string                     `json:"scope"`
	LifecycleQualified     bool                       `json:"lifecycle_qualified"`
	StartedAt              time.Time                  `json:"started_at"`
	FinishedAt             time.Time                  `json:"finished_at"`
	Passed                 bool                       `json:"passed"`
	Failure                string                     `json:"failure,omitempty"`
	ImageID                string                     `json:"image_id"`
	ImageSHA256            string                     `json:"image_sha256,omitempty"`
	GuestOS                []string                   `json:"guest_os"`
	Runtime                *vmRuntimeEvidence         `json:"runtime,omitempty"`
	ReleaseVersion         string                     `json:"release_version"`
	AirgapServerInstall    bool                       `json:"airgap_server_install"`
	Custody                string                     `json:"custody"`
	InitialPrerequisites   []string                   `json:"initial_prerequisites"`
	PostgresGate           bool                       `json:"postgres_gate"`
	DatabaseCredentialGate bool                       `json:"database_credential_gate"`
	RuntimeSQLGates        []VMDeploySQLGate          `json:"runtime_sql_gates"`
	Browser                *deploylab.BrowserEvidence `json:"browser,omitempty"`
	RecoveryCustodySHA256  string                     `json:"off_server_recovery_custody_sha256,omitempty"`
	EvidenceFiles          []string                   `json:"evidence_files"`
	CustodianIdentity      string                     `json:"custodian_identity"`
	Operations             []deploylab.Operation      `json:"operations"`
	ManualCommands         int                        `json:"manual_commands"`
	OperatorDecisions      int                        `json:"operator_decisions"`
	ObservedFailures       int                        `json:"observed_failures"`
	RedHat                 *VMRedHatEvidence          `json:"redhat,omitempty"`
	OwnedCleanupComplete   bool                       `json:"owned_cleanup_complete"`
}

// DeploySetupVM consumes one caller-owned FIFO slot, not the full three-guest
// lifecycle. The caller locks secret memory before entering this lab-only API.
// Success establishes install/first owner only and never qualifies deploy.
func DeploySetupVM(ctx context.Context, manifest *labv1.ImageManifest, options VMDeploySetupOptions) (result *VMDeploySetupResult, err error) {
	result = &VMDeploySetupResult{Scope: deploylab.FirstRunInstallScope, StartedAt: time.Now().UTC(), ImageID: manifest.GetId(), AirgapServerInstall: options.Airgap}
	defer func() { finishDeploySetupResult(result, err) }()
	if err := validateDeploySetupOptions(manifest, options); err != nil {
		return result, err
	}
	signed, err := releasebuild.Verify(ctx, options.FirstRelease, options.ReleasePublicKey, options.ReleaseKeyID)
	if err != nil {
		return result, err
	}
	result.ReleaseVersion, result.Custody = signed.GetVersion(), signed.GetCustody()
	private, err := os.MkdirTemp(options.EvidenceDirectory, ".lindm-deploy-setup-private-")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(private)) }()
	files, err := deploylab.CertificateFiles()
	if err != nil {
		return result, err
	}
	request, err := prepareDeploySetupBrowser(options, private, files)
	if err != nil {
		return result, err
	}
	defer func() { request.Password, request.SetupCode = "", "" }()
	passphrase := []byte(rand.Text() + rand.Text())
	defer clear(passphrase)
	if err := escrowDeployPassphrase(options.CustodyEscrowRecipientFile, filepath.Join(options.EvidenceDirectory, "source-custody-passphrase.age"), passphrase); err != nil {
		return result, err
	}
	result.EvidenceFiles = []string{"source-custody-passphrase.age"}
	result.CustodianIdentity = "lab operator fixture; not independent human custodians"
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
	request.Origin = "https://localhost:" + strings.Split(admin.listener.Addr().String(), ":")[1]
	request.Platform = manifestRelease(manifest).Name
	guest, err := newDeploySetupGuest(ctx, manifest, options, result)
	if guest != nil {
		defer func() {
			closeErr := guest.close()
			result.OwnedCleanupComplete = closeErr == nil
			err = errors.Join(err, closeErr)
		}()
	}
	if err != nil {
		return result, err
	}
	common := VMDeployOptions{Repository: options.Repository, CacheDir: options.CacheDir, WorkDir: options.WorkDir, EvidenceDirectory: options.EvidenceDirectory, LabBinary: options.LabBinary, FirstRelease: options.FirstRelease, ReleasePublicKey: options.ReleasePublicKey, ReleaseKeyID: options.ReleaseKeyID, TUFRootFile: options.TUFRootFile, BackupRecipientFile: options.BackupRecipientFile, RedHatTokenFile: options.RedHatTokenFile}
	if !options.Airgap {
		registration, err := prepareDeployEntitlement(ctx, guest, common, &result.RedHat)
		if err != nil {
			return result, err
		}
		if registration != nil {
			defer func() {
				err = errors.Join(err, releaseConsoleEnrollmentRedHat(context.WithoutCancel(ctx), guest, options.LabBinary, registration))
			}()
		}
	}
	if err := runDeploySetupOwner(ctx, guest, common, options.Browser, result, &request, files, passphrase, admin, device, options.Airgap); err != nil {
		return result, err
	}
	if err := exportDeployOfflineCustody(ctx, guest, private, &result.RecoveryCustodySHA256); err != nil {
		return result, err
	}
	if err := copyDeployEvidence(ctx, filepath.Join(private, "recovery-custody.age"), filepath.Join(options.EvidenceDirectory, "recovery-custody.age"), 8<<20, result.RecoveryCustodySHA256); err != nil {
		return result, err
	}
	result.EvidenceFiles = append(result.EvidenceFiles, "recovery-custody.age")
	result.Passed = true
	return result, nil
}

func finishDeploySetupResult(result *VMDeploySetupResult, err error) {
	result.Scope, result.LifecycleQualified = deploylab.FirstRunInstallScope, false
	result.FinishedAt = time.Now().UTC()
	result.ManualCommands, result.OperatorDecisions, result.ObservedFailures = deploylab.Counts(result.Operations)
	if err != nil {
		result.Passed = false
		result.OwnedCleanupComplete = false
		result.Failure = "first_run_install_failed"
	}
}

func validateDeploySetupOptions(manifest *labv1.ImageManifest, options VMDeploySetupOptions) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	release := manifestRelease(manifest)
	if err := release.LabLaneOn(platform.LaneDeploy, manifest.Architecture); err != nil {
		return err
	}
	if release.Version.Rule == platform.VersionMajor && manifest.Version == release.Version.Value {
		return errors.New("deploy setup requires an exact minor base image")
	}
	if options.Browser == nil || options.LabBinary == "" || options.EvidenceDirectory == "" || options.FirstRelease == "" || options.ReleasePublicKey == "" || options.ReleaseKeyID == "" || options.TUFRootFile == "" || options.BackupRecipientFile == "" || options.CustodyEscrowRecipientFile == "" {
		return errors.New("deploy setup requires real browser, independent release/TUF trust, backup public recipient and lab custody escrow public recipient")
	}
	if release.Lab.Entitlement && !options.Airgap && options.RedHatTokenFile == "" {
		return errors.New("deploy setup requires protected real Red Hat entitlement input")
	}
	if options.Airgap && options.RedHatTokenFile != "" {
		return errors.New("air-gap server setup requires the authenticated host-platform add-on, not an online Red Hat entitlement token")
	}
	return nil
}

func prepareDeploySetupBrowser(options VMDeploySetupOptions, private string, files map[string][]byte) (deploylab.BrowserRequest, error) {
	ca := filepath.Join(private, "transport-ca.crt")
	if err := os.WriteFile(ca, files["transport-ca.crt"], 0600); err != nil {
		return deploylab.BrowserRequest{}, err
	}
	return deploylab.BrowserRequest{Phase: "setup", Username: "deploy-" + strings.ToLower(rand.Text()), Password: rand.Text() + rand.Text(), CAFile: ca, PrivateDirectory: private, EvidenceDirectory: options.EvidenceDirectory, CredentialPath: filepath.Join(private, "passkey.json"), ResultPath: filepath.Join(options.EvidenceDirectory, "browser-setup.json")}, nil
}

func deploySetupHardware(airgap bool) *VMHardwareOptions {
	return &VMHardwareOptions{Architecture: "x86_64", Accelerator: "kvm", AllowNetwork: !airgap}
}

func newDeploySetupGuest(ctx context.Context, manifest *labv1.ImageManifest, options VMDeploySetupOptions, result *VMDeploySetupResult) (*guestVM, error) {
	guest, image, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, false, deploySetupHardware(options.Airgap))
	if err != nil {
		return nil, err
	}
	result.ImageSHA256 = image.SHA256
	if err := guest.connect(ctx); err != nil {
		return guest, err
	}
	if _, err := guest.run(ctx, "sudo -n cloud-init status --wait", nil, 64<<10, 5*time.Minute); err != nil {
		return guest, err
	}
	result.GuestOS, err = deployGuestOS(ctx, guest, manifest.Distribution, manifest.Version)
	if err != nil {
		return guest, err
	}
	result.Runtime, err = guest.runtimeEvidence(ctx)
	if err != nil {
		return guest, err
	}
	result.InitialPrerequisites, err = deployBootstrapInventory(ctx, guest)
	return guest, err
}

func observeDeploySetup(result *VMDeploySetupResult, name, kind string, run func() error) error {
	entry := deploylab.Operation{Name: name, Kind: kind, StartedAt: time.Now().UTC()}
	err := run()
	entry.FinishedAt, entry.Passed = time.Now().UTC(), err == nil
	if err != nil {
		entry.Failure = "operation_failed"
	}
	result.Operations = append(result.Operations, entry)
	return err
}

func runDeploySetupOwner(ctx context.Context, guest *guestVM, common VMDeployOptions, browser func(context.Context, deploylab.BrowserRequest) (*deploylab.BrowserEvidence, error), result *VMDeploySetupResult, request *deploylab.BrowserRequest, files map[string][]byte, passphrase []byte, admin, device *deployRoute, airgap bool) error {
	if err := prepareDeployInputs(ctx, guest, common, files); err != nil {
		return err
	}
	if err := observeDeploySetup(result, "install signed turnkey bundle", "command", func() error {
		return installDeployRelease(ctx, guest, common, common.FirstRelease, "/root/lindm-release-first", request.Origin, "https://localhost:"+strings.Split(device.listener.Addr().String(), ":")[1], result.ReleaseVersion, passphrase, airgap)
	}); err != nil {
		return err
	}
	if err := observeDeploySetup(result, "prove initial hardened owned PostgreSQL", "command", func() error { return proveDeployPostgres(ctx, guest, guest.release) }); err != nil {
		return err
	}
	result.PostgresGate = true
	if err := observeDeploySetup(result, "prove installed root-only database credentials", "harness", func() error { return proveDeployDatabaseCredentials(ctx, guest) }); err != nil {
		return err
	}
	result.DatabaseCredentialGate = true
	admin.activate(guest)
	device.activate(guest)
	if err := completeDeployOwner(ctx, guest, request, func() error {
		return observeDeploySetup(result, "browser setup", "harness", func() error {
			observed, err := browser(ctx, *request)
			result.Browser = observed
			if observed != nil {
				result.Operations = append(result.Operations, observed.Operations...)
			}
			return errors.Join(err, deploylab.ValidateBrowserEvidence(*request, observed))
		})
	}); err != nil {
		return err
	}
	return observeDeploySetup(result, "real runtime SQL security gates", "harness", func() error {
		var err error
		result.RuntimeSQLGates, err = proveDeployRuntimePrivileges(ctx, guest)
		return err
	})
}
