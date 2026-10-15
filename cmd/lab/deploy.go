// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/custody"
	"lindm/internal/deploylab"
	"lindm/internal/devlab/toolchain"
	"lindm/internal/labexec"
	"lindm/internal/trust"
	"lindm/internal/vmlab"
)

// runDeployAdmitted is called only after the normal VM scheduler acquired the
// complete three-guest footprint. Internal vmlab calls never reacquire a slot.
func runDeployAdmitted(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("deploy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options vmlab.VMDeployOptions
	manifestPath := flags.String("manifest", "", "pinned fresh Ubuntu24.04 or entitled RHEL9 x86 cloud image")
	flags.StringVar(&options.Repository, "repo", ".", "checkout containing the maintained real browser driver")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified vendor image cache")
	flags.StringVar(&options.WorkDir, "work-dir", "", "configured native lab work directory")
	flags.StringVar(&options.EvidenceDirectory, "evidence", "", "new private persistent evidence directory")
	flags.StringVar(&options.LabBinary, "lab", "", "matching prebuilt native observer; this executable by default")
	flags.StringVar(&options.FirstRelease, "first-release", "", "private signed release N export with turnkey installer")
	flags.StringVar(&options.UpgradeRelease, "upgrade-release", "", "private signed newer release N+1 export")
	flags.StringVar(&options.ReleasePublicKey, "release-public-key", "", "independently authenticated release attestation public key")
	flags.StringVar(&options.ReleaseKeyID, "release-key-id", "", "independently pinned release attestation key ID")
	flags.StringVar(&options.TUFRootFile, "tuf-root-file", "", "independently authenticated signed release-update root")
	flags.StringVar(&options.BackupRecipientFile, "backup-recipient-file", "", "protected age recipient public input")
	flags.StringVar(&options.CustodyEscrowRecipientFile, "custody-escrow-recipient-file", "", "dedicated durable LAB-ONLY public age escrow recipient; never a server backup recipient")
	flags.StringVar(&options.BackupIdentityFile, "backup-identity-file", "", "passphrase-encrypted age backup identity kept off the online server")
	identityPassphraseFD := flags.Int("backup-identity-passphrase-fd", -1, "protected anonymous private pipe carrying one backup identity passphrase line; numeric descriptor only")
	identityPassphraseEscrow := flags.String("backup-identity-passphrase-escrow", "", "durable age-encrypted off-server lab backup unlock phrase instead of a secret FD")
	labEscrowIdentity := flags.String("lab-escrow-identity-file", "", "dedicated protected LAB-ONLY private escrow identity; never uploaded or bundled")
	flags.StringVar(&options.RedHatTokenFile, "redhat-token-file", "", "protected available Red Hat offline-token input; never print contents")
	lindmd := flags.String("lindmd", "", "matching consolidated prebuilt lindmd for offline backup drill/checkpoint signing")
	lindmctl := flags.String("lindmctl", "", "matching prebuilt owner CLI for offline higher-epoch delegation")
	record := flags.String("record", "", "new private nonsecret full workflow/audit record")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *record == "" || options.EvidenceDirectory == "" || *lindmd == "" || *lindmctl == "" || options.CustodyEscrowRecipientFile == "" {
		return errors.New("deploy requires -manifest, -first-release, -upgrade-release, explicit trust and backup inputs, -lindmd, -lindmctl, -evidence and -record; no positional arguments")
	}
	if *identityPassphraseFD < 0 && (*identityPassphraseEscrow == "" || *labEscrowIdentity == "") {
		return errors.New("deploy requires protected backup passphrase FD or durable encrypted lab unlock escrow with dedicated operator identity")
	}
	if err := prepareDeployCustodianMemory(ctx, options.Repository); err != nil {
		return err
	}
	if err := custody.LockSecretMemory(); err != nil {
		return err
	}
	var err error
	options.BackupIdentityPassphrase, err = readDeployBackupUnlock(ctx, *identityPassphraseFD, *identityPassphraseEscrow, *labEscrowIdentity)
	if err != nil {
		return err
	}
	defer clear(options.BackupIdentityPassphrase)
	if options.LabBinary == "" {
		var err error
		options.LabBinary, err = os.Executable()
		if err != nil {
			return err
		}
	}
	if err := resolvePackagePaths(&options.Repository, &options.CacheDir, &options.WorkDir, &options.EvidenceDirectory, &options.LabBinary, &options.FirstRelease, &options.UpgradeRelease, &options.ReleasePublicKey, &options.TUFRootFile, &options.BackupRecipientFile, &options.CustodyEscrowRecipientFile, &options.BackupIdentityFile, &options.RedHatTokenFile, lindmd, lindmctl, record); err != nil {
		return err
	}
	if err := os.Mkdir(options.EvidenceDirectory, 0700); err != nil {
		return err
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	options.Browser = deployBrowser(options.Repository)
	options.VerifyBackup = func(ctx context.Context, archive string) error {
		return offlineDeployCommand(ctx, options.Repository, *lindmd, [][]byte{options.BackupIdentityPassphrase}, "restore-drill", "-archive", archive, "-identity-file", options.BackupIdentityFile, "-identity-passphrase-fd", "0")
	}
	var recoveryOperations []deploylab.Operation
	options.Recovery = func(ctx context.Context, private, _ string, custodyPassphrase []byte) (string, string, error) {
		return signDeployRecovery(ctx, options.Repository, private, options.BackupIdentityFile, *lindmd, *lindmctl, options.BackupIdentityPassphrase, custodyPassphrase, &recoveryOperations)
	}
	result, runErr := vmlab.DeployVM(ctx, manifest, options)
	if result != nil {
		result.Operations = append(result.Operations, recoveryOperations...)
		result.ManualCommands, result.OperatorDecisions, result.ObservedFailures = deploylab.Counts(result.Operations)
	}
	return errors.Join(runErr, writeLabEvidence(stdout, *record, result))
}

// offlineDeployCommand suppresses tool diagnostics because a parser can quote
// protected files. Its failure names the executable operation, never content.
func offlineDeployCommand(ctx context.Context, repository, executable string, passphrases [][]byte, args ...string) (err error) {
	if err := prepareDeployCustodianMemory(ctx, repository); err != nil {
		return err
	}
	pipes := make([]*os.File, 0, len(passphrases))
	defer func() {
		for _, pipe := range pipes {
			err = errors.Join(err, pipe.Close())
		}
	}()
	for _, passphrase := range passphrases {
		pipe, pipeErr := protectedDeployPipe(passphrase)
		if pipeErr != nil {
			return pipeErr
		}
		pipes = append(pipes, pipe)
	}
	var stdin io.Reader
	var files []*os.File
	if len(pipes) > 0 {
		stdin = pipes[0]
		files = pipes[1:]
	}
	if err := labexec.Run(ctx, labexec.Command{Path: executable, Args: args, Dir: repository, Stdin: stdin, Files: files, Timeout: 10 * time.Minute, Interrupt: syscall.SIGTERM, Grace: 30 * time.Second}); err != nil {
		return fmt.Errorf("deploy offline %s failed (protected output withheld): %w", args[0], err)
	}
	return nil
}

func signDeployRecovery(ctx context.Context, repository, private, identity, lindmd, lindmctl string, identityPassphrase, custodyPassphrase []byte, observed *[]deploylab.Operation) (string, string, error) {
	signCommand := func(name, executable string, passphrases [][]byte, args ...string) error {
		entry := deploylab.Operation{Name: name, Kind: "command", StartedAt: time.Now().UTC()}
		signErr := offlineDeployCommand(ctx, repository, executable, passphrases, args...)
		entry.FinishedAt, entry.Passed = time.Now().UTC(), signErr == nil
		if signErr != nil {
			entry.Failure = "offline_signing_failed"
		}
		*observed = append(*observed, entry)
		return signErr
	}
	rootPath := filepath.Join(private, "execution-root.json")
	rootBody, err := os.ReadFile(rootPath)
	if err != nil {
		return "", "", err
	}
	root := new(agentv1.ExecutionRoot)
	if err := protojson.Unmarshal(rootBody, root); err != nil {
		return "", "", err
	}
	delegationBody, err := os.ReadFile(filepath.Join(private, "execution-delegation.json"))
	if err != nil {
		return "", "", err
	}
	authority, err := trust.New()
	if err != nil {
		return "", "", err
	}
	delegation := new(agentv1.ExecutionDelegation)
	if err := verifyDeployDelegationRequest(ctx, authority, root, delegationBody, delegation); err != nil {
		return "", "", err
	}
	if delegation.GetVersion() == ^uint64(0) || delegation.GetMinimumRecoveryEpoch() == ^uint64(0) {
		return "", "", errors.New("deploy recovery counters exhausted")
	}
	previous, oldEpoch := delegation.GetVersion(), delegation.GetMinimumRecoveryEpoch()
	delegation.Version++
	delegation.MinimumRecoveryEpoch++
	declaration, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(delegation)
	if err != nil {
		return "", "", err
	}
	declarationPath := filepath.Join(private, "recovery-delegation.json")
	if err := os.WriteFile(declarationPath, declaration, 0600); err != nil {
		return "", "", err
	}
	envelopePath := filepath.Join(private, "recovery-delegation.dsse.json")
	signArgs := []string{"execution", "delegation", "sign", "-root", rootPath, "-bootstrap", filepath.Join(private, "bootstrap.dsse.json"), "-declaration", declarationPath, "-previous-version", strconv.FormatUint(previous, 10), "-minimum-recovery-epoch", strconv.FormatUint(oldEpoch, 10), "-out", envelopePath}
	signArgs = append(signArgs, "-custody-export-file", filepath.Join(private, "recovery-custody.age"), "-custody-passphrase-fd", "0")
	if err := signCommand("offline higher-epoch delegation quorum signature", lindmctl, [][]byte{custodyPassphrase}, signArgs...); err != nil {
		return "", "", err
	}
	envelope, err := os.ReadFile(envelopePath)
	if err != nil {
		return "", "", err
	}
	update, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: envelope})
	if err != nil {
		return "", "", err
	}
	updatePath := filepath.Join(private, "execution-update.json")
	if err := os.WriteFile(updatePath, update, 0600); err != nil {
		return "", "", err
	}
	checkpoint := filepath.Join(private, "security-checkpoint.dsse.json")
	checkpointArgs := []string{"restore", "checkpoint-sign", "-archive", filepath.Join(private, "backup.age"), "-security-archive", filepath.Join(private, "security-backup.age"), "-identity-file", identity, "-root-file", rootPath, "-recovery-epoch", strconv.FormatUint(delegation.GetMinimumRecoveryEpoch(), 10), "-output", checkpoint, "-confirm-fenced"}
	checkpointArgs = append(checkpointArgs, "-identity-passphrase-fd", "0", "-custody-export-file", filepath.Join(private, "recovery-custody.age"), "-custody-passphrase-fd", "3")
	if err := signCommand("offline fenced security checkpoint quorum signature", lindmd, [][]byte{identityPassphrase, custodyPassphrase}, checkpointArgs...); err != nil {
		return "", "", err
	}
	return checkpoint, updatePath, nil
}

func verifyDeployDelegationRequest(ctx context.Context, authority *trust.Authority, root *agentv1.ExecutionRoot, requestBody []byte, declaration *agentv1.ExecutionDelegation) error {
	request := new(agentv1.UpdateExecutionTrustRequest)
	if err := protojson.Unmarshal(requestBody, request); err != nil {
		return errors.New("deploy: installed execution delegation request is invalid")
	}
	keys := make([]ed25519.PublicKey, 0, len(root.GetKeys()))
	for _, key := range root.GetKeys() {
		keys = append(keys, ed25519.PublicKey(key.GetPublicKey()))
	}
	if err := authority.Verify(ctx, request.GetDelegationEnvelope(), declaration, int(root.GetThreshold()), keys...); err != nil {
		return err
	}
	now := time.Now()
	if declaration.GetDeploymentId() != root.GetDeploymentId() || declaration.GetRootVersion() != root.GetVersion() || now.Before(declaration.GetNotBefore().AsTime()) || !now.Before(declaration.GetExpiresAt().AsTime()) || now.Before(root.GetNotBefore().AsTime()) || !now.Before(root.GetExpiresAt().AsTime()) {
		return errors.New("deploy: offline custody delegation is not current for the authenticated deployment")
	}
	return nil
}

func deployBrowser(repository string) func(context.Context, deploylab.BrowserRequest) (*deploylab.BrowserEvidence, error) {
	return func(ctx context.Context, request deploylab.BrowserRequest) (*deploylab.BrowserEvidence, error) {
		configuration, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(request.PrivateDirectory, "deploy-browser.json")
		if err := os.WriteFile(path, configuration, 0600); err != nil {
			clear(configuration)
			return nil, err
		}
		clear(configuration)
		node, environ, err := toolchain.Node(ctx, repository, os.Environ())
		if err != nil {
			return nil, err
		}
		runErr := labexec.Run(ctx, labexec.Command{Path: node, Args: []string{filepath.Join(repository, "web/acceptance/deploy.mjs"), path}, Env: environ, Dir: repository, Timeout: deploylab.BrowserTimeout(request), Interrupt: syscall.SIGTERM, Grace: 45 * time.Second})
		observed := new(deploylab.BrowserEvidence)
		readErr := readConsoleBrowserJSON(request.ResultPath, observed)
		return observed, errors.Join(runErr, readErr)
	}
}
