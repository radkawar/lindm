// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"lindm/internal/custody"
	"lindm/internal/install"
	"lindm/internal/serverops"
)

func runOperations(ctx context.Context, args []string) error {
	command := args[0]
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if command == "restore" && len(args) > 1 && args[1] == "checkpoint-sign" {
		return runCheckpointSign(ctx, args[2:])
	}
	if command == "update" {
		return runServerUpdate(ctx, args[1:])
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "protected protobuf JSON server configuration")
	recipient := flags.String("recipient-file", "", "operator age public recipient file")
	identity := flags.String("identity-file", "", "offline passphrase-encrypted operator age identity file")
	identityFD := flags.Int("identity-passphrase-fd", -1, "owner-private anonymous passphrase pipe; creation requires confirmation")
	outputDirectory := flags.String("output-dir", "", "existing root-only backup directory")
	output := flags.String("output", "", "new root-only output file")
	archive := flags.String("archive", "", "earlier encrypted backup archive")
	securityArchive := flags.String("security-archive", "", "independently retained authoritative fenced encrypted checkpoint archive")
	checkpoint := flags.String("security-checkpoint", "", "offline root-quorum signed checkpoint envelope")
	update := flags.String("execution-update", "", "strict UpdateExecutionTrustRequest protobuf JSON with newer quorum recovery epoch")
	root := flags.String("root-file", "", "independently authenticated public execution root")
	fenced := flags.Bool("confirm-fenced", false, "all admin/device ingress and replicas are externally fenced")
	reason := flags.String("reason", "", "operator explanation for checkpoint acceptance")
	if err := flags.Parse(args[1:]); err != nil {
		return errors.New("operations: invalid_arguments")
	}
	if flags.NArg() != 0 {
		return errors.New("operations: positional_arguments_rejected")
	}
	switch command {
	case "custody-status":
		if *configPath == "" {
			return errors.New("custody-status requires -config")
		}
		health, err := serverops.CustodyStatus(*configPath)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(health)
	case "backup":
		if *configPath == "" || *recipient == "" || *outputDirectory == "" {
			return errors.New("backup requires -config, -recipient-file and -output-dir")
		}
		path, err := serverops.Backup(ctx, serverops.BackupOptions{Config: *configPath, RecipientFile: *recipient, OutputDirectory: *outputDirectory, ConfirmFenced: *fenced})
		if err != nil {
			return err
		}
		_, err = io.WriteString(os.Stdout, path+"\n")
		return err
	case "backup-keygen":
		if *identity == "" || *recipient == "" {
			return errors.New("backup-keygen requires offline -identity-file and -recipient-file outputs")
		}
		if err := custody.LockSecretMemory(); err != nil {
			return err
		}
		passphrase, err := custody.ReadPassphraseFD(ctx, *identityFD, true)
		if err != nil {
			return err
		}
		defer clear(passphrase)
		return serverops.GenerateBackupKey(ctx, *identity, *recipient, passphrase)
	case "restore-drill":
		if *archive == "" || *identity == "" {
			return errors.New("restore-drill requires -archive and -identity-file")
		}
		if err := custody.LockSecretMemory(); err != nil {
			return err
		}
		passphrase, err := custody.ReadPassphraseFD(ctx, *identityFD, false)
		if err != nil {
			return err
		}
		defer clear(passphrase)
		result, err := serverops.RestoreDrill(ctx, *archive, *identity, passphrase)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "restore":
		if *configPath == "" || *archive == "" || *identity == "" || *securityArchive == "" || *checkpoint == "" || *update == "" || *root == "" || *reason == "" || !*fenced {
			return errors.New("restore requires fresh migrator -config, -archive, -security-archive, -security-checkpoint, -execution-update, -root-file, -identity-file, -reason and -confirm-fenced")
		}
		if err := custody.LockSecretMemory(); err != nil {
			return err
		}
		passphrase, err := custody.ReadPassphraseFD(ctx, *identityFD, false)
		if err != nil {
			return err
		}
		defer clear(passphrase)
		result, err := serverops.Restore(ctx, serverops.RestoreOptions{Config: *configPath, Archive: *archive, SecurityArchive: *securityArchive, SecurityCheckpoint: *checkpoint, ExecutionUpdate: *update, IdentityFile: *identity, IdentityPassphrase: passphrase, RootFile: *root, ConfirmFenced: *fenced, Reason: *reason})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "support":
		if *configPath == "" || *output == "" {
			return errors.New("support requires -config and new -output file")
		}
		return serverops.Support(ctx, *configPath, *output)
	default:
		return errors.New("operations: unknown_command")
	}
}

func runCheckpointSign(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("restore checkpoint-sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	archive := flags.String("archive", "", "earlier backup archive")
	securityArchive := flags.String("security-archive", "", "complete authoritative fenced snapshot")
	identity := flags.String("identity-file", "", "offline operator decryption identity")
	identityFD := flags.Int("identity-passphrase-fd", -1, "owner-private anonymous pipe for operator identity passphrase")
	custodyExport := flags.String("custody-export-file", "", "off-host passphrase-encrypted generated custodian export")
	custodyFD := flags.Int("custody-passphrase-fd", -1, "owner-private anonymous pipe for custody export passphrase")
	custodianIdentity := flags.String("custodian-identity-file", "", "external custodian's passphrase-encrypted standard age identity")
	custodianFD := flags.Int("custodian-identity-passphrase-fd", -1, "owner-private anonymous pipe for external custodian identity passphrase")
	var encryptedKeys []string
	flags.Func("key-custody", "encrypted root-key age object; repeat for externally supplied custodians or rotated keys", func(path string) error { encryptedKeys = append(encryptedKeys, path); return nil })
	root := flags.String("root-file", "", "independently authenticated public execution root")
	output := flags.String("output", "", "new signed checkpoint output")
	epoch := flags.Uint64("recovery-epoch", 0, "new root-quorum approved recovery epoch")
	fenced := flags.Bool("confirm-fenced", false, "attest snapshot completeness through the explicit ingress fence")
	if err := flags.Parse(args); err != nil {
		return errors.New("operations: invalid_checkpoint_arguments")
	}
	if flags.NArg() != 0 || *archive == "" || *securityArchive == "" || *identity == "" || *root == "" || *output == "" || *epoch == 0 || (*custodyExport == "" && *custodianIdentity == "") || !*fenced {
		return errors.New("operations: complete_fenced_checkpoint_arguments_required")
	}
	if err := custody.LockSecretMemory(); err != nil {
		return err
	}
	identityPassphrase, err := custody.ReadPassphraseFD(ctx, *identityFD, false)
	if err != nil {
		return err
	}
	defer clear(identityPassphrase)
	options := serverops.CustodySigningOptions{ExportFile: *custodyExport, IdentityFile: *custodianIdentity, KeyFiles: encryptedKeys}
	if *custodyExport != "" {
		options.Passphrase, err = custody.ReadPassphraseFD(ctx, *custodyFD, false)
		if err != nil {
			return err
		}
		defer clear(options.Passphrase)
	}
	if *custodianIdentity != "" {
		options.IdentityPassphrase, err = custody.ReadPassphraseFD(ctx, *custodianFD, false)
		if err != nil {
			return err
		}
		defer clear(options.IdentityPassphrase)
	}
	return serverops.SignCheckpoint(ctx, serverops.CheckpointOptions{Archive: *archive, SecurityArchive: *securityArchive, IdentityFile: *identity, IdentityPassphrase: identityPassphrase, RootFile: *root, Output: *output, Custody: options, RecoveryEpoch: *epoch, ConfirmFenced: *fenced})
}

func runServerUpdate(ctx context.Context, args []string) (err error) {
	if len(args) == 0 {
		return errors.New("update requires import, check or apply")
	}
	flags := flag.NewFlagSet("update "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundle := flags.String("bundle", "", "private signed release export directory")
	key := flags.String("release-key-file", "", "independently authenticated release attestation public key")
	keyID := flags.String("release-key-id", "", "independently pinned release public key SPKI SHA256")
	if err := flags.Parse(args[1:]); err != nil {
		return errors.New("operations: invalid_update_arguments")
	}
	if flags.NArg() != 0 {
		return errors.New("operations: positional_arguments_rejected")
	}
	switch args[0] {
	case "import":
		if *bundle == "" || *key == "" || *keyID == "" {
			return errors.New("update import requires -bundle, -release-key-file and -release-key-id")
		}
		health, err := serverops.ImportRelease(ctx, *bundle, *key, *keyID)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(health)
	case "check":
		health, err := serverops.CheckRelease(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(health)
	case "apply":
		lease, err := serverops.AcquireUpgradeLease(ctx)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, lease.Close()) }()
		directory, publicKey, id, err := lease.ImportedRelease(ctx)
		if err != nil {
			return err
		}
		document, cleanup, err := serverops.StageRuntimeDatabaseConfig("/etc/lindm/server.json")
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, cleanup()) }()
		cfg := document.Proto
		return install.Run(ctx, install.Options{Bundle: directory, ReleaseKey: publicKey, ReleaseKeyID: id, Origin: cfg.GetPublicUrl(), DeviceOrigin: cfg.GetDevicePublicUrl(), BackupRecipient: "/etc/lindm/backup-recipient", AdminPort: uint(cfg.GetAdminListener().GetPort()), DevicePort: uint(cfg.GetDeviceListener().GetPort()), Airgap: true, OperationsLease: lease})
	default:
		return errors.New("operations: unknown_update_command")
	}
}
