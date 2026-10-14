// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"syscall"

	"lindm/internal/custody"
	"lindm/internal/vmlab"
)

func runDeployOperatorInit(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("deploy operator-init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", ".", "checkout containing maintained lab memory-protection helper")
	directory := flags.String("output", "", "new private OFF-SERVER lab fixture directory")
	recipient := flags.String("escrow-recipient-file", "", "dedicated durable LAB-ONLY operator public age recipient")
	identity := flags.String("lab-escrow-identity-file", "", "protected dedicated LAB-ONLY private escrow identity; never uploaded or bundled")
	record := flags.String("record", "", "new private nonsecret lab-operator-custody-fixture-only evidence")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *directory == "" || *recipient == "" || *identity == "" || *record == "" {
		return errors.New("lab operator initialization requires new off-server output, dedicated escrow public/private inputs and record; never product custody")
	}
	if err := resolvePackagePaths(repository, directory, recipient, identity, record); err != nil {
		return err
	}
	if err := prepareDeployCustodianMemory(ctx, *repository); err != nil {
		return err
	}
	if err := custody.LockSecretMemory(); err != nil {
		return err
	}
	if err := os.Mkdir(*directory, 0700); err != nil {
		return err
	}
	if err := vmlab.InitializeDeployOperator(ctx, *directory, *recipient); err != nil {
		return err
	}
	if err := vmlab.VerifyDeployOperatorEscrow(ctx, *directory, *identity); err != nil {
		return err
	}
	result := map[string]any{"scope": "lab-operator-custody-fixture-only", "lifecycle_qualified": false, "passed": true, "durable_unlock_escrow_reload_verified": true, "independent_human_custodians": false, "encrypted_backup_identity": *directory + "/backup-identity.age", "backup_public_recipient": *directory + "/backup-recipient.txt", "encrypted_unlock_escrow": *directory + "/backup-identity-unlock.age"}
	return writeLabEvidence(stdout, *record, result)
}

func runDeployOperatorVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("deploy operator-verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", ".", "checkout containing maintained lab memory-protection helper")
	directory := flags.String("input", "", "existing encrypted OFF-SERVER operator fixture directory")
	identity := flags.String("lab-escrow-identity-file", "", "dedicated protected LAB-ONLY private escrow identity; never uploaded or bundled")
	record := flags.String("record", "", "new private nonsecret independent-process reload evidence")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *directory == "" || *identity == "" || *record == "" {
		return errors.New("operator verification requires existing encrypted fixture, protected dedicated lab escrow identity and new record")
	}
	if err := resolvePackagePaths(repository, directory, identity, record); err != nil {
		return err
	}
	if err := prepareDeployCustodianMemory(ctx, *repository); err != nil {
		return err
	}
	if err := custody.LockSecretMemory(); err != nil {
		return err
	}
	if err := vmlab.VerifyDeployOperatorEscrow(ctx, *directory, *identity); err != nil {
		return err
	}
	result := map[string]any{"scope": "lab-operator-custody-fixture-only", "lifecycle_qualified": false, "passed": true, "independent_process_unlock_reload_verified": true, "independent_human_custodians": false, "encrypted_fixture_directory": *directory}
	return writeLabEvidence(stdout, *record, result)
}

func readDeployBackupUnlock(ctx context.Context, fd int, escrow, identity string) ([]byte, error) {
	if fd >= 0 {
		if escrow != "" || identity != "" {
			return nil, errors.New("choose either protected passphrase FD or encrypted lab escrow, never both")
		}
		passphrase, readErr := custody.ReadPassphraseFD(ctx, fd, false)
		if err := errors.Join(readErr, syscall.Close(fd)); err != nil {
			clear(passphrase)
			return nil, err
		}
		return passphrase, nil
	}
	if escrow == "" || identity == "" {
		return nil, errors.New("deploy requires protected backup passphrase FD or encrypted unlock escrow plus dedicated lab private escrow identity")
	}
	if err := resolvePackagePaths(&escrow, &identity); err != nil {
		return nil, err
	}
	return vmlab.ReadDeployEscrowPassphrase(ctx, escrow, identity)
}
