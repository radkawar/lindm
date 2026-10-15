// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const deployInstallerDiagnosticLimit = 1 << 20

// executeDeployInstaller keeps potentially credential-bearing native output in
// locked lab-parent memory. On failure it encrypts the bounded streams directly
// to the off-server lab operator before the caller closes the owned guest. No
// plaintext diagnostic is written, returned, or included in product artifacts.
func executeDeployInstaller(ctx context.Context, guest *guestVM, options VMDeployOptions, destination, command string, input io.Reader) (resultErr error) {
	const step = "execute signed turnkey installer"
	started := time.Now().UTC()
	if observer := guest.serverCommandObserver; observer != nil {
		defer func() { observer(step, started, time.Now().UTC(), resultErr == nil) }()
	}
	output, err := guest.runResult(ctx, "sudo -n env LC_ALL=C DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), input, deployInstallerDiagnosticLimit, 10*time.Minute)
	defer clear(output.Stdout)
	defer clear(output.Stderr)
	if err == nil && output.ExitCode == 0 {
		return nil
	}
	recipient := options.CustodyEscrowRecipientFile
	captureErr := writeDeployInstallerDiagnostics(recipient, options.EvidenceDirectory, filepath.Base(destination), output.Stdout, output.Stderr)
	diagnostic, diagnosticErr := guest.runResult(ctx, "sudo -n sh -eu -c 'chmod 0755 /root/lindm-deploy-input/lab-helper; /root/lindm-deploy-input/lab-helper deploy database-diagnostic'", nil, 64<<10, time.Minute)
	defer clear(diagnostic.Stdout)
	defer clear(diagnostic.Stderr)
	captureErr = errors.Join(captureErr, writeDeployInstallerDiagnostics(recipient, options.EvidenceDirectory, filepath.Base(destination)+"-database", diagnostic.Stdout, diagnostic.Stderr))
	if diagnosticErr != nil || diagnostic.ExitCode != 0 {
		captureErr = errors.Join(captureErr, errors.New("lab database failure observer did not complete"))
	}
	captureErr = errors.Join(captureErr, captureDeployServiceJournal(ctx, guest, options, filepath.Base(destination)+"-journal"))
	if err != nil {
		return errors.Join(fmt.Errorf("%s: %w", step, err), captureErr)
	}
	return errors.Join(fmt.Errorf("%s: guest exit %d (stdout %d bytes, stderr %d bytes)", step, output.ExitCode, len(output.Stdout), len(output.Stderr)), captureErr)
}

// executeDeployBackup retains failed backup output only as off-server custody
// ciphertext, with the same bounded streams and root command as the installer.
func executeDeployBackup(ctx context.Context, guest *guestVM, options VMDeployOptions, name, command string) (path []byte, resultErr error) {
	const step = "create encrypted backup"
	if observer := guest.serverCommandObserver; observer != nil {
		started := time.Now().UTC()
		defer func() { observer(step, started, time.Now().UTC(), resultErr == nil) }()
	}
	output, err := guest.runResult(ctx, "sudo -n env LC_ALL=C DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), nil, deployInstallerDiagnosticLimit, 10*time.Minute)
	defer clear(output.Stderr)
	if err == nil && output.ExitCode == 0 {
		return output.Stdout, nil
	}
	defer clear(output.Stdout)
	captureErr := writeDeployInstallerDiagnostics(options.CustodyEscrowRecipientFile, options.EvidenceDirectory, strings.TrimSuffix(name, ".age")+"-command", output.Stdout, output.Stderr)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%s: %w", step, err), captureErr)
	}
	return nil, errors.Join(fmt.Errorf("%s: guest exit %d (stdout %d bytes, stderr %d bytes)", step, output.ExitCode, len(output.Stdout), len(output.Stderr)), captureErr)
}

func captureDeployServiceJournal(ctx context.Context, guest *guestVM, options VMDeployOptions, label string) error {
	journal, err := guest.runResult(ctx, "sudo -n env LC_ALL=C journalctl --no-pager --output=cat --lines=200 --unit=lindmd.service --unit=lindmd-migrate.service", nil, deployInstallerDiagnosticLimit, time.Minute)
	defer clear(journal.Stdout)
	defer clear(journal.Stderr)
	captureErr := writeDeployInstallerDiagnostics(options.CustodyEscrowRecipientFile, options.EvidenceDirectory, label, journal.Stdout, journal.Stderr)
	if err != nil || journal.ExitCode != 0 {
		captureErr = errors.Join(captureErr, errors.New("lab private service journal observer did not complete"))
	}
	return captureErr
}

func writeDeployInstallerDiagnostics(recipient, directory, label string, stdout, stderr []byte) error {
	if label == "" || label == "." || label != filepath.Base(label) || directory == "" || !filepath.IsAbs(directory) {
		return errors.New("installer diagnostics require a private absolute evidence directory and single path label")
	}
	if len(stdout) > deployInstallerDiagnosticLimit || len(stderr) > deployInstallerDiagnosticLimit {
		return errors.New("installer diagnostic stream exceeds the bounded evidence limit")
	}
	if err := encryptDeployEvidence(recipient, filepath.Join(directory, label+"-stdout.age"), stdout); err != nil {
		return fmt.Errorf("encrypt lab installer stdout: %w", err)
	}
	if err := encryptDeployEvidence(recipient, filepath.Join(directory, label+"-stderr.age"), stderr); err != nil {
		return fmt.Errorf("encrypt lab installer stderr: %w", err)
	}
	return nil
}
