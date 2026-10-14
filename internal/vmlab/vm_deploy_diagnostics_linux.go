// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
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
	if err != nil {
		return errors.Join(fmt.Errorf("%s: %w", step, err), captureErr)
	}
	return errors.Join(fmt.Errorf("%s: guest exit %d (stdout %d bytes, stderr %d bytes)", step, output.ExitCode, len(output.Stdout), len(output.Stderr)), captureErr)
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
