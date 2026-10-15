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

// Restore output follows the same off-server ciphertext-only custody as backup
// output. Never discard a real refusal or print credential-bearing diagnostics.
func executeDeployRestore(ctx context.Context, guest *guestVM, options VMDeployOptions, command string, input io.Reader) (resultErr error) {
	const step = "restore encrypted backup into fresh VM"
	if observer := guest.serverCommandObserver; observer != nil {
		started := time.Now().UTC()
		defer func() { observer(step, started, time.Now().UTC(), resultErr == nil) }()
	}
	output, err := guest.runResult(ctx, "sudo -n env LC_ALL=C DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), input, deployInstallerDiagnosticLimit, 10*time.Minute)
	defer clear(output.Stdout)
	defer clear(output.Stderr)
	if err == nil && output.ExitCode == 0 {
		return nil
	}
	captureErr := writeDeployInstallerDiagnostics(options.CustodyEscrowRecipientFile, options.EvidenceDirectory, "restore-command", output.Stdout, output.Stderr)
	if err != nil {
		return errors.Join(fmt.Errorf("%s: %w", step, err), captureErr)
	}
	return errors.Join(fmt.Errorf("%s: guest exit %d (stdout %d bytes, stderr %d bytes)", step, output.ExitCode, len(output.Stdout), len(output.Stderr)), captureErr)
}

const deployServiceJournalCommand = `sudo -n sh -c '
env LC_ALL=C journalctl --no-pager --output=cat --lines=200 --unit=lindmd.service --unit=lindmd-migrate.service --unit=lindm-postgresql.service
journal_status=$?
env LC_ALL=C journalctl --no-pager --output=json --lines=50 --unit=lindm-postgresql.service
env LC_ALL=C journalctl --no-pager --output=cat --lines=200 _TRANSPORT=audit
stat -c "%n uid=%u gid=%g mode=%a context=%C" /var/lib/pgsql /var/lib/pgsql/lindm /var/lib/pgsql/lindm/postgresql.conf /var/lib/pgsql/lindm/lindm.conf /etc/lindm /etc/lindm/postgresql /etc/lindm/postgresql/server.crt /etc/lindm/postgresql/server.key
stat -L -c "%n uid=%u gid=%g mode=%a context=%C" /usr/bin/postgres /usr/bin/postmaster
systemctl cat postgresql.service
systemctl cat lindm-postgresql.service
systemctl show lindm-postgresql.service --property=MainPID --property=NoNewPrivileges --property=SELinuxContext --property=ExecStart --property=ProtectSystem --property=ProtectHome --property=PrivateTmp
pid=$(systemctl show lindm-postgresql.service --property=MainPID --value)
case "$pid" in
  ""|*[!0-9]*|0) ;;
  *)
    cat "/proc/$pid/attr/current" "/proc/$pid/status" "/proc/$pid/mountinfo"
    ;;
esac
logs=0
for logfile in /var/lib/pgsql/lindm/log/*.log /var/lib/postgresql/lindm/log/*.log; do
  if [ -f "$logfile" ] && [ ! -L "$logfile" ]; then
    printf "%s\n" "$logfile"
    dd if="$logfile" bs=32768 count=1 iflag=nofollow status=none
    logs=$((logs + 1))
    if [ "$logs" -ge 8 ]; then break; fi
  fi
done
if command -v getenforce; then getenforce; fi
if command -v ausearch; then ausearch -m AVC,USER_AVC -ts boot --raw; fi
exit "$journal_status"
'`

func captureDeployServiceJournal(ctx context.Context, guest *guestVM, options VMDeployOptions, label string) error {
	journal, err := guest.runResult(ctx, deployServiceJournalCommand, nil, deployInstallerDiagnosticLimit, time.Minute)
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
