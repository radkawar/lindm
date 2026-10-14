// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
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
)

// VMServerOptions selects only an owned guest and source checkout. The lane never
// uses the shared development database or binds its administrative listener.
type VMServerOptions struct{ Repository, CacheDir, WorkDir string }

// VMServerResult contains no credentials, database contents or enrollment secret.
type VMServerResult struct {
	ImageID           string                   `json:"image_id"`
	ImageSHA256       string                   `json:"image_sha256"`
	SourceSHA256      string                   `json:"source_snapshot_sha256"`
	GuestOS           []string                 `json:"guest_os"`
	Runtime           *vmRuntimeEvidence       `json:"runtime"`
	Builds            []*packaging.BuildResult `json:"builds"`
	SignerFingerprint string                   `json:"signer_fingerprint"`
	PostgreSQL        string                   `json:"postgresql"`
	RowsSHA256        string                   `json:"owner_device_rows_sha256"`
	Steps             []string                 `json:"steps"`
}

// ServerVM qualifies low-level native package/configuration boundaries,
// explicit migration, protected setup authority, confinement, restart, direct
// upgrade refusal and retained-data purge. It is not browser/login/enrollment
// or encrypted recovery proof; DeployVM owns the complete real workflow.
func ServerVM(ctx context.Context, manifest *labv1.ImageManifest, options VMServerOptions) (result *VMServerResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if err := manifestRelease(manifest).LabLane(platform.LaneServer); err != nil {
		return nil, err
	}
	if manifest.Architecture != "amd64" {
		return nil, errors.New("vm server requires an amd64 manifest")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	vm, verified, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, false, &VMHardwareOptions{AllowNetwork: true})
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, vm.close())
		if err != nil {
			result = nil
		}
	}()
	result = &VMServerResult{ImageID: manifest.Id, ImageSHA256: verified.SHA256}
	source := filepath.Join(vm.dir, "source")
	result.SourceSHA256, err = snapshotServerSource(ctx, options.Repository, source)
	if err != nil {
		return nil, err
	}
	options.Repository = source
	signer, err := packaging.GenerateDevelopmentSigner(ctx, vm.dir)
	if err != nil {
		return nil, err
	}
	result.SignerFingerprint = signer.Fingerprint
	var artifacts []packaging.Artifact
	for _, version := range []string{"0.1.0", "0.1.1"} {
		dir := filepath.Join(vm.dir, version)
		if err := os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
		build, err := packaging.BuildServerSource(ctx, packaging.SourceRequest{Repository: options.Repository, Revision: "server-lab", BuildRequest: packaging.BuildRequest{Version: version, TargetArchitecture: manifest.Architecture, OutputDir: dir, Formats: []packaging.Format{packaging.FormatDEB}, Signer: *signer}})
		if err != nil {
			return nil, err
		}
		result.Builds = append(result.Builds, build)
		artifacts = append(artifacts, build.Artifacts[0])
	}
	// A second clean staging/build of the same source/version must be byte-identical.
	repeatDir := filepath.Join(vm.dir, "repeat")
	if err := os.Mkdir(repeatDir, 0700); err != nil {
		return nil, err
	}
	repeat, err := packaging.BuildServerSource(ctx, packaging.SourceRequest{Repository: options.Repository, Revision: "server-lab", BuildRequest: packaging.BuildRequest{Version: "0.1.0", TargetArchitecture: manifest.Architecture, OutputDir: repeatDir, Formats: []packaging.Format{packaging.FormatDEB}, Signer: *signer}})
	if err != nil {
		return nil, err
	}
	if repeat.Artifacts[0].SHA256 != artifacts[0].SHA256 {
		return nil, fmt.Errorf("server DEB clean builds differ: binaries %s/%s; packages %s/%s", result.Builds[0].BinarySHA256, repeat.BinarySHA256, artifacts[0].SHA256, repeat.Artifacts[0].SHA256)
	}
	result.Steps = append(result.Steps, "reproducible-deb")
	repoDir := filepath.Join(vm.dir, "apt")
	if err := os.Mkdir(repoDir, 0700); err != nil {
		return nil, err
	}
	repo, err := packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: repoDir, DEBs: []string{artifacts[0].Path, artifacts[1].Path}, Signer: *signer})
	if err != nil {
		return nil, err
	}
	if err := vm.connect(ctx); err != nil {
		return nil, err
	}
	result.Runtime, err = vm.runtimeEvidence(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "cloud-init", "cloud-init status --wait", nil); err != nil {
		return nil, err
	}
	host, err := vm.run(ctx, hostTruthCommand, nil, 4096, 15*time.Second)
	if err != nil {
		return nil, err
	}
	result.GuestOS = strings.Split(string(host), "\n")
	if len(result.GuestOS) != 7 || result.GuestOS[0] != manifest.Distribution || result.GuestOS[1] != manifest.Version || result.GuestOS[2] != "x86_64" {
		return nil, errors.New("server guest OS differs from the pinned manifest")
	}
	if err := installServerPostgres(ctx, vm); err != nil {
		return nil, err
	}
	forward, public, err := serverAPT(ctx, vm, repo, artifacts)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, forward.Close(), public.Close()) }()
	install := func(version string) error {
		_, err := serverGuestCommand(ctx, vm, "install signed server", "apt-get -q -y -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false update && apt-get -q -y --no-install-recommends install lindmd="+version+" && test \"$(/usr/bin/lindmd version)\" = "+version, nil)
		return err
	}
	if err := install("0.1.0"); err != nil {
		return nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "installation does not start or migrate", "! systemctl is-active --quiet lindmd.service && test ! -e /etc/lindm/server.json", nil); err != nil {
		return nil, err
	}
	if err := prepareServerGuest(ctx, vm); err != nil {
		return nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "explicit migration", "systemctl start lindmd-migrate.service", nil); err != nil {
		return nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "protect migration metadata", "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d lindm", strings.NewReader(deploylab.RestrictRuntimeMigrationMetadataSQL)); err != nil {
		return nil, err
	}
	result.Steps = append(result.Steps, "signed-install", "explicit-migration")
	if _, err := serverGuestCommand(ctx, vm, "prepare protected setup output directory", "install -d -o root -g root -m 0755 /var/lib/lindmd-operations; install -d -o lindmd-migrate -g lindmd-migrate -m 0700 /var/lib/lindmd-operations/setup", nil); err != nil {
		return nil, err
	}
	// Keep first-run capability out of argv, journals and the evidence document.
	bootstrap := "runuser -u lindmd-migrate -- /usr/bin/lindmd setup-code -config /etc/lindm/migrate/server.json -output /var/lib/lindmd-operations/setup/code"
	if _, err := serverGuestCommand(ctx, vm, "protected first-run code issuance", bootstrap, nil); err != nil {
		return nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "retain setup code under root custody", "chown root:root /var/lib/lindmd-operations/setup/code /var/lib/lindmd-operations/setup", nil); err != nil {
		return nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "private first-run code custody", "test \"$(stat -c %a /var/lib/lindmd-operations/setup/code)\" = 600 && test \"$(stat -c %U /var/lib/lindmd-operations/setup/code)\" = root && test \"$(wc -c < /var/lib/lindmd-operations/setup/code)\" = 44 && ! runuser -u lindmd -- test -r /var/lib/lindmd-operations/setup/code && ! runuser -u lindmd-migrate -- test -r /var/lib/lindmd-operations/setup/code", nil); err != nil {
		return nil, err
	}
	rejected, err := vm.runResult(ctx, "sudo -n sh -c "+nativeQuote(bootstrap), nil, 16384, time.Minute)
	if err != nil {
		return nil, err
	}
	if rejected.ExitCode == 0 {
		return nil, errors.New("setup issuance overwrote an existing code file")
	}
	if _, err := serverGuestCommand(ctx, vm, "start service", "systemctl enable --now lindmd.service", nil); err != nil {
		return nil, err
	}
	if err := probeServerGuest(ctx, vm); err != nil {
		return nil, err
	}
	result.Steps = append(result.Steps, "protected-setup-code-issuance", "tls-health-console-auth-options", "protected-rpc-401", "runtime-no-ddl-no-migrator-access")
	before, err := serverRowsDigest(ctx, vm)
	if err != nil {
		return nil, err
	}
	result.RowsSHA256 = before
	if _, err := serverGuestCommand(ctx, vm, "restart service", "systemctl restart lindmd.service", nil); err != nil {
		return nil, err
	}
	if err := probeServerGuest(ctx, vm); err != nil {
		return nil, err
	}
	rejectedUpgrade, err := vm.runResult(ctx, "sudo -n env LC_ALL=C DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote("apt-get -q -y --no-install-recommends install lindmd=0.1.1"), nil, 1<<20, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	marker := []byte("lindmd upgrade requires the signed bundle installer and encrypted backup.")
	if rejectedUpgrade.ExitCode == 0 || (!bytes.Contains(rejectedUpgrade.Stdout, marker) && !bytes.Contains(rejectedUpgrade.Stderr, marker)) {
		return nil, errors.New("direct native server upgrade did not specifically require signed release installer authorization")
	}
	if _, err := serverGuestCommand(ctx, vm, "rejected upgrade retains old binary", "test \"$(/usr/bin/lindmd version)\" = 0.1.0", nil); err != nil {
		return nil, err
	}
	after, err := serverRowsDigest(ctx, vm)
	if err != nil {
		return nil, err
	}
	if before != after {
		return nil, errors.New("restart or denied native upgrade changed owner/device rows")
	}
	result.Steps = append(result.Steps, "restart-retained-rows", "direct-native-upgrade-denied-without-release-authorization")
	version, err := serverGuestCommand(ctx, vm, "record PostgreSQL version", "runuser -u postgres -- psql -X -At -c 'SHOW server_version'", nil)
	if err != nil {
		return nil, err
	}
	result.PostgreSQL = strings.TrimSpace(string(version))
	if _, err := serverGuestCommand(ctx, vm, "purge retains data", "apt-get -q -y purge lindmd && test ! -e /usr/bin/lindmd && test -f /etc/lindm/server.json && test -f /etc/lindm/server.key", nil); err != nil {
		return nil, err
	}
	retained, err := serverRowsDigest(ctx, vm)
	if err != nil {
		return nil, err
	}
	if retained != before {
		return nil, errors.New("package purge changed retained database")
	}
	result.Steps = append(result.Steps, "purge-retains-config-keys-database")
	return result, nil
}

func serverGuestCommand(ctx context.Context, vm *guestVM, step, command string, input io.Reader) (data []byte, resultErr error) {
	if observer := vm.serverCommandObserver; observer != nil {
		started := time.Now().UTC()
		defer func() { observer(step, started, time.Now().UTC(), resultErr == nil) }()
	}
	output, err := vm.runResult(ctx, "sudo -n env LC_ALL=C DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), input, 1<<20, 10*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", step, err)
	}
	if output.ExitCode != 0 {
		return nil, fmt.Errorf("%s: guest exit %d (stdout %d bytes, stderr %d bytes)", step, output.ExitCode, len(output.Stdout), len(output.Stderr))
	}
	return output.Stdout, nil
}

func serverRowsDigest(ctx context.Context, vm *guestVM) (string, error) {
	const query = "SELECT row_to_json(t) FROM (SELECT * FROM first_run_setup ORDER BY id) t; SELECT row_to_json(t) FROM (SELECT * FROM principals ORDER BY id) t; SELECT row_to_json(t) FROM (SELECT * FROM local_accounts ORDER BY id) t; SELECT row_to_json(t) FROM (SELECT * FROM devices ORDER BY id) t;"
	rows, err := serverGuestCommand(ctx, vm, "compare setup/account/device rows", "runuser -u postgres -- psql -X -At -v ON_ERROR_STOP=1 -d lindm", strings.NewReader(query))
	if err != nil {
		return "", err
	}
	if !bytes.Contains(rows, []byte("backup-fixture")) || !bytes.Contains(rows, []byte("code_hash")) {
		return "", errors.New("backup comparison requires nonempty protected setup and device fixtures")
	}
	digest := sha256.Sum256(rows)
	return hex.EncodeToString(digest[:]), nil
}
