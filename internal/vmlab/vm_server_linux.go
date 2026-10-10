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
)

// VMServerOptions selects only an owned guest and source checkout. The lane never
// uses the shared development database or binds its administrative listener.
type VMServerOptions struct{ Repository, CacheDir, WorkDir string }

// VMServerResult contains no credentials, database contents or enrollment secret.
type VMServerResult struct {
	ImageID               string                   `json:"image_id"`
	ImageSHA256           string                   `json:"image_sha256"`
	SourceSHA256          string                   `json:"source_snapshot_sha256"`
	GuestOS               []string                 `json:"guest_os"`
	Runtime               *vmRuntimeEvidence       `json:"runtime"`
	Builds                []*packaging.BuildResult `json:"builds"`
	SignerFingerprint     string                   `json:"signer_fingerprint"`
	PostgreSQL            string                   `json:"postgresql"`
	RowsSHA256            string                   `json:"owner_device_rows_sha256"`
	ConfigInventorySHA256 string                   `json:"config_inventory_sha256"`
	Steps                 []string                 `json:"steps"`
}

// ServerVM qualifies installation, explicit migration, LOCAL owner bootstrap,
// restart, signed upgrade, PostgreSQL backup/restore and retained-data purge.
// The pending device row is a backup fixture, not enrollment evidence. WebAuthn
// login is deliberately not claimed: the protected RPC must remain unauthorized.
func ServerVM(ctx context.Context, manifest *labv1.ImageManifest, options VMServerOptions) (result *VMServerResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if manifest.Distribution != "ubuntu" || manifest.Version != "24.04" || manifest.Architecture != "amd64" {
		return nil, errors.New("vm server requires Ubuntu 24.04 amd64")
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
	// Never expose the one-use enrollment output to logs or the evidence document.
	bootstrap := "runuser -u lindmd -- /usr/bin/lindmd bootstrap-owner -config /etc/lindm/server.json -username owner"
	output, err := serverGuestCommand(ctx, vm, "local owner bootstrap", bootstrap, nil)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(output, []byte("Enrollment secret (shown once): ")) {
		return nil, errors.New("bootstrap did not issue enrollment")
	}
	rejected, err := vm.runResult(ctx, "sudo -n sh -c "+nativeQuote(bootstrap), nil, 16384, time.Minute)
	if err != nil {
		return nil, err
	}
	if rejected.ExitCode == 0 || bytes.Contains(rejected.Stdout, []byte("Enrollment secret (shown once): ")) {
		return nil, errors.New("local bootstrap was not one-shot")
	}
	if _, err := serverGuestCommand(ctx, vm, "seed backup-only device", "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d lindm", strings.NewReader("INSERT INTO devices(id,state,enrolled_at,hostname) VALUES ('b4077c77-e5e7-4694-9f3d-97289f94c9d8','pending',now(),'backup-fixture');\n")); err != nil {
		return nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "start service", "systemctl enable --now lindmd.service", nil); err != nil {
		return nil, err
	}
	if err := probeServerGuest(ctx, vm); err != nil {
		return nil, err
	}
	result.Steps = append(result.Steps, "local-bootstrap-one-shot", "tls-health-console-auth-options", "protected-rpc-401", "runtime-no-ddl-no-migrator-access")
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
	if err := install("0.1.1"); err != nil {
		return nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "upgrade restart", "systemctl start lindmd-migrate.service && systemctl restart lindmd.service", nil); err != nil {
		return nil, err
	}
	if err := probeServerGuest(ctx, vm); err != nil {
		return nil, err
	}
	after, err := serverRowsDigest(ctx, vm)
	if err != nil {
		return nil, err
	}
	if before != after {
		return nil, errors.New("restart/upgrade changed owner or device rows")
	}
	result.Steps = append(result.Steps, "restart-retained-rows", "signed-upgrade-retained-rows")
	inventory, err := serverGuestCommand(ctx, vm, "backup database and protected files", serverBackupCommand, nil)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(inventory)
	result.ConfigInventorySHA256 = hex.EncodeToString(digest[:])
	if _, err := serverGuestCommand(ctx, vm, "destroy and restore owned database", serverRestoreCommand, nil); err != nil {
		return nil, err
	}
	if err := probeServerGuest(ctx, vm); err != nil {
		return nil, err
	}
	restored, err := serverRowsDigest(ctx, vm)
	if err != nil {
		return nil, err
	}
	if restored != before {
		return nil, errors.New("restored owner/device rows differ")
	}
	result.Steps = append(result.Steps, "pg-dump-config-inventory", "destroy-database", "pg-restore-identical-rows")
	version, err := serverGuestCommand(ctx, vm, "record PostgreSQL version", "runuser -u postgres -- psql -X -At -c 'SHOW server_version'", nil)
	if err != nil {
		return nil, err
	}
	result.PostgreSQL = strings.TrimSpace(string(version))
	if _, err := serverGuestCommand(ctx, vm, "purge retains data", "apt-get -q -y purge lindmd && test ! -e /usr/bin/lindmd && test -f /etc/lindm/server.json && test -f /etc/lindm/server.key && cd /etc/lindm && sha256sum --check --status /var/backups/lindm/config.sha256", nil); err != nil {
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

func serverGuestCommand(ctx context.Context, vm *guestVM, step, command string, input io.Reader) ([]byte, error) {
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
	const query = "SELECT row_to_json(t) FROM (SELECT * FROM principals ORDER BY id) t; SELECT row_to_json(t) FROM (SELECT * FROM local_accounts ORDER BY id) t; SELECT row_to_json(t) FROM (SELECT * FROM devices ORDER BY id) t;"
	rows, err := serverGuestCommand(ctx, vm, "compare owner/device rows", "runuser -u postgres -- psql -X -At -v ON_ERROR_STOP=1 -d lindm", strings.NewReader(query))
	if err != nil {
		return "", err
	}
	if !bytes.Contains(rows, []byte("backup-fixture")) || !bytes.Contains(rows, []byte("owner")) {
		return "", errors.New("backup comparison requires nonempty owner and device fixtures")
	}
	digest := sha256.Sum256(rows)
	return hex.EncodeToString(digest[:]), nil
}

const serverBackupCommand = `systemctl stop lindmd.service
install -d -m 0700 /var/backups/lindm
runuser -u postgres -- pg_dump -Fc lindm > /var/backups/lindm/database.dump
chmod 0600 /var/backups/lindm/database.dump
tar -C /etc -cpf /var/backups/lindm/config.tar lindm
chmod 0600 /var/backups/lindm/config.tar
cd /etc/lindm
find . -type f -exec sha256sum {} + | sort > /var/backups/lindm/config.sha256
find . -printf '%P %u %g %m\n' | sort > /var/backups/lindm/config.inventory
cat /var/backups/lindm/config.inventory
`

const serverRestoreCommand = `runuser -u postgres -- dropdb lindm
runuser -u postgres -- createdb -O lindm_migrator lindm
cat /var/backups/lindm/database.dump | runuser -u postgres -- pg_restore --exit-on-error --dbname=lindm
rm -rf /etc/lindm
tar -C /etc -xpf /var/backups/lindm/config.tar
cd /etc/lindm
sha256sum --check --status /var/backups/lindm/config.sha256
runuser -u lindmd -- /usr/bin/lindmd check-config -config /etc/lindm/server.json
systemctl start lindmd.service
`
