// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"lindm/db"
	"lindm/internal/platform"
	"lindm/internal/serverops"
)

type installState struct {
	// Version is the last release that passed verified runtime readiness.
	Version, Origin, DeviceOrigin, TLSCA string
	// AttemptedVersion is authenticated before native mutation; InstalledVersion
	// checkpoints the native package database independently of runtime readiness.
	AttemptedVersion, InstalledVersion string
	LocalDatabase                      bool
	Pending                            *installationProgress
}

func upgradeRelease(ctx context.Context, o Options, version, packagePath string, release *platform.Release) (err error) {
	if err := verifyNativePackage(ctx, packagePath, release, o.Bundle); err != nil {
		return err
	}
	lease := o.OperationsLease
	if lease == nil {
		return errors.New("upgrade requires the held operations lease")
	}
	data, err := protected("/etc/lindm/install-state.json", true)
	if err != nil {
		return err
	}
	var state installState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	installedVersion, err := nativeInstalledVersion(ctx, release)
	if err != nil {
		return err
	}
	if err := checkUpgradeVersion(&state, installedVersion, version, o.Rollback); err != nil {
		return err
	}
	if o.Origin != state.Origin || o.DeviceOrigin != state.DeviceOrigin {
		return errors.New("upgrade cannot change deployment public origins")
	}
	tmp, err := os.MkdirTemp("/var/lib", "lindm-upgrade-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(tmp)) }()
	if err := os.Chmod(tmp, 0755); err != nil {
		return err
	}
	if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
		if _, err := command(ctx, nil, "dpkg-deb", "--extract", packagePath, tmp); err != nil {
			return err
		}
	} else {
		if _, err := command(ctx, nil, "/bin/sh", "-c", `set -eu; cd "$2"; rpm2cpio "$1" | cpio --extract --make-directories --no-absolute-filenames`, "extract", packagePath, tmp); err != nil {
			return err
		}
	}
	binary := filepath.Join(tmp, "usr/bin/lindmd")
	if err := integrationCredentialPreflight(ctx, binary); err != nil {
		return err
	}
	preflight, err := command(ctx, nil, binary, "schema-check", "-config", "/etc/lindm/migrate/server.json")
	if err != nil {
		return err
	}
	var policy db.SchemaStatus
	if err := json.Unmarshal(preflight, &policy); err != nil {
		return errors.New("new binary returned invalid migration preflight")
	}
	if !policy.Compatible && len(policy.Pending) == 0 {
		return errors.New("database is incompatible with this release")
	}
	for _, pending := range policy.Pending {
		if pending <= policy.Current {
			return errors.New("migration history contains a gap; upgrade refused")
		}
	}
	if len(policy.Pending) > 0 && policy.Current > policy.Target {
		return errors.New("database is newer than migration target")
	}
	if err := databasePreflight(ctx); err != nil {
		return err
	}
	if o.Rollback && (!policy.Compatible || len(policy.Pending) != 0 || policy.Target < policy.Floor) {
		return errors.New("rollback exceeds trusted schema compatibility floor; fenced backup restore required")
	}
	if !policy.Online {
		if _, err := command(ctx, nil, "systemctl", "stop", "lindmd.service"); err != nil {
			return err
		}
	}
	if err := lease.RestartTimersOnClose(); err != nil {
		return err
	}
	if _, err := command(ctx, nil, "systemctl", "stop", "lindmd-backup.timer", "lindmd-release-check.timer", "lindmd-release-check.service"); err != nil {
		return err
	}
	if err := prepareNativeIntegrationUpgrade(ctx, binary); err != nil {
		return err
	}
	if err := lease.Backup(ctx, serverops.BackupOptions{Config: "/etc/lindm/server.json", RecipientFile: "/etc/lindm/backup-recipient", OutputDirectory: "/var/backups/lindm"}); err != nil {
		return fmt.Errorf("upgrade encrypted backup prerequisite: %w", err)
	}
	if err := directory("/var/lib/lindmd-operations/rollback", 0, 0, 0755); err != nil {
		return err
	}
	previousDir := filepath.Join("/var/lib/lindmd-operations/rollback", installedVersion)
	if err := directory(previousDir, 0, 0, 0755); err != nil {
		return err
	}
	previousBinary := filepath.Join(previousDir, "lindmd")
	if err := copyFileNew("/usr/bin/lindmd", previousBinary, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := authorizeUpgrade(version); err != nil {
		return err
	}
	defer func() {
		removeErr := os.Remove("/run/lindm-install/authorized-version")
		if !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	state.AttemptedVersion = version
	state.InstalledVersion = installedVersion
	if err := writeInstallationState(&state); err != nil {
		return err
	}
	if err := activateUpgrade(ctx, &o, &state, packagePath, release, previousBinary, policy.Online); err != nil {
		return err
	}
	return finishUpgrade(ctx, lease, &state, version)
}

// A version-bound, one-use authorization is consumed by the package pre-hook.
func authorizeUpgrade(version string) error {
	if err := directory("/run/lindm-install", 0, 0, 0700); err != nil {
		return err
	}
	authorization, err := packageAuthorization(version)
	if err != nil {
		return err
	}
	return newFile("/run/lindm-install/authorized-version", authorization, 0, 0, 0600)
}

func checkUpgradeVersion(state *installState, installedVersion, version string, rollback bool) error {
	if !semver.IsValid("v"+state.Version) || !semver.IsValid("v"+installedVersion) || !semver.IsValid("v"+version) {
		return errors.New("invalid release version")
	}
	comparison := semver.Compare("v"+version, "v"+installedVersion)
	if comparison == 0 || (comparison < 0 && !rollback) || (comparison > 0 && rollback) {
		return errors.New("upgrade requires a newer release; authenticated older rollback requires explicit --rollback and compatible schema")
	}
	return nil
}

// The last-ready record is not evidence of the currently installed package:
// unpacking or configuring the next release can fail before runtime readiness.
func nativeInstalledVersion(ctx context.Context, release *platform.Release) (string, error) {
	var data []byte
	var err error
	if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
		data, err = command(ctx, nil, "dpkg-query", "--show", "--showformat=${Version}", "lindmd")
	} else {
		data, err = command(ctx, nil, "rpm", "--query", "--queryformat", "%{VERSION}", "lindmd")
	}
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(data))
	if !semver.IsValid("v" + version) {
		return "", errors.New("native server package returned invalid release version")
	}
	return version, nil
}

// activateUpgrade preserves native authorization in its caller while migrations
// and both old/new runtime readiness gates run.
func activateUpgrade(ctx context.Context, o *Options, state *installState, packagePath string, release *platform.Release, previousBinary string, online bool) error {
	installErr := installPackage(ctx, packagePath, release, o.Rollback)
	// Native hooks may fail after replacing the payload. Record the observed
	// package even on an error, without promoting it to the last-ready release.
	installedVersion, err := nativeInstalledVersion(ctx, release)
	if err != nil {
		return errors.Join(installErr, err)
	}
	state.InstalledVersion = installedVersion
	if err := writeInstallationState(state); err != nil {
		return errors.Join(installErr, err)
	}
	if installErr != nil {
		return installErr
	}
	if !o.Rollback {
		if _, err := command(ctx, nil, "systemctl", "start", "lindmd-migrate.service"); err != nil {
			return fmt.Errorf("migration failed; service state retained, inspect private journal; never run automatic Down: %w", err)
		}
	}
	if err := restrictMetadata(ctx); err != nil {
		return err
	}
	if online {
		if err := ready(ctx, *o); err != nil {
			return fmt.Errorf("old runtime no longer ready after online migration: %w", err)
		}
	}
	if err := checkRuntimeConfig(ctx); err != nil {
		return err
	}
	if _, err := command(ctx, nil, "systemctl", "restart", "lindmd.service"); err != nil {
		return err
	}
	if err := ready(ctx, *o); err != nil {
		// Only a trusted declared-compatible schema permits binary rollback.
		previousStatus, checkErr := command(ctx, nil, previousBinary, "schema-check", "-config", "/etc/lindm/migrate/server.json")
		var previousPolicy db.SchemaStatus
		if checkErr == nil && json.Unmarshal(previousStatus, &previousPolicy) == nil && previousPolicy.Compatible && len(previousPolicy.Pending) == 0 {
			return errors.Join(err, errors.New("previous binary accepts current schema; use its authenticated signed bundle with --rollback; never run schema Down"))
		}
		return errors.Join(err, errors.New("previous binary is incompatible; fenced encrypted backup restore required"))
	}
	return nil
}

func finishUpgrade(ctx context.Context, lease *serverops.UpgradeLease, state *installState, version string) error {
	state.Version = version
	if err := writeInstallationState(state); err != nil {
		return err
	}
	if _, statErr := os.Stat("/var/lib/lindmd-operations/release-feed-state.json"); statErr == nil {
		if err := lease.CheckRelease(ctx); err != nil {
			return fmt.Errorf("installed release-feed check failed: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	fmt.Println("Console:", state.Origin)
	return nil
}

func ready(ctx context.Context, o Options) error {
	ca, err := os.ReadFile("/etc/lindm/console-ca.crt")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("invalid console TLS trust")
	}
	u, err := url.Parse(o.Origin)
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname()}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(o.AdminPort), 10)))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.Origin+"/readyz", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			closeErr := resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent && copyErr == nil && closeErr == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("verified HTTPS readiness deadline exceeded")
		case <-tick.C:
		}
	}
}
