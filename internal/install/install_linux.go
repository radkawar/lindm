// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package install owns authenticated native installation and upgrade orchestration.
// It never imports ambient database credentials or permits runtime schema mutation.
package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
	"lindm/internal/packaging"
	"lindm/internal/platform"
	"lindm/internal/releasebuild"
	"lindm/internal/serverops"
)

// Options is the installer invocation, not a serialized deployment schema.
type Options struct {
	Bundle, ReleaseKey, ReleaseKeyID, Origin, DeviceOrigin, BackupRecipient string
	DatabaseURL, MigrationURL, TLSCertificate, TLSKey, TLSCA, SetupCodeFile string
	AdminPort, DevicePort                                                   uint
	ExecutionRootRecipients                                                 []string
	CustodyPassphraseFD                                                     int
	Airgap, Rollback                                                        bool
	// OperationsLease is a same-process day2 caller's already-held lease. The
	// caller retains ownership and must close it after Run returns.
	OperationsLease *serverops.UpgradeLease
}

func Run(ctx context.Context, o Options) (err error) {
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" {
		return errors.New("requires root on x86-64 Linux")
	}
	if err := custody.LockSecretMemory(); err != nil {
		return err
	}
	if err := options(&o); err != nil {
		return err
	}
	if err := protectedBundle(o.Bundle); err != nil {
		return err
	}
	// Authenticate all release bytes before any package transaction or persistent write.
	manifest, err := releasebuild.Verify(ctx, o.Bundle, o.ReleaseKey, o.ReleaseKeyID)
	if err != nil {
		return err
	}
	if err := releasebuild.VerifyInstaller(ctx, o.Bundle, o.ReleaseKey, o.ReleaseKeyID); err != nil {
		return err
	}
	release, err := distribution()
	if err != nil {
		return err
	}
	format := release.Packages.Backend.PackageFormat()
	packagePath := ""
	for _, a := range manifest.GetArtifacts() {
		if a.GetProduct() == "lindmd" && a.GetArchitecture() == "amd64" && a.GetFormat() == format {
			if packagePath != "" {
				return errors.New("ambiguous server package")
			}
			packagePath = filepath.Join(o.Bundle, a.GetPath())
		}
	}
	if packagePath == "" {
		return errors.New("signed native server package missing")
	}
	if o.Airgap {
		if err := requireAirgapAddon(o.Bundle, release); err != nil {
			return err
		}
	}
	var disk unix.Statfs_t
	if err := unix.Statfs("/var", &disk); err != nil {
		return err
	}
	if disk.Bavail*uint64(disk.Bsize) < 4<<30 {
		return errors.New("at least 4 GiB free in /var required before installation")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return errors.New("cgroup v2 required")
	}
	// All entry points acquire operations before lifecycle; update apply already
	// holds operations while authenticating its imported release/configuration.
	if o.OperationsLease == nil {
		o.OperationsLease, err = serverops.AcquireUpgradeLease(ctx)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, o.OperationsLease.Close()) }()
	} else if err := o.OperationsLease.Validate(); err != nil {
		return err
	}
	lock, err := os.OpenFile("/run/lindm-install.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another installer holds the lifecycle lock")
	}
	_, stateErr := os.Stat("/etc/lindm/install-state.json")
	upgrade := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return stateErr
	}
	if upgrade {
		data, err := protected("/etc/lindm/install-state.json", true)
		if err != nil {
			return err
		}
		var state installState
		if err := json.Unmarshal(data, &state); err != nil {
			return err
		}
		if state.Pending != nil {
			if err := validateInstallationResume(&state, o, manifest.GetVersion()); err != nil {
				return err
			}
			return continueInstallation(ctx, &o, release, packagePath, &state, nil)
		}
		if err := requireBrowserCompatibleUpgrade(); err != nil {
			return err
		}
		return upgradeRelease(ctx, o, manifest.GetVersion(), packagePath, release)
	}
	return installFresh(ctx, &o, release, packagePath, manifest.GetVersion())
}

func installFresh(ctx context.Context, o *Options, release *platform.Release, packagePath, version string) error {
	if o.Rollback {
		return errors.New("rollback requires a completed managed installation")
	}
	if o.DatabaseURL == "" {
		entries, err := os.ReadDir(release.Server.PostgreSQLDataDirectory)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if len(entries) != 0 {
			return errors.New("unmanaged local database directory is not a fresh installation baseline")
		}
	}
	// Validate recipient custody and admit its passphrase before committing the
	// input binding. Invalid initial inputs must not strand a pending journal.
	rootCustody, err := newAuthorityCustody(ctx, *o)
	if err != nil {
		return err
	}
	defer rootCustody.clear()
	state, err := beginInstallation(*o, version)
	if err != nil {
		return err
	}
	return continueInstallation(ctx, o, release, packagePath, state, rootCustody)
}

func continueInstallation(ctx context.Context, o *Options, release *platform.Release, packagePath string, state *installState, rootCustody *authorityCustody) error {
	if !state.Pending.IdentityReady {
		if err := resetUnpublishedIdentity(state); err != nil {
			return err
		}
		if rootCustody == nil {
			var err error
			rootCustody, err = newAuthorityCustody(ctx, *o)
			if err != nil {
				return err
			}
			defer rootCustody.clear()
		}
	}
	if err := installDependencies(ctx, *o, release); err != nil {
		return err
	}
	if err := verifyNativePackage(ctx, packagePath, release, o.Bundle); err != nil {
		return err
	}
	if err := authorizeInstallationPackage(ctx, packagePath, release, state.Pending.Version); err != nil {
		return err
	}
	if err := provision(ctx, *o, release, rootCustody, state); err != nil {
		return err
	}
	if err := databasePreflight(ctx, release); err != nil {
		return err
	}
	if _, err := command(ctx, nil, "systemctl", "start", "lindmd-migrate.service"); err != nil {
		return err
	}
	if err := restrictMetadata(ctx); err != nil {
		return err
	}
	if err := issueSetup(ctx); err != nil {
		return err
	}
	if err := checkRuntimeConfig(ctx); err != nil {
		return err
	}
	if _, err := command(ctx, nil, "systemctl", "enable", "--now", "lindmd.service", "lindmd-backup.timer", "lindmd-release-check.timer"); err != nil {
		return err
	}
	if err := ready(ctx, *o); err != nil {
		return err
	}
	state.Version = state.Pending.Version
	state.Pending = nil
	if err := writeInstallationState(state); err != nil {
		return err
	}
	return displaySetup(*o)
}

func options(o *Options) error {
	var err error
	o.Bundle, err = filepath.Abs(o.Bundle)
	if err != nil {
		return err
	}
	if o.Origin == "" || o.BackupRecipient == "" || o.ReleaseKey == "" || o.ReleaseKeyID == "" {
		return errors.New("origin, backup-recipient-file and independent release-key-file/key-id required")
	}
	if err := publicOrigins(o); err != nil {
		return err
	}
	if (o.DatabaseURL == "") != (o.MigrationURL == "") {
		return errors.New("external database requires separate runtime and migrator URL files")
	}
	if o.DatabaseURL != "" && (!filepath.IsAbs(o.DatabaseURL) || !filepath.IsAbs(o.MigrationURL)) {
		return errors.New("database-url accepts only an absolute protected file path, never a secret URL")
	}
	if (o.TLSCertificate == "") != (o.TLSKey == "") {
		return errors.New("bring-own TLS requires certificate and protected key together")
	}
	if (o.TLSKey != "") != (o.TLSCA != "") {
		return errors.New("bring-own TLS requires its independently approved root file; generated TLS does not accept an unused CA override")
	}
	for _, item := range []struct {
		path   string
		secret bool
	}{{o.ReleaseKey, false}, {o.BackupRecipient, false}, {o.DatabaseURL, true}, {o.MigrationURL, true}, {o.TLSCertificate, false}, {o.TLSKey, true}, {o.TLSCA, false}} {
		if item.path != "" {
			data, err := protected(item.path, item.secret)
			if item.secret {
				clear(data)
			}
			if err != nil {
				return err
			}
		}
	}
	recipient, err := protected(o.BackupRecipient, false)
	if err != nil {
		return err
	}
	if _, err := age.ParseX25519Recipient(strings.TrimSpace(string(recipient))); err != nil {
		return errors.New("backup recipient must be an age X25519 public recipient, not a private identity")
	}
	return nil
}

func publicOrigins(o *Options) error {
	var parsed [2]*url.URL
	for i, origin := range []string{o.Origin, o.DeviceOrigin} {
		if origin == "" {
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("public origins must be HTTPS origins without credentials, path or query")
		}
		if port := u.Port(); port != "" {
			value, err := strconv.ParseUint(port, 10, 16)
			if err != nil || value == 0 {
				return errors.New("invalid public HTTPS port")
			}
		}
		u.Path = ""
		u.RawPath = ""
		parsed[i] = u
	}
	if parsed[0] == nil {
		return errors.New("console HTTPS origin required")
	}
	warnConsoleDNSRequirement(parsed[0].Hostname(), os.Stderr)
	if o.AdminPort < 1024 || o.AdminPort > 65535 || o.DevicePort < 1024 || o.DevicePort > 65535 || o.AdminPort == o.DevicePort {
		return errors.New("distinct unprivileged listener ports required")
	}
	if parsed[0].Port() == "" {
		parsed[0].Host = net.JoinHostPort(parsed[0].Hostname(), strconv.FormatUint(uint64(o.AdminPort), 10))
	}
	o.Origin = parsed[0].String()
	if parsed[1] == nil {
		parsed[1] = &url.URL{Scheme: "https", Host: net.JoinHostPort(parsed[0].Hostname(), strconv.FormatUint(uint64(o.DevicePort), 10))}
	}
	o.DeviceOrigin = parsed[1].String()
	return nil
}

func verifyNativePackage(ctx context.Context, path string, release *platform.Release, bundle string) (err error) {
	if release.Packages.Backend.PackageDB() != platform.PackageDBRPM {
		return nil
	} // DEBs are authenticated by the signed release and APT repository.
	armor := filepath.Join(bundle, "agent-repository", "package-signing.asc")
	db, err := os.MkdirTemp("/var/lib", "lindm-rpm-trust-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(db)) }()
	fingerprint, err := protected(filepath.Join(bundle, "native-package.fingerprint"), false)
	if err != nil {
		return err
	}
	return packaging.VerifyRPMSignature(ctx, db, path, armor, string(fingerprint))
}

func distribution() (*platform.Release, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = strings.Trim(v, "\"'")
		}
	}
	release := platform.Identify(platform.OSRelease{ID: values["ID"], VersionID: values["VERSION_ID"], VariantID: values["VARIANT_ID"]})
	if err := release.LabLaneOn(platform.LaneDeploy, runtime.GOARCH); err != nil {
		return nil, err
	}
	return release, nil
}

func installPackage(ctx context.Context, path string, release *platform.Release, rollback bool) error {
	if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
		_, err := command(ctx, nil, "dpkg", "--install", path)
		return err
	}
	// These immutable bytes already passed pinned DSSE and isolated native
	// signature verification. Skip only the redundant host-global keyring check
	// for this single RPM; never skip payload digests or vendor DNF verification.
	args := []string{"--upgrade", "--nosignature"}
	if rollback {
		args = append(args, "--oldpackage")
	}
	_, err := command(ctx, nil, "rpm", append(args, path)...)
	return err
}

func displaySetup(o Options) (err error) {
	// Root-only retention permits a browser ceremony to resume after interruption.
	data, err := protected("/var/lib/lindmd-operations/setup/code", true)
	if err != nil {
		return err
	}
	defer clear(data)
	if o.SetupCodeFile != "" {
		if !filepath.IsAbs(o.SetupCodeFile) {
			return errors.New("setup-code-file must be absolute")
		}
		if _, err := protected(filepath.Join(filepath.Dir(o.SetupCodeFile), ".unused"), false); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := newFile(o.SetupCodeFile, data, 0, 0, 0600); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(os.Stdout, "Console:", o.Origin); err != nil {
			return err
		}
		if err := printConsoleTrust(os.Stdout); err != nil {
			return err
		}
		return printCustody(os.Stdout)
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return errors.New("no private terminal; setup code retained in /var/lib/lindmd-operations/setup/code; use --setup-code-file for automated installation")
	}
	defer func() { err = errors.Join(err, tty.Close()) }()
	if err := printConsoleTrust(tty); err != nil {
		return err
	}
	if err := printCustody(tty); err != nil {
		return err
	}
	_, err = fmt.Fprintf(tty, "Console: %s\nSetup code: %s", o.Origin, data)
	return err
}
