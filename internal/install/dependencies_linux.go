// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
	"lindm/internal/platform"
	"lindm/internal/serverdeps"
)

// installDependencies uses normally authenticated, configured distro repositories
// in connected mode. Air-gap mode imports only the signed per-platform closure.
func installDependencies(ctx context.Context, o Options, release *platform.Release) (err error) {
	if release.Server.PostgreSQLModule != "" {
		if o.Airgap {
			return errors.New("RHEL offline installation is not available in this release")
		}
		if err := prepareRHELPostgreSQL(ctx, release, command); err != nil {
			return err
		}
	}
	var cleanup func() error
	if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
		cleanup, err = prepareUbuntuDependencies()
		if err != nil {
			return err
		}
	}
	if cleanup != nil {
		defer func() { err = errors.Join(err, cleanup()) }()
	}
	if !o.Airgap {
		if err := installConnectedDependencies(ctx, release); err != nil {
			return err
		}
		return checkPostgreSQLTools(ctx, release, command)
	}
	name := release.Server.SnapshotName
	pin, err := os.ReadFile(filepath.Join(o.Bundle, name+".digest"))
	if err != nil {
		return err
	}
	cache, err := os.MkdirTemp("/var/cache", "lindm-install-snapshot-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(cache)) }()
	f, err := os.Open(filepath.Join(o.Bundle, name))
	if err != nil {
		return err
	}
	digest := strings.TrimSpace(string(pin))
	err = errors.Join(serverdeps.Import(ctx, cache, digest, f), f.Close())
	if err != nil {
		return err
	}
	manifest, _, err := serverdeps.Load(cache, digest)
	if err != nil {
		return err
	}
	if manifest.GetDistribution() != release.ID || manifest.GetVersion() != release.Version.Value || manifest.GetArchitecture() != "amd64" {
		return errors.New("signed dependency snapshot platform mismatch")
	}
	if err := requiredDependencies(manifest.GetRequestedPackages(), release); err != nil {
		return err
	}
	return serverdeps.Install(ctx, cache, digest)
}

func requireAirgapAddon(bundle string, release *platform.Release) error {
	if release.Server.PostgreSQLModule != "" {
		return errors.New("RHEL offline installation is not available in this release")
	}
	for _, name := range []string{release.Server.SnapshotName, release.Server.SnapshotName + ".digest"} {
		if _, err := os.Stat(filepath.Join(bundle, name)); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("air-gap installation requires authenticated %s; use this platform's signed offline add-on", name)
		} else if err != nil {
			return err
		}
	}
	return nil
}

func installConnectedDependencies(ctx context.Context, release *platform.Release) error {
	switch release.Packages.Backend.PackageDB() {
	case platform.PackageDBDpkg:
		args := make([]string, 0, 16+len(release.Server.RequiredPackages))
		args = append(args, "-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false", "-o", "Acquire::https::Verify-Peer=true", "-o", "Acquire::https::Verify-Host=true", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold")
		if _, err := command(ctx, nil, "apt-get", append(args, "update")...); err != nil {
			return err
		}
		args = append(args, "-y", "install")
		args = append(args, release.Server.RequiredPackages...)
		_, err := command(ctx, nil, "apt-get", args...)
		return err
	case platform.PackageDBRPM:
		args := make([]string, 0, 5+len(release.Server.RequiredPackages))
		args = append(args, "--assumeyes", "--setopt=*.gpgcheck=True", "--setopt=*.sslverify=True", "--setopt=install_weak_deps=False", "install")
		args = append(args, release.Server.RequiredPackages...)
		_, err := command(ctx, nil, "dnf", args...)
		return err
	default:
		return errors.New("connected dependency backend is unsupported")
	}
}

func requiredDependencies(requested []string, release *platform.Release) error {
	present := make(map[string]bool, len(requested))
	for _, name := range requested {
		base, _, _ := strings.Cut(name, "=")
		present[base] = true
	}
	for _, name := range release.Server.RequiredPackages {
		if !present[name] {
			return errors.New("signed dependency closure missing required package: " + name)
		}
	}
	return nil
}

// Preseed the distro-supported cluster switch before postgresql-common is
// configured. Existing operator policy/configuration is never overwritten.
func prepareUbuntuDependencies() (cleanup func() error, err error) {
	const configPath = "/etc/postgresql-common/createcluster.conf"
	const policyPath = "/usr/sbin/policy-rc.d"
	if _, err := os.Lstat(policyPath); err == nil {
		return nil, errors.New("existing native service policy prevents installer-owned start fencing; refusing to overwrite operator policy")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := os.Lstat(configPath); err == nil {
		configuration, err := protected(configPath, false)
		if err != nil {
			return nil, err
		}
		if !clusterPolicyDisabled(configuration) {
			return nil, errors.New("existing PostgreSQL cluster policy is not unambiguously disabled; refusing to overwrite operator configuration")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		if err := os.Mkdir("/etc/postgresql-common", 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		dir, _, err := custody.OpenRoot("/etc/postgresql-common", unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return nil, err
		}
		if err := dir.Close(); err != nil {
			return nil, err
		}
		if err := newFile(configPath, []byte("# Turnkey owns its separate hardened cluster.\ncreate_main_cluster = false\n"), 0, 0, 0644); err != nil {
			return nil, err
		}
	}
	policy := []byte("#!/bin/sh\n# Temporary authenticated installer transaction policy.\nexit 101\n")
	if err := newFile(policyPath, policy, 0, 0, 0755); err != nil {
		return nil, err
	}
	return func() error {
		actual, err := protected(policyPath, false)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, policy) {
			return errors.New("temporary native service policy changed; refusing to delete unrelated bytes")
		}
		return os.Remove(policyPath)
	}, nil
}

// Accept the four disabled spellings without changing operator configuration.
func clusterCreationDisabled(value string) bool {
	value = strings.TrimSpace(value)
	return value == "0" || strings.EqualFold(value, "off") ||
		strings.EqualFold(value, "false") || strings.EqualFold(value, "no")
}

// clusterPolicyDisabled checks the bounded, root-protected pre-transaction file
// without requiring a tool from the dependency transaction itself. It accepts
// standalone assignments in PgCommon's documented configuration grammar.
// Includes, duplicate creation switches and unsupported syntax fail closed: their
// effective value cannot be established from this one protected file.
func clusterPolicyDisabled(configuration []byte) bool {
	found := false
	for len(configuration) > 0 {
		line, remaining, _ := bytes.Cut(configuration, []byte{'\n'})
		configuration = remaining
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		keyEnd := 0
		for keyEnd < len(line) && clusterPolicyKeyByte(line[keyEnd]) {
			keyEnd++
		}
		if keyEnd == 0 || keyEnd == len(line) {
			return false
		}
		key := line[:keyEnd]
		if bytes.EqualFold(key, []byte("include")) ||
			bytes.EqualFold(key, []byte("include_if_exists")) ||
			bytes.EqualFold(key, []byte("include_dir")) {
			return false
		}
		if line[keyEnd] != '=' && line[keyEnd] != ' ' && line[keyEnd] != '\t' {
			return false
		}
		value := bytes.TrimSpace(line[keyEnd:])
		if len(value) > 0 && value[0] == '=' {
			value = bytes.TrimSpace(value[1:])
		}
		if len(value) == 0 {
			return false
		}
		if value[0] == '\'' {
			end := bytes.IndexByte(value[1:], '\'')
			if end < 0 {
				return false
			}
			tail := bytes.TrimSpace(value[end+2:])
			if len(tail) != 0 && tail[0] != '#' {
				return false
			}
			value = value[1 : end+1]
			if bytes.IndexByte(value, '\\') >= 0 {
				return false
			}
		} else {
			value, _, _ = bytes.Cut(value, []byte{'#'})
			value = bytes.TrimSpace(value)
			if len(value) == 0 {
				return false
			}
			first := value[0]
			if first == '-' {
				if len(value) < 2 {
					return false
				}
				first = value[1]
			}
			if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') &&
				(first < '0' || first > '9') {
				return false
			}
			for _, character := range value {
				if !clusterPolicyKeyByte(character) && character != ':' &&
					character != '/' && character != '+' {
					return false
				}
			}
		}
		if bytes.EqualFold(key, []byte("create_main_cluster")) {
			if found || !clusterCreationDisabled(string(value)) {
				return false
			}
			found = true
		}
	}
	return found
}

func clusterPolicyKeyByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '_' || value == '.' || value == '-'
}
