// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Native Conf/RepoReader is separate from the collector's Base/read_all_repos.
// Enabled identities are checked against the actual CLI as a second source.
const dnfConfigTruthScript = `import json
import os
try:
    import dnf
    import dnf.conf
    import dnf.conf.read
    import dnf.rpm
    if str(dnf.__version__).split('.')[0] != '4':
        result = {'status': 'unavailable'}
    else:
        conf = dnf.conf.Conf()
        os.stat(conf.config_file_path)
        conf.read()
        if conf.installroot != '/':
            result = {'status': 'unavailable'}
        else:
            conf.substitutions.update_from_etc('/', varsdir=conf.varsdir)
            if conf.releasever is None:
                conf.releasever = dnf.rpm.detect_releasever('/')
            repositories = []
            for repo in dnf.conf.read.RepoReader(conf, None):
                if repo.enabled:
                    repositories.append({'id': repo.id, 'base_url': list(repo.baseurl), 'metalink': repo.metalink or '', 'mirrorlist': repo.mirrorlist or '', 'pkg_gpgcheck': bool(repo.gpgcheck), 'gpg_key': list(repo.gpgkey)})
                if len(repositories) > 256:
                    raise ValueError()
            result = {'status': 'success', 'varsdirs': list(conf.varsdir), 'releasever': conf.releasever or '', 'repositories': repositories}
except ModuleNotFoundError as error:
    result = {'status': 'unavailable' if error.name == 'dnf' else 'failure'}
except FileNotFoundError:
    result = {'status': 'unavailable'}
except PermissionError:
    result = {'status': 'denied'}
except (ValueError, UnicodeError):
    result = {'status': 'invalid'}
except Exception:
    result = {'status': 'failure'}
print(json.dumps(result))`

// DNF5's CLI owns the configuration and variable truth. Base.load_config only
// supplies the configured varsdir for the independent explicit-lock file probe.
const dnf5ConfigTruthScript = `import json
try:
    import libdnf5.base
    base = libdnf5.base.Base()
    base.load_config()
    conf = base.get_config()
    result = {'status': 'success', 'varsdirs': list(conf.get_varsdir_option().get_value())} if conf.get_installroot_option().get_value() == '/' else {'status': 'unavailable'}
except ModuleNotFoundError:
    result = {'status': 'unavailable'}
except PermissionError:
    result = {'status': 'denied'}
except (ValueError, UnicodeError):
    result = {'status': 'invalid'}
except Exception:
    result = {'status': 'failure'}
print(json.dumps(result))`

// Repo info otherwise loads enabled metadata. Disable every repository for that
// invocation only, then join its configuration rows to repo list's enabled IDs.
// No metadata/cache contents, network access or writable system state is needed.
const dnf5TruthCommandPrefix = `work=$(mktemp -d); trap 'rm -rf -- "$work"' EXIT HUP INT TERM; HOME="$work" dnf5 --cacheonly --noplugins --quiet --setopt=logdir="$work" --setopt=cachedir="$work" --setopt=persistdir="$work" `

// Only ancillary native logging/cache/state directories are redirected. The
// system configuration, reposdir and variable precedence remain unchanged.
// -I prevents per-user Python injection. Nonverbose repolist does not activate
// repository metadata or a sack; --cacheonly and --noplugins also fence the CLI.
const dnfRepositoryTruthCommand = `work=$(mktemp -d); trap 'rm -rf -- "$work"' EXIT HUP INT TERM; HOME="$work" python3 -I -c 'import sys; from dnf.cli.main import main; sys.exit(main(sys.argv[1:]))' --cacheonly --noplugins --quiet --color=never --setopt=logdir="$work" --setopt=cachedir="$work" --setopt=persistdir="$work" repolist --enabled`

func (o vmInventoryOracle) platform() (*inventoryv1.PlatformDetails, error) {
	data, err := o.command(`if [ -e /etc/os-release ]; then . /etc/os-release; else . /usr/lib/os-release; fi; if [ -n "${CPE_NAME-}" ]; then printf 'success\n%s' "$CPE_NAME"; else printf 'unavailable\n'; fi`)
	if err != nil {
		return nil, err
	}
	value, status, err := parseTruthStatus(data)
	if err != nil {
		return nil, err
	}
	result := &inventoryv1.PlatformDetails{Cpe: &inventoryv1.ObservedString{Status: status, Value: string(value)}}
	backend, err := o.command("if command -v dnf5 >/dev/null 2>&1; then printf dnf5; else printf dnf4; fi")
	if err != nil {
		return nil, err
	}
	script := dnfConfigTruthScript
	if string(backend) == "dnf5" {
		script = dnf5ConfigTruthScript
	}
	data, status, err = o.optional("python3", "python3 -I -c "+nativeQuote(script))
	if err != nil {
		return nil, err
	}
	var directories []string
	if status == truthSuccess {
		directories, status, err = parseDNFConfigTruth(data)
		if err != nil {
			return nil, err
		}
	}
	result.ReleaseverLock = &inventoryv1.ObservedString{Status: status}
	result.Releasever = &inventoryv1.ObservedString{Status: status}
	result.Repositories = &inventoryv1.RepositoryObservation{Status: status}
	if status != truthSuccess {
		return result, nil
	}
	result.ReleaseverLock = truthString("")
	for _, directory := range directories {
		quoted := nativeQuote(filepath.Join(directory, "releasever"))
		data, err := o.command("if [ ! -e " + quoted + " ]; then printf 'unavailable\\n'; elif [ ! -f " + quoted + " ]; then printf 'invalid\\n'; elif [ ! -r " + quoted + " ]; then printf 'denied\\n'; else printf 'success\\n'; cat -- " + quoted + "; fi")
		if err != nil {
			return nil, err
		}
		lock, err := parseReleaseLockTruth(data)
		if err != nil {
			return nil, err
		}
		if lock.Status == truthUnavailable {
			continue
		}
		result.ReleaseverLock = lock
		if lock.Status != truthSuccess {
			result.Repositories.Status = lock.Status
			return result, nil
		}
	}
	if string(backend) == "dnf5" {
		result.Repositories, result.Releasever, err = o.dnf5Platform()
	} else {
		var config struct {
			Releasever   string                `json:"releasever"`
			Repositories []nativeDNFRepository `json:"repositories"`
		}
		if json.Unmarshal(data, &config) != nil || config.Repositories == nil {
			return nil, errors.New("incomplete native DNF4 configuration truth")
		}
		result.Releasever = truthString(config.Releasever)
		native, commandErr := o.platformCommand(dnfRepositoryTruthCommand)
		if commandErr != nil {
			return nil, commandErr
		}
		result.Repositories, err = parseDNFRepositoryTruth(native)
		if err == nil && result.Repositories.Status == truthSuccess {
			err = attachDNFConfigurations(result.Repositories, config.Repositories, false)
		}
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (o vmInventoryOracle) platformCommand(script string) (guestCommandResult, error) {
	command := "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -c " + nativeQuote("set -eu; "+script)
	result, err := o.vm.runResult(o.ctx, command, nil, 4<<20, 30*time.Second)
	if err != nil {
		return guestCommandResult{}, errors.New("native platform truth transport failed")
	}
	return result, nil
}

func (o vmInventoryOracle) dnf5Platform() (*inventoryv1.RepositoryObservation, *inventoryv1.ObservedString, error) {
	list, err := o.platformCommand(dnf5TruthCommandPrefix + "repo list --enabled --json")
	if err != nil {
		return nil, nil, err
	}
	info, err := o.platformCommand(dnf5TruthCommandPrefix + "--disable-repo='*' repo info --all --json")
	if err != nil {
		return nil, nil, err
	}
	repositories, err := parseDNF5RepositoryTruth(list, info)
	if err != nil {
		return nil, nil, err
	}
	vars, err := o.platformCommand(dnf5TruthCommandPrefix + "--dump-variables")
	if err != nil {
		return nil, nil, err
	}
	releasever, err := parseDNF5ReleaseverTruth(vars)
	return repositories, releasever, err
}

func parseDNFConfigTruth(data []byte) ([]string, inventoryv1.CollectionStatus, error) {
	var config struct {
		Status   string   `json:"status"`
		Varsdirs []string `json:"varsdirs"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, 0, errors.New("invalid native DNF configuration truth")
	}
	var status inventoryv1.CollectionStatus
	switch config.Status {
	case "success":
		status = truthSuccess
	case "unavailable":
		status = truthUnavailable
	case "denied":
		status = truthDenied
	case "invalid":
		status = inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT
	case "failure":
		status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
	default:
		return nil, 0, errors.New("unknown native DNF configuration status")
	}
	if status != truthSuccess {
		if len(config.Varsdirs) != 0 {
			return nil, 0, errors.New("failed native config truth contains partial directories")
		}
		return nil, status, nil
	}
	if len(config.Varsdirs) > 32 {
		return nil, inventoryv1.CollectionStatus_COLLECTION_STATUS_CAPACITY_EXCEEDED, nil
	}
	for _, directory := range config.Varsdirs {
		if !filepath.IsAbs(directory) || strings.ContainsAny(directory, "\x00\r\n") {
			return nil, inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT, nil
		}
	}
	return config.Varsdirs, status, nil
}

func parseReleaseLockTruth(data []byte) (*inventoryv1.ObservedString, error) {
	value, status, err := parseTruthStatus(data)
	if err != nil {
		return nil, err
	}
	result := &inventoryv1.ObservedString{Status: status}
	if status != truthSuccess {
		return result, nil
	}
	if len(value) > 4096 {
		result.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_CAPACITY_EXCEEDED
		return result, nil
	}
	text := strings.TrimSuffix(string(value), "\n")
	if text == "" || strings.ContainsFunc(text, func(r rune) bool { return r <= ' ' || r == 127 }) {
		result.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT
		return result, nil
	}
	result.Value = text
	return result, nil
}

func parseDNFRepositoryTruth(native guestCommandResult) (*inventoryv1.RepositoryObservation, error) {
	result := &inventoryv1.RepositoryObservation{Status: truthSuccess, Backend: "dnf4"}
	// DNF's nonverbose native command explicitly reports this successful empty
	// configuration. It is not a fallback for arbitrary warnings or failures.
	emptyConfiguration := native.ExitCode == 0 && len(native.Stdout) == 0 && string(native.Stderr) == "No repositories available\n"
	if native.ExitCode != 0 || (len(native.Stderr) != 0 && !emptyConfiguration) {
		return &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE}, nil
	}
	if emptyConfiguration || len(native.Stdout) == 0 {
		return result, nil
	}
	rows, err := truthRows(native.Stdout)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || strings.Join(rows[0], " ") != "repo id repo name" {
		return nil, errors.New("invalid native DNF repolist header")
	}
	seen := make(map[string]bool, len(rows)-1)
	for _, row := range rows[1:] {
		if len(row) < 2 || strings.ContainsAny(row[0], "$\x00\r\n") || seen[row[0]] {
			return nil, errors.New("invalid or duplicate native repository identity")
		}
		seen[row[0]] = true
		result.Ids = append(result.Ids, row[0])
	}
	if len(result.Ids) > 256 {
		return nil, fmt.Errorf("native repository truth exceeds capacity (%d IDs)", len(result.Ids))
	}
	return result, nil
}

// JSON keys are DNF5's native CLI contract, also emitted by the DNF4
// RepoReader probe. Pointers distinguish false/empty from missing fields.
type nativeDNFRepository struct {
	ID         string   `json:"id"`
	BaseURLs   []string `json:"base_url"`
	Metalink   *string  `json:"metalink"`
	Mirrorlist *string  `json:"mirrorlist"`
	GPGCheck   *bool    `json:"pkg_gpgcheck"`
	GPGKeys    []string `json:"gpg_key"`
}

func parseDNF5RepositoryTruth(list, info guestCommandResult) (*inventoryv1.RepositoryObservation, error) {
	if list.ExitCode != 0 || info.ExitCode != 0 || len(list.Stderr) != 0 || len(info.Stderr) != 0 {
		return &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE}, nil
	}
	var enabled []struct {
		ID      string `json:"id"`
		Enabled *bool  `json:"is_enabled"`
	}
	var configurations []nativeDNFRepository
	if json.Unmarshal(list.Stdout, &enabled) != nil || enabled == nil || json.Unmarshal(info.Stdout, &configurations) != nil || configurations == nil {
		return nil, errors.New("invalid native DNF5 repository JSON truth")
	}
	if len(enabled) > 256 {
		return nil, errors.New("native enabled repository truth exceeds capacity")
	}
	result := &inventoryv1.RepositoryObservation{Status: truthSuccess, Backend: "dnf5"}
	for _, repo := range enabled {
		if repo.Enabled == nil || !*repo.Enabled {
			return nil, errors.New("native enabled repository truth includes disabled or missing state")
		}
		result.Ids = append(result.Ids, repo.ID)
	}
	if err := attachDNFConfigurations(result, configurations, true); err != nil {
		return nil, err
	}
	return result, nil
}

func attachDNFConfigurations(result *inventoryv1.RepositoryObservation, rows []nativeDNFRepository, allowDisabled bool) error {
	enabled := make(map[string]bool, len(result.Ids))
	for _, id := range result.Ids {
		if id == "" || strings.ContainsAny(id, "$ \t\x00\r\n") || enabled[id] {
			return errors.New("invalid or duplicate native enabled repository identity")
		}
		enabled[id] = true
	}
	seen := make(map[string]bool, len(rows))
	configurations := make([]*inventoryv1.RepositoryConfiguration, 0, len(enabled))
	for _, row := range rows {
		if row.ID == "" || strings.ContainsAny(row.ID, "$ \t\x00\r\n") || seen[row.ID] {
			return errors.New("invalid or duplicate native repository configuration identity")
		}
		seen[row.ID] = true
		if !enabled[row.ID] {
			if allowDisabled {
				continue
			}
			return errors.New("native repository configuration disagrees with enabled CLI identities")
		}
		if row.BaseURLs == nil || row.GPGKeys == nil || row.Metalink == nil || row.Mirrorlist == nil || row.GPGCheck == nil {
			return errors.New("incomplete native repository configuration truth")
		}
		config := &inventoryv1.RepositoryConfiguration{Id: row.ID, Gpgcheck: *row.GPGCheck}
		var err error
		for _, source := range []struct {
			values []string
			target *[]string
		}{{row.BaseURLs, &config.BaseUrls}, {row.GPGKeys, &config.GpgKeys}} {
			for _, value := range source.values {
				clean, redacted, err := redactDNFTruthURL(value)
				if err != nil {
					return err
				}
				*source.target = append(*source.target, clean)
				config.UrlsRedacted = config.UrlsRedacted || redacted
			}
		}
		for _, source := range []struct {
			value  string
			target *string
		}{{*row.Metalink, &config.Metalink}, {*row.Mirrorlist, &config.Mirrorlist}} {
			if source.value == "" {
				continue
			}
			var redacted bool
			*source.target, redacted, err = redactDNFTruthURL(source.value)
			if err != nil {
				return err
			}
			config.UrlsRedacted = config.UrlsRedacted || redacted
		}
		configurations = append(configurations, config)
	}
	if len(configurations) != len(enabled) {
		return errors.New("native repository configuration missing enabled CLI identity")
	}
	result.Configurations = configurations
	return nil
}

func redactDNFTruthURL(value string) (string, bool, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Opaque != "" || strings.ContainsAny(value, "$\x00\r\n") {
		// Never include native text or url.Parse's error, which may carry secrets.
		return "", false, errors.New("invalid native repository URL truth (value withheld)")
	}
	redacted := parsed.User != nil || strings.ContainsAny(value, "?#")
	parsed.User, parsed.RawQuery, parsed.Fragment, parsed.RawFragment, parsed.ForceQuery = nil, "", "", "", false
	return parsed.String(), redacted, nil
}

func parseDNF5ReleaseverTruth(native guestCommandResult) (*inventoryv1.ObservedString, error) {
	if native.ExitCode != 0 || len(native.Stderr) != 0 {
		return &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE}, nil
	}
	lines := strings.Split(strings.TrimSuffix(string(native.Stdout), "\n"), "\n")
	if len(lines) == 0 || lines[0] != "======== Variables: ========" {
		return nil, errors.New("invalid native DNF5 variables header")
	}
	result := &inventoryv1.ObservedString{Status: truthUnavailable}
	seen := make(map[string]bool, len(lines)-1)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, " = ")
		if !ok || name == "" || seen[name] {
			return nil, errors.New("invalid native DNF5 variables truth")
		}
		seen[name] = true
		if name == "releasever" {
			if value == "" || strings.ContainsAny(value, "$ \t\x00\r\n") {
				return nil, errors.New("invalid native effective releasever truth")
			}
			result = truthString(value)
		}
	}
	return result, nil
}
