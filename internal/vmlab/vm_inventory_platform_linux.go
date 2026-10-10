//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// This queries native Conf directly for the configured varsdir, rather than
// the collector's Base/read_all_repos helper. Repository truth comes separately
// from DNF's actual nonverbose repolist CLI; neither path initializes a sack.
const dnfConfigTruthScript = `import json
import os
try:
    import dnf
    import dnf.conf
    if str(dnf.__version__).split('.')[0] != '4':
        result = {'status': 'unavailable'}
    else:
        conf = dnf.conf.Conf()
        os.stat(conf.config_file_path)
        conf.read()
        result = {'status': 'success', 'varsdirs': list(conf.varsdir)} if conf.installroot == '/' else {'status': 'unavailable'}
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
	data, status, err = o.optional("python3", "python3 -I -c "+nativeQuote(dnfConfigTruthScript))
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
	command := "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -c " + nativeQuote("set -eu; "+dnfRepositoryTruthCommand)
	native, err := o.vm.runResult(o.ctx, command, nil, 4<<20, 30*time.Second)
	if err != nil {
		return nil, errors.New("native repository truth transport failed")
	}
	result.Repositories, err = parseDNFRepositoryTruth(native)
	if err != nil {
		return nil, err
	}
	if result.Repositories.Status != truthSuccess {
		result.ReleaseverLock = &inventoryv1.ObservedString{Status: result.Repositories.Status}
	}
	return result, nil
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
