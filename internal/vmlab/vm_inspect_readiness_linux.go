// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const inspectSystemReadinessCommand = "env LC_ALL=C systemctl is-system-running --wait"
const inspectSystemdVersionCommand = "env LC_ALL=C systemctl --version"
const inspectFailedUnitsCommand = "env LC_ALL=C systemctl list-units --state=failed --no-legend --plain --no-pager --full"

// maxInspectFailedUnits bounds the recorded failed-unit names of a degraded boot.
const maxInspectFailedUnits = 32

// systemd before v240 accepts --wait but ignores it for is-system-running and
// reports the current transient state at once (observed on AlmaLinux 8.10's
// systemd 239). Only such a manager is polled.
const inspectSystemWaitVersion = 240
const inspectNetworkReadinessCommand = "if command -v nm-online >/dev/null 2>&1; then env LC_ALL=C nm-online -s -q --timeout=30 && printf 'complete\\n'; else printf 'not-installed\\n'; fi"

type vmInspectReadiness struct {
	SystemState           string                `json:"system_state"`
	FailedUnits           []vmInspectFailedUnit `json:"failed_units,omitempty"`
	NetworkManagerStartup string                `json:"network_manager_startup"`
	StartedAt             time.Time             `json:"started_at"`
	CompletedAt           time.Time             `json:"completed_at"`
}

// SSH and cloud-init completion do not prove that systemd and NetworkManager
// have finished startup. Record their own bounded native readiness signals before
// taking the independent "before" inventory sample. Degraded is a settled boot,
// not a claim that every system service is healthy.
func collectInspectReadiness(ctx context.Context, run func(context.Context, string, io.Reader, int, time.Duration) (guestCommandResult, error)) (*vmInspectReadiness, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	proof := &vmInspectReadiness{StartedAt: time.Now().UTC()}
	system, err := run(ctx, inspectSystemReadinessCommand, nil, 1024, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("native system startup readiness: %w", err)
	}
	if inspectSystemTransient(system) {
		if err := requireLegacySystemWait(ctx, run); err != nil {
			return nil, err
		}
		for inspectSystemTransient(system) {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("native system startup readiness: %w", ctx.Err())
			case <-time.After(time.Second):
			}
			if system, err = run(ctx, inspectSystemReadinessCommand, nil, 1024, 30*time.Second); err != nil {
				return nil, fmt.Errorf("native system startup readiness: %w", err)
			}
		}
	}
	switch {
	case system.ExitCode == 0 && string(system.Stdout) == "running\n" && len(system.Stderr) == 0:
		proof.SystemState = "running"
	case system.ExitCode == 1 && string(system.Stdout) == "degraded\n" && len(system.Stderr) == 0:
		proof.SystemState = "degraded"
		// Degraded names no cause; record which units failed so the record can
		// be attributed to the image, the lab fixture or the product.
		if proof.FailedUnits, err = inspectFailedUnits(ctx, run); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("native system startup is not settled")
	}
	network, err := run(ctx, inspectNetworkReadinessCommand, nil, 1024, 35*time.Second)
	if err != nil {
		return nil, fmt.Errorf("native NetworkManager startup readiness: %w", err)
	}
	if network.ExitCode != 0 || len(network.Stderr) != 0 {
		return nil, errors.New("native NetworkManager startup did not complete")
	}
	switch string(network.Stdout) {
	case "complete\n":
		proof.NetworkManagerStartup = "complete"
	case "not-installed\n":
		proof.NetworkManagerStartup = "not-installed"
	default:
		return nil, errors.New("invalid native NetworkManager startup proof")
	}
	proof.CompletedAt = time.Now().UTC()
	return proof, nil
}

func inspectSystemTransient(system guestCommandResult) bool {
	state := string(system.Stdout)
	return system.ExitCode == 1 && len(system.Stderr) == 0 && (state == "initializing\n" || state == "starting\n")
}

// vmInspectFailedUnit attributes a degraded boot: the unit's native Result
// (exit-code, timeout, …) and the last journal lines of this boot.
type vmInspectFailedUnit struct {
	Unit    string   `json:"unit"`
	Result  string   `json:"result"`
	Journal []string `json:"journal"`
}

func inspectFailedUnits(ctx context.Context, run func(context.Context, string, io.Reader, int, time.Duration) (guestCommandResult, error)) ([]vmInspectFailedUnit, error) {
	listed, err := run(ctx, inspectFailedUnitsCommand, nil, 4096, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("native failed units: %w", err)
	}
	if listed.ExitCode != 0 || len(listed.Stderr) != 0 {
		return nil, errors.New("native failed units unavailable")
	}
	var units []vmInspectFailedUnit
	for line := range strings.Lines(string(listed.Stdout)) {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != "failed" || len(units) == maxInspectFailedUnits || !validUnitName(fields[0]) {
			return nil, errors.New("invalid native failed unit list")
		}
		units = append(units, vmInspectFailedUnit{Unit: fields[0]})
	}
	for i := range units {
		// Validated names contain no single quote, so quoting is exact.
		quoted := "'" + units[i].Unit + "'"
		result, err := run(ctx, "env LC_ALL=C systemctl show --property=Result --value -- "+quoted, nil, 256, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("native failed unit result: %w", err)
		}
		value, ok := strings.CutSuffix(string(result.Stdout), "\n")
		if result.ExitCode != 0 || len(result.Stderr) != 0 || !ok || value == "" || strings.Trim(value, "abcdefghijklmnopqrstuvwxyz-") != "" {
			return nil, errors.New("invalid native failed unit result")
		}
		units[i].Result = value
		journal, err := run(ctx, "sudo -n env LC_ALL=C journalctl -b --no-pager --quiet -o cat -n 5 -u "+quoted, nil, 4096, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("native failed unit journal: %w", err)
		}
		if journal.ExitCode != 0 || len(journal.Stderr) != 0 {
			return nil, errors.New("native failed unit journal unavailable")
		}
		for line := range strings.Lines(string(journal.Stdout)) {
			units[i].Journal = append(units[i].Journal, strings.ToValidUTF8(strings.TrimSuffix(line, "\n"), "?"))
		}
	}
	return units, nil
}

// validUnitName admits systemd's unit-name alphabet (escaped names use \x2d).
func validUnitName(name string) bool {
	return len(name) <= 256 && strings.Contains(name, ".") && strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_.@-\\") == ""
}

// requireLegacySystemWait accepts a transient answer to --wait only from a
// systemd that predates the switch; a newer manager must have waited.
func requireLegacySystemWait(ctx context.Context, run func(context.Context, string, io.Reader, int, time.Duration) (guestCommandResult, error)) error {
	version, err := run(ctx, inspectSystemdVersionCommand, nil, 4096, 10*time.Second)
	if err != nil {
		return fmt.Errorf("native systemd version: %w", err)
	}
	first, _, _ := strings.Cut(string(version.Stdout), "\n")
	fields := strings.Fields(first)
	if version.ExitCode != 0 || len(version.Stderr) != 0 || len(fields) < 2 || fields[0] != "systemd" {
		return errors.New("invalid native systemd version")
	}
	number, err := strconv.Atoi(fields[1])
	if err != nil || number <= 0 {
		return errors.New("invalid native systemd version")
	}
	if number >= inspectSystemWaitVersion {
		return errors.New("native system startup is not settled")
	}
	return nil
}
