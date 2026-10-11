//go:build linux

package osupdate

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

var errRollingNativeHolds = errors.New("rolling_partial_upgrade_native_holds_refused")

// checkNativeHolds asks the native config resolver, not a second parser for its
// default files. It runs before refresh and immediately before installation.
// Nothing copies exclusions into the isolated whole-system transaction or tells
// the package manager to ignore its locks.
func (b *rollingBackend) checkNativeHolds(ctx context.Context) error {
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN {
		// pacman-conf uses pacman's own Include, glob and option resolution.
		// Query the HOST config, not our exclusion-free archive configuration.
		result, err := runCommand(ctx, step{timeout: oracleTimeout, stdoutLimit: oracleOutputMax}, "/usr/bin/pacman-conf", "--config", "/etc/pacman.conf", "IgnorePkg", "IgnoreGroup")
		if err != nil {
			return failure("native_exclusion_query_failed", b.tool(), agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, result)
		}
		return rejectPacmanExclusions(result.stdout)
	}
	// zypper locks explicitly reads ZConfig::locksFile(), honoring configdir,
	// locksfile.path and supported configuration overrides. The same command
	// prefix/environment and effective libzypp configuration drive dup.
	result, err := b.command(ctx, step{timeout: oracleTimeout, stdoutLimit: oracleOutputMax}, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "--xmlout", "locks")
	if err != nil {
		return err
	}
	return rejectZypperLocks(result.stdout)
}

func rejectPacmanExclusions(data []byte) error {
	// With no exclusions, pacman-conf emits no lines. Every nonempty value
	// (including a wildcard or group) prevents a complete snapshot upgrade.
	if len(bytes.TrimSpace(data)) != 0 {
		return errRollingNativeHolds
	}
	return nil
}

func rejectZypperLocks(data []byte) error {
	var stream struct {
		XMLName xml.Name `xml:"stream"`
		Lists   []struct {
			Size  *uint64    `xml:"size,attr"`
			Locks []struct{} `xml:"lock"`
		} `xml:"locks"`
		Messages []struct {
			Type string `xml:"type,attr"`
		} `xml:"message"`
	}
	if err := xml.Unmarshal(data, &stream); err != nil {
		return errNativeOutput
	}
	if len(stream.Lists) != 1 || stream.Lists[0].Size == nil || *stream.Lists[0].Size != uint64(len(stream.Lists[0].Locks)) {
		return errNativeOutput
	}
	for _, message := range stream.Messages {
		if message.Type == "error" {
			return errNativeOutput
		}
	}
	if *stream.Lists[0].Size != 0 {
		return errRollingNativeHolds
	}
	return nil
}
