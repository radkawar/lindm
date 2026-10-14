// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"embed"
	"fmt"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	// BinaryPath is the packaged agent executable.
	BinaryPath = "/usr/libexec/lindm/lindm-agent"
	// ExecutorStatePath is the root-owned journal and identity directory.
	ExecutorStatePath = "/var/lib/lindm/executor"
	// AgentStatePath is the lindm-owned observation spool.
	AgentStatePath = "/var/lib/lindm/agent"
	// RuntimeDirectory is the root-owned, group-traversable socket directory.
	RuntimeDirectory = "/run/lindm"
	// SocketName is the executor socket file name, not a path.
	SocketName = "executor.sock"
	// NetworkUser is resolved by the agent at start. It is not a numeric UID.
	NetworkUser = "lindm"
	// PackageName is the DEB and RPM package name.
	PackageName = "lindm-agent"
	// DefaultSourceDateEpoch keeps an unset request off the wall clock.
	DefaultSourceDateEpoch int64 = 1760000000
	// APTDistribution and APTComponent are the isolated lab archive coordinates.
	APTDistribution = "stable"
	APTComponent    = "main"
	// RPMRelease is the RPM release used for every upstream version.
	RPMRelease = "1"

	stateParent           = "/var/lib/lindm"
	configDir             = "/etc/lindm"
	lifecyclePath         = "/usr/libexec/lindm/lifecycle"
	unitDir               = "/usr/lib/systemd/system"
	executorUnit          = "lindm-executor.service"
	agentUnit             = "lindm-agent.service"
	poweroffUnit          = "lindm-live-root-poweroff.service"
	firewallRestoreUnit   = "lindm-firewall-restore.service"
	connectivityGuardUnit = "lindm-connectivity-guard.service"
	connectivityProbeUnit = "lindm-connectivity-probe.service"
	// Static OS update units: started by the provider-owned timer or the
	// executor, never enabled by the package.
	osUpdateUnit       = "lindm-os-update.service"
	osUpdateNowUnit    = "lindm-os-update-now.service"
	osUpdateStatusUnit = "lindm-os-update-status.service"
	// sessionUnit is the per-user remote-assistance helper (systemd user unit).
	sessionUnit = "lindm-session.service"
	// sessionAutostartPath starts sessionUnit from XDG autostart on desktops
	// whose session manager never activates graphical-session.target.
	sessionAutostartPath = "/etc/xdg/autostart/lindm-session.desktop"
	// overlayExtensionDir is the system GNOME Shell extension the session
	// helper uses as its only qualified non-interactive assistance overlay.
	overlayExtensionDir = "/usr/share/gnome-shell/extensions/lindm-overlay@lindm.dev"
	sysusersPath        = "/usr/lib/sysusers.d/lindm.conf"
	tmpfilesPath        = "/usr/lib/tmpfiles.d/lindm.conf"
	copyrightPath       = "/usr/share/doc/lindm-agent/copyright"
	purposeText         = "development-package-signing\n"
)

//go:embed assets/*
var assetFS embed.FS

// AgentConfigJSON is the document written to both packaged configuration files.
// It uses protobuf names and contains no numeric UID.
func AgentConfigJSON() ([]byte, error) {
	payload := &agentv1.AgentConfig{
		StateDirectory:   ExecutorStatePath,
		RuntimeDirectory: RuntimeDirectory,
		SocketName:       SocketName,
		NetworkUser:      NetworkUser,
		SpoolDirectory:   AgentStatePath,
	}
	if err := protovalidate.Validate(payload); err != nil {
		return nil, fmt.Errorf("validate packaged agent configuration: %w", err)
	}
	data, err := (protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}).Marshal(payload)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func asset(name string) ([]byte, error) {
	data, err := assetFS.ReadFile("assets/" + name)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, fmt.Errorf("%w: embedded asset %s", ErrArtifact, name)
	}
	return data, nil
}

func epochOf(requested int64) (int64, error) {
	if requested == 0 {
		return DefaultSourceDateEpoch, nil
	}
	if requested < 0 {
		return 0, fmt.Errorf("%w: negative source date", ErrUnsafePath)
	}
	return requested, nil
}

func wants(formats []Format, format Format) bool {
	if len(formats) == 0 {
		return true
	}
	for _, item := range formats {
		if item == format {
			return true
		}
	}
	return false
}
