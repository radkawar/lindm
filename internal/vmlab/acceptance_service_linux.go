//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AcceptanceServiceProbeUnit is an inert unit created only on the owned guest.
// Preparing it does not start/enable it; the assigned profile must cause that.
const AcceptanceServiceProbeUnit = "acceptance-native-probe.service"

const acceptanceServiceProbe = `[Unit]
Description=Lindm acceptance native effect probe
[Service]
Type=oneshot
ExecStart=/usr/bin/true
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
`

// PrepareServiceProbe creates a harmless disabled/inactive native baseline. Call
// after stock inventory acceptance and before browser profile creation. This does
// not mask, stop or reconfigure any vendor service or install observation tools.
func (g *AcceptanceGuest) PrepareServiceProbe(ctx context.Context) (string, error) {
	if g.closed || g.vm == nil || !g.enrolled || g.probeReady {
		return "", errors.New("service probe requires an enrolled guest without a prepared probe")
	}
	path := "/etc/systemd/system/" + AcceptanceServiceProbeUnit
	command := "test ! -e " + path + "; umask 022; set -C; cat > " + path + "; systemctl daemon-reload"
	if _, err := g.vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote(command), strings.NewReader(acceptanceServiceProbe), 16<<10, time.Minute); err != nil {
		return "", err
	}
	active, enabled, err := g.serviceProbeState(ctx)
	if err != nil {
		return "", err
	}
	if active != "inactive" || enabled != "disabled" {
		return "", errors.New("new service probe was not inactive and disabled before assignment")
	}
	g.probeReady = true
	return AcceptanceServiceProbeUnit, nil
}

// VerifyServiceEffect polls read-only native systemd state, not an accepted
// action toast or a compliance label. No start/enable command occurs here.
func (g *AcceptanceGuest) VerifyServiceEffect(ctx context.Context, active, enabled bool) error {
	if g.closed || g.vm == nil || !g.probeReady || (!active && !enabled) {
		return errors.New("native effect requires a prepared probe and a change from its inactive/disabled baseline")
	}
	wantActive, wantEnabled := "inactive", "disabled"
	if active {
		wantActive = "active"
	}
	if enabled {
		wantEnabled = "enabled"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		observedActive, observedEnabled, err := g.serviceProbeState(ctx)
		if err != nil {
			return err
		}
		if observedActive == wantActive && observedEnabled == wantEnabled {
			g.evidence.ServiceEffect = true
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("native profile effect not observed (active=%s enabled=%s): %w", observedActive, observedEnabled, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (g *AcceptanceGuest) serviceProbeState(ctx context.Context) (string, string, error) {
	data, err := g.vm.run(ctx, "systemctl show --property=LoadState,ActiveState,UnitFileState "+AcceptanceServiceProbeUnit, nil, 4096, 15*time.Second)
	if err != nil {
		return "", "", err
	}
	var loaded, active, enabled string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return "", "", errors.New("native systemd state is not key/value output")
		}
		switch key {
		case "LoadState":
			loaded = value
		case "ActiveState":
			active = value
		case "UnitFileState":
			enabled = value
		}
	}
	if loaded != "loaded" || active == "" || enabled == "" {
		return "", "", errors.New("native systemd probe unit disappeared or returned incomplete state")
	}
	return active, enabled, nil
}
