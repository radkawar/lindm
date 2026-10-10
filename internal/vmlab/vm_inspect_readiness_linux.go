//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

const inspectSystemReadinessCommand = "env LC_ALL=C systemctl is-system-running --wait"
const inspectNetworkReadinessCommand = "if command -v nm-online >/dev/null 2>&1; then env LC_ALL=C nm-online -s -q --timeout=30 && printf 'complete\\n'; else printf 'not-installed\\n'; fi"

type vmInspectReadiness struct {
	SystemState           string    `json:"system_state"`
	NetworkManagerStartup string    `json:"network_manager_startup"`
	StartedAt             time.Time `json:"started_at"`
	CompletedAt           time.Time `json:"completed_at"`
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
	switch {
	case system.ExitCode == 0 && string(system.Stdout) == "running\n" && len(system.Stderr) == 0:
		proof.SystemState = "running"
	case system.ExitCode == 1 && string(system.Stdout) == "degraded\n" && len(system.Stderr) == 0:
		proof.SystemState = "degraded"
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
