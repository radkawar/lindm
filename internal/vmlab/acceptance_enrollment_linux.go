//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
)

// Enroll consumes a browser-created grant or provisioning token with the actual
// installed customer CLI. The fixture supplies only authenticated public trust
// material and endpoint addresses; no fixture enrollment or issuance API is used.
// The caller owns secret and must clear it after this call. Approval-required
// tokens need an independent owner to approve concurrently while resume waits.
func (g *AcceptanceGuest) Enroll(ctx context.Context, fixture *devlab.AuthorityFixture, kind string, secret []byte) (string, error) {
	if g.closed || g.vm == nil || g.enrolled || fixture == nil || len(secret) == 0 {
		return "", errors.New("acceptance enrollment requires a live unprovisioned guest, fixture and browser credential")
	}
	credentialPath, flag := "/run/lindm-enrollment/grant", "-grant"
	switch kind {
	case "grant":
	case "provisioning":
		credentialPath, flag = "/etc/lindm/provisioning-token", "-provisioning-token-file"
	default:
		return "", errors.New("acceptance credential kind must be grant or provisioning")
	}
	for _, address := range []string{fixture.AdminAddress, fixture.DeviceAddress} {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != "127.0.0.1" {
			return "", errors.New("acceptance fixture endpoints must be isolated IPv4 loopback")
		}
		if _, err := g.Forward(ctx, net.JoinHostPort("127.0.0.1", port), address); err != nil {
			return "", err
		}
	}
	material, err := fixture.ReadAgentFixture(ctx)
	if err != nil {
		return "", err
	}
	if _, err := waitGuestExecutorReady(ctx, g.vm, agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED); err != nil {
		return "", err
	}
	for _, file := range []struct {
		path string
		data []byte
	}{
		{"/etc/lindm/execution-root.json", material.ExecutionRootJSON},
		{"/etc/lindm/bootstrap.dsse.json", material.BootstrapEnvelope},
		{credentialPath, secret},
	} {
		command := "umask 077; install -d -m 0700 /run/lindm-enrollment; cat > " + nativeQuote(file.path) + "; chown root:root " + nativeQuote(file.path) + "; chmod 0600 " + nativeQuote(file.path)
		if _, err := g.vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote(command), bytes.NewReader(file.data), 4096, time.Minute); err != nil {
			return "", fmt.Errorf("place protected enrollment material: %w", err)
		}
	}
	// Paths and flags are exactly GetEnrollmentInstructions' customer commands.
	// Suppress command output, not failure: secret-bearing error bodies never
	// enter evidence, and an interrupted enrollment is not silently replayed.
	command := "trap 'rm -f " + credentialPath + "' EXIT\n" +
		packaging.BinaryPath + " bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json " + flag + " " + credentialPath + "\n" +
		packaging.BinaryPath + " resume -wait-seconds 3600\n" +
		"systemctl enable --now lindm-executor.service lindm-agent.service\n" +
		"systemctl restart lindm-agent.service\n"
	result, err := g.vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(command), nil, 64<<10, 65*time.Minute)
	if err != nil {
		return "", fmt.Errorf("customer enrollment command: %w", err)
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("customer enrollment command exited %d (output withheld)", result.ExitCode)
	}
	status, err := waitGuestExecutorReady(ctx, g.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	if err != nil {
		return "", err
	}
	if !vmValidID(status.GetDeviceId()) {
		return "", errors.New("customer enrollment omitted the installed device identity")
	}
	g.enrolled = true
	g.evidence.DeviceID, g.evidence.CredentialKind = status.GetDeviceId(), kind
	return status.GetDeviceId(), nil
}
