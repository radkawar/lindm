package devlab

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"lindm/internal/config"
	"lindm/internal/trust"
)

// AgentFixture contains only the public, verified provisioning documents from
// an existing development fixture. It never exposes fixture signing keys.
type AgentFixture struct {
	ExecutionRootJSON []byte
	BootstrapEnvelope []byte
}

// ReadAgentFixture verifies existing protected trust; it does not initialize or
// replace trust. Run the explicit development trust command before using it.
func ReadAgentFixture(ctx context.Context, repoRoot string) (*AgentFixture, error) {
	var result *AgentFixture
	err := locked(ctx, repoRoot, func(root string) error {
		fixture := FixturePath(root)
		if err := validateFixture(fixture); err != nil {
			return err
		}
		authority, err := trust.New()
		if err != nil {
			return err
		}
		dir := filepath.Join(fixture, "agent-trust")
		if err := verifyDevelopmentTrust(ctx, authority, dir); err != nil {
			return err
		}
		execution, err := os.ReadFile(filepath.Join(dir, "execution-root.json"))
		if err != nil {
			return err
		}
		bundle, err := os.ReadFile(filepath.Join(dir, "bootstrap.dsse.json"))
		if err != nil {
			return err
		}
		verified, err := authority.VerifyBootstrap(ctx, execution, bundle, time.Now())
		if err != nil {
			return err
		}
		document, err := config.Load(filepath.Join(fixture, "server.json"))
		if err != nil {
			return err
		}
		transport, err := os.ReadFile(filepath.Join(fixture, "transport-ca.crt"))
		if err != nil {
			return err
		}
		device, err := os.ReadFile(filepath.Join(fixture, "device-ca.crt"))
		if err != nil {
			return err
		}
		if verified.Bundle.GetDeploymentId() != document.Proto.GetDeploymentId() || verified.Bundle.GetEnrollmentOrigin() != consoleOrigin || verified.Bundle.GetEnrollmentOrigin() != document.Proto.GetPublicUrl() || verified.Bundle.GetDeviceOrigin() != "https://localhost:18445" || !bytes.Equal(verified.Bundle.GetTransportCaPem(), transport) || !bytes.Equal(verified.Bundle.GetDeviceCaPem(), device) {
			return errors.New("existing agent trust does not bind the development fixture")
		}
		result = &AgentFixture{ExecutionRootJSON: execution, BootstrapEnvelope: bundle}
		return nil
	})
	return result, err
}
