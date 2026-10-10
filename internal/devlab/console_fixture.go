package devlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/trust"
)

// OpenLocalConsoleAuthorityFixture owns a local-auth server and database on a
// dynamic loopback port. Unlike tunneled native lanes, its configured HTTPS,
// WebAuthn and signed enrollment origins all name the browser's actual port.
// Integrations and reports use an owned ephemeral encryption key. Automated
// owners remain private; CreateConsoleEnrollment issues a separate browser
// credential through the real account API. The caller must Close it.
func OpenLocalConsoleAuthorityFixture(ctx context.Context, repository, binary string) (*AuthorityFixture, error) {
	return openAuthorityFixture(ctx, repository, binary, authorityLocalConsole)
}

// Enable the real integration/report services without configuring destinations
// or schedules. Their encryption key is private to this disposable database.
func (f *AuthorityFixture) configureConsoleIntegrations(cfg *configv1.ServerConfig) error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	defer clear(key[:])
	const name = "integrations.key"
	if err := os.WriteFile(filepath.Join(f.directory, name), key[:], 0600); err != nil {
		return fmt.Errorf("write console integrations key: %w", err)
	}
	cfg.Integrations = &configv1.IntegrationsConfig{EncryptionKeyFile: name}
	return nil
}

// CreateConsoleEnrollment returns the one-time secret for the fixed console-owner
// account in this disposable local database. Never log it as ordinary evidence or
// place it in a URL. The browser chooses its own password and authenticator.
func (f *AuthorityFixture) CreateConsoleEnrollment(ctx context.Context) (_ *authv1.AccountEnrollment, resultErr error) {
	if f.local == nil || f.ConsoleOrigin == consoleOrigin {
		return nil, errors.New("browser enrollment requires a dynamic local console fixture")
	}
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, owner.Close(cleanup))
	}()
	enrollment := new(authv1.AccountEnrollment)
	if err := owner.localRequest(ctx, "/auth/accounts/create", &authv1.CreateAccountRequest{Username: "console-owner", Role: "owner"}, enrollment, http.StatusOK); err != nil {
		return nil, err
	}
	return enrollment, nil
}

// ReadAgentFixture returns this live fixture's public provisioning material,
// including its own signed origins, not necessarily the shared dev origins.
func (f *AuthorityFixture) ReadAgentFixture(ctx context.Context) (*AgentFixture, error) {
	if f == nil || f.closed || f.process == nil || f.database == nil {
		return nil, errors.New("authority fixture is not live")
	}
	root, err := os.ReadFile(filepath.Join(f.directory, "execution-root.json"))
	if err != nil {
		return nil, err
	}
	bootstrap, err := os.ReadFile(filepath.Join(f.directory, "bootstrap.dsse.json"))
	if err != nil {
		return nil, err
	}
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	if _, err := authority.VerifyBootstrap(ctx, root, bootstrap, time.Now()); err != nil {
		return nil, err
	}
	return &AgentFixture{ExecutionRootJSON: root, BootstrapEnvelope: bootstrap}, nil
}

// Wait holds an interactive fixture until cancellation or unexpected server exit.
// Like Close and Restart, it must not race another fixture lifecycle operation.
func (f *AuthorityFixture) Wait(ctx context.Context) error {
	if f.closed || f.process == nil {
		return errors.New("authority fixture is not live")
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-f.done:
		f.process, f.done = nil, nil
		return errors.Join(errors.New("isolated lindmd exited during console session"), err)
	}
}

// Re-sign only the private bootstrap; shared trust and offline keys stay read-only
// and the server never receives those keys. Normal bootstrap validation remains
// mandatory, so dynamic origins cannot be faked with a dial override.
func (f *AuthorityFixture) originAgentFixture(ctx context.Context, material *AgentFixture, deviceOrigin string) (*AgentFixture, error) {
	var result *AgentFixture
	err := locked(ctx, f.repository, func(root string) error {
		directory := filepath.Join(FixturePath(root), "agent-trust")
		authority, err := trust.New()
		if err != nil {
			return err
		}
		if err := verifyDevelopmentTrust(ctx, authority, directory); err != nil {
			return err
		}
		verified, err := authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, time.Now())
		if err != nil {
			return err
		}
		keys := make([]ed25519.PrivateKey, 0, verified.Root.GetThreshold())
		defer func() {
			for _, key := range keys {
				clear(key)
			}
		}()
		for i := range verified.Root.GetThreshold() {
			encoded, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("execution-key-%d.pem", i)))
			if err != nil {
				return err
			}
			key, err := developmentPrivateKey(encoded)
			clear(encoded)
			if err != nil {
				return err
			}
			keys = append(keys, key)
		}
		bundle := proto.CloneOf(verified.Bundle)
		bundle.BundleId, bundle.EnrollmentOrigin = uuid.NewString(), f.ConsoleOrigin
		bundle.DeviceOrigin = deviceOrigin
		envelope, err := authority.Sign(ctx, bundle, keys...)
		if err != nil {
			return err
		}
		if _, err := authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, envelope, time.Now()); err != nil {
			return err
		}
		result = &AgentFixture{ExecutionRootJSON: material.ExecutionRootJSON, BootstrapEnvelope: envelope}
		return nil
	})
	return result, err
}
