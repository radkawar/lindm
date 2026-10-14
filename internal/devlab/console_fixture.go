// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
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

// Fresh per-fixture escrow transport and wrapping keys make managed secrets
// and local-admin custody usable in the console. The always-require setting
// starts off, so reveals follow the default rule: approval whenever another
// enrolled admin could approve. RequireConsoleRevealApproval forces it on.
func (f *AuthorityFixture) configureConsoleEscrow(cfg *configv1.ServerConfig) error {
	transport, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(transport)
	if err != nil {
		return err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	const transportName, wrappingName = "console-escrow-transport.pem", "console-escrow-wrapping.key"
	err = os.WriteFile(filepath.Join(f.directory, transportName), encoded, 0600)
	clear(encoded)
	if err != nil {
		return fmt.Errorf("write console escrow transport key: %w", err)
	}
	var wrapping [32]byte
	if _, err := rand.Read(wrapping[:]); err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(f.directory, wrappingName), wrapping[:], 0600)
	clear(wrapping[:])
	if err != nil {
		return fmt.Errorf("write console escrow wrapping key: %w", err)
	}
	cfg.Escrow = &configv1.EscrowConfig{TransportKeyFile: transportName, WrappingKeyFile: wrappingName}
	return nil
}

// RequireConsoleRevealApproval restarts the console server with
// escrow.reveal_approval_required set, preserving its database, accounts and
// escrow keys.
func (f *AuthorityFixture) RequireConsoleRevealApproval(ctx context.Context) error {
	if f.connected != nil {
		return errors.New("reveal approval configuration requires controller-owned authority fixture")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return err
	}
	if document.Proto.GetEscrow() == nil {
		return errors.New("console reveal approval requires configured escrow")
	}
	document.Proto.Escrow.RevealApprovalRequired = true
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return err
	}
	if err := f.writeConfig(encoded); err != nil {
		return err
	}
	return f.Restart(ctx)
}

// CreateConsoleEnrollment returns the one-time secret for the fixed console-owner
// account. Named demos call this once and preserve the original private owner
// access file. Never log the secret as evidence or place it in a URL. The browser
// chooses its own password and authenticator.
func (f *AuthorityFixture) CreateConsoleEnrollment(ctx context.Context) (*authv1.AccountEnrollment, error) {
	return f.createConsoleAccount(ctx, "console-owner", "owner")
}

// CreateConsoleApproverEnrollment returns the one-time secret for the fixed
// console-approver account: a distinct admin human who may decide enrollment
// approvals that console-owner requested, but cannot execute them.
func (f *AuthorityFixture) CreateConsoleApproverEnrollment(ctx context.Context) (*authv1.AccountEnrollment, error) {
	return f.createConsoleAccount(ctx, "console-approver", "admin")
}

func (f *AuthorityFixture) createConsoleAccount(ctx context.Context, username, role string) (_ *authv1.AccountEnrollment, resultErr error) {
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
	if err := owner.localRequest(ctx, "/auth/accounts/create", &authv1.CreateAccountRequest{Username: username, Role: role}, enrollment, http.StatusOK); err != nil {
		return nil, err
	}
	return enrollment, nil
}

// ValidatePublicHost admits only a lowercase multi-label DNS name for a lab
// console origin: never an IP literal or a localhost name, which already
// resolve without a lab hosts entry, and never a single label, which WebAuthn
// treats as a public suffix and refuses as a relying party.
func ValidatePublicHost(host string) error {
	invalid := errors.New("public console host must be a lowercase multi-label DNS name, not localhost or an IP address")
	if len(host) == 0 || len(host) > 253 || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return invalid
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return invalid
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return invalid
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return invalid
			}
		}
	}
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return invalid
	}
	return nil
}

// ReadAgentFixture returns this live fixture's public provisioning material,
// including its own signed origins, not necessarily the shared dev origins.
func (f *AuthorityFixture) ReadAgentFixture(ctx context.Context) (*AgentFixture, error) {
	if f != nil && f.connected != nil {
		return f.connectedAgentFixture(ctx)
	}
	if f == nil || f.closed || (f.process == nil && (f.ha == nil || !f.ha.running())) || f.database == nil {
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
	if f.connected != nil {
		return errors.New("wait requires controller-owned authority fixture")
	}
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
