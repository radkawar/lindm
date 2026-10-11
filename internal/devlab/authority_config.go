package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
	"lindm/internal/trust"
)

// authorityDocument constructs current-schema configuration from verified public
// trust and fixed lab dependencies. It never decodes the shared server.json or
// copies authorization policy from a potentially older development installation.
func authorityDocument(ctx context.Context, path, shared string, material *AgentFixture) (*config.Document, error) {
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	verified, err := authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, time.Now())
	if err != nil {
		return nil, err
	}
	cfg := &configv1.ServerConfig{
		DeploymentId: verified.Bundle.GetDeploymentId(), PublicUrl: consoleOrigin,
		AdminListener:  &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444},
		DeviceListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18445},
		Database:       &configv1.DatabaseConfig{UrlFile: filepath.Join(shared, "database-url"), MigrationUrlFile: proto.String(filepath.Join(shared, "migration-database-url")), MaxConnections: 4, AdminConnections: proto.Uint32(2)},
		Tls:            &configv1.TLSConfig{CertificateFile: filepath.Join(shared, "server.crt"), PrivateKeyFile: filepath.Join(shared, "server.key")},
		DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: filepath.Join(shared, "device-ca.crt"), PrivateKeyFile: filepath.Join(shared, "device-ca.key")},
		Authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{Issuer: issuer, ClientId: "lindm-console", ClientSecretFile: filepath.Join(shared, "console-secret"), DirectoryClientId: "lindm-directory", DirectoryClientSecretFile: filepath.Join(shared, "directory-secret")}}},
		Authorization:  &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "/mdm-admins", Role: "admin"}}},
		TrustedCaFile:  filepath.Join(shared, "transport-ca.crt"), InventoryBudgetBytes: proto.Uint64(10 << 30),
	}
	encoded, err := protojson.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return nil, err
	}
	return config.Load(path)
}

// validateAuthorityFixture checks only the immutable files used by an isolated
// Keycloak lane. It deliberately does not interpret the shared server schema.
func validateAuthorityFixture(dir string) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	if m.Version != fixtureVersion || m.Directory != dir {
		return errors.New("authority fixture manifest binding changed")
	}
	for _, name := range []string{"transport-ca.crt", "transport-ca.key", "device-ca.crt", "device-ca.key", "server.crt", "server.key", "postgres-password", "database-url", "migration-database-url", "console-secret", "directory-secret", "owner-password"} {
		data, err := readOwned(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		clear(data)
		if m.Files[name] != hex.EncodeToString(digest[:]) {
			return fmt.Errorf("authority fixture file %s changed", name)
		}
	}
	return validateCertificates(dir)
}
