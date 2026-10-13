package config

import (
	"crypto/x509"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func TestAuthenticationSchema(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&configv1.ServerConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*configv1.ServerConfig)
		valid  bool
	}{
		{name: "keycloak", valid: true},
		{name: "local", valid: true, change: func(cfg *configv1.ServerConfig) { cfg.Authentication = localAuthentication() }},
		{name: "missing authentication", change: func(cfg *configv1.ServerConfig) { cfg.Authentication = nil }},
		{name: "missing primary", change: func(cfg *configv1.ServerConfig) { cfg.Authentication = &configv1.AuthenticationConfig{} }},
		{name: "shared clients", change: func(cfg *configv1.ServerConfig) {
			cfg.Authentication.GetKeycloak().DirectoryClientId = cfg.Authentication.GetKeycloak().ClientId
		}},
		{name: "insecure issuer", change: func(cfg *configv1.ServerConfig) {
			cfg.Authentication.GetKeycloak().Issuer = "http://idp.example/realms/lindm"
		}},
		{name: "missing secret", change: func(cfg *configv1.ServerConfig) { cfg.Authentication.GetKeycloak().ClientSecretFile = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := executionSigningSchemaConfig()
			if test.change != nil {
				test.change(cfg)
			}
			if err := validator.Validate(cfg); (err == nil) != test.valid {
				t.Fatalf("validation = %v, want valid %t", err, test.valid)
			}
		})
	}
}

func TestBreakGlassSchema(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&configv1.BreakGlassPolicy{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*configv1.BreakGlassPolicy)
		valid  bool
	}{
		{name: "permission policy", valid: true},
		{name: "console restriction", valid: true, change: func(p *configv1.BreakGlassPolicy) { p.ConsoleOnly = true }},
		{name: "missing allowlist", change: func(p *configv1.BreakGlassPolicy) { p.AllowedPermissions = nil }},
		{name: "console cannot replace allowlist", change: func(p *configv1.BreakGlassPolicy) { p.ConsoleOnly = true; p.AllowedPermissions = nil }},
		{name: "unknown permission", change: func(p *configv1.BreakGlassPolicy) { p.AllowedPermissions = []string{"anything"} }},
		{name: "duplicate permission", change: func(p *configv1.BreakGlassPolicy) {
			p.AllowedPermissions = []string{"accounts.manage", "accounts.manage"}
		}},
		{name: "missing lifetime", change: func(p *configv1.BreakGlassPolicy) { p.MaxSessionLifetime = nil }},
		{name: "zero lifetime", change: func(p *configv1.BreakGlassPolicy) { p.MaxSessionLifetime = durationpb.New(0) }},
		{name: "negative lifetime", change: func(p *configv1.BreakGlassPolicy) { p.MaxSessionLifetime = durationpb.New(-time.Second) }},
		{name: "over one hour", change: func(p *configv1.BreakGlassPolicy) { p.MaxSessionLifetime = durationpb.New(time.Hour + time.Nanosecond) }},
		{name: "missing incident reason requirement", change: func(p *configv1.BreakGlassPolicy) { p.RequireIncidentReason = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := &configv1.BreakGlassPolicy{AllowedPermissions: []string{"accounts.manage", "resources.assign"}, MaxSessionLifetime: durationpb.New(time.Hour), RequireIncidentReason: true}
			if test.change != nil {
				test.change(policy)
			}
			if err := validator.Validate(policy); (err == nil) != test.valid {
				t.Fatalf("validation = %v, want valid %t", err, test.valid)
			}
		})
	}
}

func TestEntraSchema(t *testing.T) {
	entra := &configv1.EntraDirectory{
		TenantId: "5026e756-92d1-4328-8cc1-5f6c9b5a51a9", ClientId: "cd614dd3-f636-4492-999c-5143d67f415a",
		DirectoryClientId: "a2a762fd-82cb-4616-8ed4-355aaf81d695", ClientSecretFile: "login-secret", DirectoryClientSecretFile: "directory-secret",
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(entra))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(entra); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*configv1.EntraDirectory){
		func(e *configv1.EntraDirectory) { e.TenantId = "common" },
		func(e *configv1.EntraDirectory) { e.ClientId = e.DirectoryClientId },
		func(e *configv1.EntraDirectory) { e.ClientId = strings.ToUpper(e.DirectoryClientId) },
		func(e *configv1.EntraDirectory) { e.DirectoryClientSecretFile = "" },
	} {
		invalid := proto.CloneOf(entra)
		change(invalid)
		if err := validator.Validate(invalid); err == nil {
			t.Fatal("invalid Entra identity mapping accepted")
		}
	}
}

func TestAuthenticationJSONRejectsLegacyAndMultipleSources(t *testing.T) {
	for _, data := range []string{`{"oidc":{}}`, `{"authentication":{"local":{},"keycloak":{}}}`} {
		if err := protojson.Unmarshal([]byte(data), &configv1.ServerConfig{}); err == nil {
			t.Fatalf("accepted invalid configuration %s", data)
		}
	}
}

func TestResolveLocalWithoutIdentityProviderFiles(t *testing.T) {
	dir := databaseFixture(t)
	writeCertificate(t, dir, "root", true, nil, nil)
	writeCertificate(t, dir, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	writeCertificate(t, dir, "server", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
	writeCertificate(t, dir, "device", true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	document := &Document{base: dir, Proto: &configv1.ServerConfig{
		PublicUrl: "https://localhost", Database: &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 2},
		Tls:            &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: "device.crt", PrivateKeyFile: "device.key"},
		Authentication: localAuthentication(),
	}}
	resources, err := document.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if resources.ClientSecret != "" || resources.DirectoryClientSecret != "" {
		t.Fatal("local mode loaded external credentials")
	}
	data, err := protojson.Marshal(executionSigningSchemaConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Strict loading rejects the previous serialized field, even if it otherwise
	// contains the complete external configuration.
	data = []byte(strings.Replace(string(data), `"authentication":`, `"oidc":`, 1))
	writeFixtureFile(t, dir, "legacy.json", data)
	if _, err := Load(filepath.Join(dir, "legacy.json")); err == nil {
		t.Fatal("legacy configuration loaded")
	}
}

func TestEntraSecretFiles(t *testing.T) {
	dir := databaseFixture(t)
	writeFixtureFile(t, dir, "login-secret", []byte(" login-secret-value\n"))
	writeFixtureFile(t, dir, "directory-secret", []byte(" directory-secret-value\n"))
	entra := &configv1.EntraDirectory{ClientSecretFile: "login-secret", DirectoryClientSecretFile: "directory-secret"}
	document := &Document{base: dir, Proto: &configv1.ServerConfig{
		Authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Entra{Entra: entra}},
	}}
	resources := &Resources{}
	if err := document.authenticationSecrets(resources); err != nil {
		t.Fatal(err)
	}
	if resources.ClientSecret != "login-secret-value" || resources.DirectoryClientSecret != "directory-secret-value" {
		t.Fatal("Entra did not resolve distinct protected credential files")
	}
	writeFixtureFile(t, dir, "empty-secret", []byte(" \n"))
	entra.DirectoryClientSecretFile = "empty-secret"
	if err := document.authenticationSecrets(&Resources{}); err == nil {
		t.Fatal("empty directory secret accepted")
	}
	entra.DirectoryClientSecretFile = "missing-secret"
	if err := document.authenticationSecrets(&Resources{}); err == nil {
		t.Fatal("missing directory secret accepted")
	}
}

func localAuthentication() *configv1.AuthenticationConfig {
	return &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}}
}

func TestAuthorizationSourceSchema(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&configv1.ServerConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		local bool
		group string
		valid bool
	}{
		{name: "exact Keycloak path", group: "/operators", valid: true},
		{name: "not a Keycloak path", group: "operators"},
		{name: "empty Keycloak path", group: "/"},
		{name: "local cannot union directory", local: true, group: "/operators"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := executionSigningSchemaConfig()
			if test.local {
				cfg.Authentication = localAuthentication()
			}
			cfg.Authorization = &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: test.group, Role: "operator"}}}
			if err := validator.Validate(cfg); (err == nil) != test.valid {
				t.Fatalf("source validation=%v, want valid=%v", err, test.valid)
			}
		})
	}
}

// A configuration file written for an earlier release keeps loading: retired
// permission names become their current equivalents before validation.
func TestLoadUpgradesRetiredPermissions(t *testing.T) {
	cfg := executionSigningSchemaConfig()
	cfg.Authorization = &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "assist", Permissions: []string{"fleet.read", "remote_assistance.run"}}}}
	cfg.BreakGlass = &configv1.BreakGlassPolicy{AllowedPermissions: []string{"remote_assistance.run", "accounts.manage"}, MaxSessionLifetime: durationpb.New(time.Hour), RequireIncidentReason: true}
	encoded, err := protojson.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFixtureFile(t, dir, "server.json", encoded)
	document, err := Load(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"fleet.read", "remote_assistance.view", "remote_assistance.control"}
	if got := document.Proto.GetAuthorization().GetRoles()[0].GetPermissions(); !slices.Equal(got, want) {
		t.Fatalf("role permissions = %q, want %q", got, want)
	}
	want = []string{"remote_assistance.view", "remote_assistance.control", "accounts.manage"}
	if got := document.Proto.GetBreakGlass().GetAllowedPermissions(); !slices.Equal(got, want) {
		t.Fatalf("break-glass allowlist = %q, want %q", got, want)
	}
	cfg.BreakGlass.AllowedPermissions = []string{"remote_assistance.unknown"}
	if encoded, err = protojson.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, dir, "unknown.json", encoded)
	if _, err := Load(filepath.Join(dir, "unknown.json")); err == nil {
		t.Fatal("loaded an unknown permission")
	}
}
