// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func oktaAuthentication() *configv1.AuthenticationConfig {
	return &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Okta{Okta: &configv1.OktaDirectory{
		Issuer: "https://example.okta.com", OrgUrl: "https://example.okta.com",
		ClientId: "login-client", ClientSecretFile: "login-secret", DirectoryClientId: "directory-client",
		DirectoryKeyId: "directory-key", DirectoryPrivateKeyFile: "directory-key.pem",
	}}}
}

func googleAuthentication() *configv1.AuthenticationConfig {
	return &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Google{Google: &configv1.GoogleDirectory{
		ClientId: "login-client", ClientSecretFile: "login-secret", ServiceAccountEmail: "directory@example.iam.gserviceaccount.com",
		PrivateKeyId: "directory-key", PrivateKeyFile: "directory-key.pem", DelegatedSubject: "reader@example.com", HostedDomain: "example.com",
	}}}
}

func scimConfiguration() *configv1.SCIMConfig {
	return &configv1.SCIMConfig{Connectors: []*configv1.SCIMConnector{{
		Id: "provisioner", Correlations: []*configv1.SCIMCorrelation{{
			ProviderId: "00u12345678901234567", Issuer: "https://example.okta.com", Subject: "00u12345678901234567",
		}},
	}}}
}

func TestDirectoryConfigurationSchema(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&configv1.ServerConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		auth   func() *configv1.AuthenticationConfig
		change func(*configv1.ServerConfig)
		valid  bool
	}{
		{name: "Okta", auth: oktaAuthentication, valid: true},
		{name: "Google", auth: googleAuthentication, valid: true},
		{name: "SCIM supplemental", auth: oktaAuthentication, valid: true, change: func(c *configv1.ServerConfig) { c.Authentication.Scim = scimConfiguration() }},
		{name: "Okta shared clients", auth: oktaAuthentication, change: func(c *configv1.ServerConfig) {
			c.Authentication.GetOkta().DirectoryClientId = c.Authentication.GetOkta().ClientId
		}},
		{name: "Okta insecure org", auth: oktaAuthentication, change: func(c *configv1.ServerConfig) { c.Authentication.GetOkta().OrgUrl = "http://example.okta.com" }},
		{name: "Okta management path", auth: oktaAuthentication, change: func(c *configv1.ServerConfig) { c.Authentication.GetOkta().OrgUrl = "https://example.okta.com/api" }},
		{name: "Okta missing private key", auth: oktaAuthentication, change: func(c *configv1.ServerConfig) { c.Authentication.GetOkta().DirectoryPrivateKeyFile = "" }},
		{name: "Google missing delegation", auth: googleAuthentication, change: func(c *configv1.ServerConfig) { c.Authentication.GetGoogle().DelegatedSubject = "" }},
		{name: "Google missing hosted domain", auth: googleAuthentication, change: func(c *configv1.ServerConfig) { c.Authentication.GetGoogle().HostedDomain = "" }},
		{name: "SCIM cannot provision local", auth: localAuthentication, change: func(c *configv1.ServerConfig) { c.Authentication.Scim = scimConfiguration() }},
		{name: "SCIM duplicate connector", auth: oktaAuthentication, change: func(c *configv1.ServerConfig) {
			c.Authentication.Scim = scimConfiguration()
			c.Authentication.Scim.Connectors = append(c.Authentication.Scim.Connectors, proto.CloneOf(c.Authentication.Scim.Connectors[0]))
		}},
		{name: "SCIM duplicate immutable mapping", auth: oktaAuthentication, change: func(c *configv1.ServerConfig) {
			c.Authentication.Scim = scimConfiguration()
			connector := c.Authentication.Scim.Connectors[0]
			connector.Correlations = append(connector.Correlations, proto.CloneOf(connector.Correlations[0]))
		}},
		{name: "Okta group ID", auth: oktaAuthentication, valid: true, change: func(c *configv1.ServerConfig) {
			c.Authorization = &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "00g12345678901234567", Role: "operator"}}}
		}},
		{name: "Okta group name rejected", auth: oktaAuthentication, change: func(c *configv1.ServerConfig) {
			c.Authorization = &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "operators", Role: "operator"}}}
		}},
		{name: "Google group ID", auth: googleAuthentication, valid: true, change: func(c *configv1.ServerConfig) {
			c.Authorization = &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "01abc234", Role: "operator"}}}
		}},
		{name: "Google group email rejected", auth: googleAuthentication, change: func(c *configv1.ServerConfig) {
			c.Authorization = &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "operators@example.com", Role: "operator"}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := executionSigningSchemaConfig()
			cfg.Authentication = test.auth()
			if test.change != nil {
				test.change(cfg)
			}
			if err := validator.Validate(cfg); (err == nil) != test.valid {
				t.Fatalf("validation = %v, want valid %t", err, test.valid)
			}
		})
	}
}

func TestDirectoryJSONRejectsUnknownAndMultipleSources(t *testing.T) {
	for _, data := range []string{
		`{"authentication":{"okta":{},"google":{}}}`,
		`{"authentication":{"google":{"privateKey":"inline secret"}}}`,
		`{"authentication":{"okta":{"apiToken":"inline secret"}}}`,
		`{"authentication":{"scim":{"freshnessSeconds":120}}}`,
		`{"authentication":{"keycloak":{"upstream":{"skipFreshness":true}}}}`,
	} {
		if err := protojson.Unmarshal([]byte(data), &configv1.ServerConfig{}); err == nil {
			t.Fatalf("accepted invalid configuration %s", data)
		}
	}
}

func TestDirectoryProtectedKeyResources(t *testing.T) {
	for _, auth := range []struct {
		name string
		new  func() *configv1.AuthenticationConfig
	}{{"Okta", oktaAuthentication}, {"Google", googleAuthentication}} {
		t.Run(auth.name, func(t *testing.T) {
			dir := databaseFixture(t)
			writeFixtureFile(t, dir, "login-secret", []byte(" login-value\n"))
			// Key parsing is the provider constructor's responsibility; this checks the protected descriptor boundary.
			key := []byte("protected directory key bytes\n")
			writeFixtureFile(t, dir, "directory-key.pem", key)
			doc := &Document{base: dir, Proto: &configv1.ServerConfig{Authentication: auth.new()}}
			resources := &Resources{}
			if err := doc.authenticationSecrets(resources); err != nil {
				t.Fatal(err)
			}
			if resources.ClientSecret != "login-value" || !bytes.Equal(resources.DirectoryPrivateKeyPEM, key) || resources.DirectoryClientSecret != "" {
				t.Fatal("directory key resource or login credential changed")
			}
			if err := os.Chmod(filepath.Join(dir, "directory-key.pem"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := doc.authenticationSecrets(&Resources{}); err == nil {
				t.Fatal("world-readable directory private key accepted")
			}
			if err := os.Chmod(filepath.Join(dir, "directory-key.pem"), 0600); err != nil {
				t.Fatal(err)
			}
			writeFixtureFile(t, dir, "directory-key.pem", []byte(" \n"))
			if err := doc.authenticationSecrets(&Resources{}); err == nil {
				t.Fatal("empty directory private key accepted")
			}
		})
	}
}

func TestBrokerProtectedSecretResource(t *testing.T) {
	dir := databaseFixture(t)
	writeFixtureFile(t, dir, "login-secret", []byte("login-value"))
	writeFixtureFile(t, dir, "broker-secret", []byte("broker-value"))
	writeFixtureFile(t, dir, "upstream-secret", []byte("upstream-value"))
	cfg := executionSigningSchemaConfig()
	keycloak := cfg.Authentication.GetKeycloak()
	keycloak.ClientSecretFile = "login-secret"
	keycloak.DirectoryClientSecretFile = "broker-secret"
	keycloak.Upstream = &configv1.KeycloakBrokerUpstream{Alias: "original", ConnectorId: "original", Issuer: "https://upstream.example/realms/original", DirectoryClientId: "reader", DirectoryClientSecretFile: "upstream-secret"}
	doc := &Document{base: dir, Proto: cfg}
	resources := &Resources{}
	if err := doc.authenticationSecrets(resources); err != nil {
		t.Fatal(err)
	}
	if resources.DirectoryClientSecret != "broker-value" || resources.BrokerDirectoryClientSecret != "upstream-value" {
		t.Fatal("broker and authoritative upstream credentials were conflated")
	}
	if err := os.Chmod(filepath.Join(dir, "upstream-secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := doc.authenticationSecrets(&Resources{}); err == nil {
		t.Fatal("world-readable upstream secret accepted")
	}
}

func TestBrokerConfigurationSchema(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&configv1.KeycloakDirectory{}))
	if err != nil {
		t.Fatal(err)
	}
	base := executionSigningSchemaConfig().Authentication.GetKeycloak()
	base.Upstream = &configv1.KeycloakBrokerUpstream{
		Alias: "original", ConnectorId: "original", Issuer: "https://upstream.example/realms/original",
		DirectoryClientId: "reader", DirectoryClientSecretFile: "upstream-secret",
	}
	for _, test := range []struct {
		name   string
		change func(*configv1.KeycloakDirectory)
		valid  bool
	}{
		{name: "distinct original authority", valid: true},
		{name: "broker copy not original authority", change: func(c *configv1.KeycloakDirectory) { c.Upstream.Issuer = c.Issuer }},
		{name: "insecure upstream", change: func(c *configv1.KeycloakDirectory) { c.Upstream.Issuer = "http://upstream.example/realms/original" }},
		{name: "missing alias", change: func(c *configv1.KeycloakDirectory) { c.Upstream.Alias = "" }},
		{name: "missing connector", change: func(c *configv1.KeycloakDirectory) { c.Upstream.ConnectorId = "" }},
		{name: "missing upstream credential", change: func(c *configv1.KeycloakDirectory) { c.Upstream.DirectoryClientSecretFile = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := proto.CloneOf(base)
			if test.change != nil {
				test.change(cfg)
			}
			if err := validator.Validate(cfg); (err == nil) != test.valid {
				t.Fatalf("validation = %v, want valid %t", err, test.valid)
			}
		})
	}
}
