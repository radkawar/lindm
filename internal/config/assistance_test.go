// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/x509"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func TestResolveAssistanceRelay(t *testing.T) {
	relay := func() *configv1.AssistanceConfig {
		return &configv1.AssistanceConfig{Relay: &configv1.AssistanceRelayConfig{
			Listener:     &configv1.ListenerConfig{Address: "0.0.0.0", Port: 3478},
			RelayAddress: "192.0.2.10", RelayPortMin: 49160, RelayPortMax: 49200,
			Urls: []string{"turn:relay.example:3478?transport=udp"}, Realm: "relay.example",
		}}
	}
	for _, test := range []struct {
		name     string
		change   func(*configv1.ServerConfig)
		accepted bool
	}{
		{name: "absent", accepted: true, change: func(c *configv1.ServerConfig) { c.Assistance = nil }},
		{name: "configured", accepted: true},
		{name: "independent capability ceiling", accepted: true, change: func(c *configv1.ServerConfig) {
			c.Assistance.PolicyCeiling = &agentv1.AssistancePolicy{Clipboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, Keyboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, Display: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON}
		}},
		{name: "unknown capability mode", change: func(c *configv1.ServerConfig) {
			c.Assistance.PolicyCeiling = &agentv1.AssistancePolicy{Messages: agentv1.AssistancePolicyMode(99)}
		}},
		{name: "files require explicit limits", change: func(c *configv1.ServerConfig) {
			c.Assistance.PolicyCeiling = &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON}
		}},
		{name: "bounded files ceiling", accepted: true, change: func(c *configv1.ServerConfig) {
			c.Assistance.PolicyCeiling = &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, FileLimits: &agentv1.AssistanceFilePolicy{MaxFileBytes: 1024, MaxSessionBytes: 4096, AllowedMimeTypes: []string{"text/plain"}, AllowedExtensions: []string{".txt"}}}
		}},
		{name: "files hard bound", change: func(c *configv1.ServerConfig) {
			c.Assistance.PolicyCeiling = &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, FileLimits: &agentv1.AssistanceFilePolicy{MaxFileBytes: 16777217, MaxSessionBytes: 67108864, AllowedMimeTypes: []string{"text/plain"}, AllowedExtensions: []string{".txt"}}}
		}},
		{name: "files unsupported type", change: func(c *configv1.ServerConfig) {
			c.Assistance.PolicyCeiling = &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, FileLimits: &agentv1.AssistanceFilePolicy{MaxFileBytes: 1024, MaxSessionBytes: 4096, AllowedMimeTypes: []string{"application/x-unimplemented"}, AllowedExtensions: []string{".bin"}}}
		}},
		{name: "wildcard relay address", change: func(c *configv1.ServerConfig) { c.Assistance.Relay.RelayAddress = "0.0.0.0" }},
		{name: "IPv6 relay address", change: func(c *configv1.ServerConfig) { c.Assistance.Relay.RelayAddress = "2001:db8::1" }},
		{name: "link-local relay address", change: func(c *configv1.ServerConfig) { c.Assistance.Relay.RelayAddress = "169.254.1.1" }},
		{name: "exposed loopback relay address", change: func(c *configv1.ServerConfig) { c.Assistance.Relay.RelayAddress = "127.0.0.1" }},
		{name: "local lab relay", accepted: true, change: func(c *configv1.ServerConfig) {
			c.Assistance.Relay.RelayAddress = "127.0.0.1"
			c.Assistance.Relay.Listener.Address = "127.0.0.1"
		}},
		{name: "maximum relay port span", accepted: true, change: func(c *configv1.ServerConfig) { c.Assistance.Relay.RelayPortMax = 53255 }},
		{name: "oversized relay port span", change: func(c *configv1.ServerConfig) { c.Assistance.Relay.RelayPortMax = 53256 }},
		{name: "listener inside relay ports", change: func(c *configv1.ServerConfig) { c.Assistance.Relay.Listener.Port = 49170 }},
		{name: "admin listener port", change: func(c *configv1.ServerConfig) { c.Assistance.Relay.Listener.Port = c.AdminListener.Port }},
		{name: "distinct address same port", accepted: true, change: func(c *configv1.ServerConfig) {
			c.Assistance.Relay.Listener = &configv1.ListenerConfig{Address: "192.0.2.10", Port: c.AdminListener.Port}
		}},
		{name: "missing relay", change: func(c *configv1.ServerConfig) { c.Assistance.Relay = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := databaseFixture(t)
			writeCertificate(t, dir, "root", true, nil, nil)
			writeCertificate(t, dir, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
			writeCertificate(t, dir, "server", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
			writeCertificate(t, dir, "device", true, nil, nil)
			writeFixtureFile(t, dir, "oidc-secret", []byte("isolated-test-credential"))
			cfg := &configv1.ServerConfig{
				PublicUrl:      "https://localhost",
				AdminListener:  &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444},
				DeviceListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18445},
				Database:       &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 2},
				Tls:            &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
				DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: "device.crt", PrivateKeyFile: "device.key"},
				Authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{ClientSecretFile: "oidc-secret", DirectoryClientSecretFile: "oidc-secret"}}},
				Assistance:     relay(),
			}
			if test.change != nil {
				test.change(cfg)
			}
			resources, err := (&Document{base: dir, Proto: cfg}).Resolve()
			if err == nil {
				resources.HTTPClient.CloseIdleConnections()
				if !proto.Equal(resources.Proto.GetAssistance().GetPolicyCeiling(), cfg.GetAssistance().GetPolicyCeiling()) {
					t.Fatal("resource resolution changed the configured policy ceiling")
				}
			}
			if (err == nil) != test.accepted {
				t.Fatalf("resolve = %v, want accepted %t", err, test.accepted)
			}
		})
	}
}
