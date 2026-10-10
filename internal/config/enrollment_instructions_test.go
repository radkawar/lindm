package config

import (
	"path/filepath"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestEnrollmentInstructionsConfiguration(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&configv1.ServerConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*configv1.ServerConfig)
		valid  bool
	}{
		{name: "configured", valid: true},
		{name: "optional configuration absent", valid: true, change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions = nil }},
		{name: "repositories absent", valid: true, change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions = &configv1.EnrollmentInstructionsConfig{} }},
		{name: "v6 fingerprint", valid: true, change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.DnfRepository.SigningKeyFingerprint = strings.Repeat("A", 64)
		}},
		{name: "HTTP apt base", change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.AptRepository.BaseUrl = "http://packages.example/apt"
		}},
		{name: "HTTP dnf key", change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.DnfRepository.SigningKeyUrl = "http://packages.example/key.asc"
		}},
		{name: "apt URL credentials", change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.AptRepository.BaseUrl = "https://user:password@packages.example/apt"
		}},
		{name: "dnf URL query", change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.DnfRepository.BaseUrl = "https://packages.example/rpm?token=secret"
		}},
		{name: "apt key fragment", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.AptRepository.SigningKeyUrl += "#key" }},
		{name: "dnf line injection", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.DnfRepository.BaseUrl += "\ngpgcheck=0" }},
		{name: "missing apt key", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.AptRepository.SigningKeyUrl = "" }},
		{name: "missing dnf base", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.DnfRepository.BaseUrl = "" }},
		{name: "missing fingerprint", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.DnfRepository.SigningKeyFingerprint = "" }},
		{name: "short key ID", change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.AptRepository.SigningKeyFingerprint = "0123456789ABCDEF"
		}},
		{name: "lowercase fingerprint", change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.AptRepository.SigningKeyFingerprint = strings.Repeat("a", 40)
		}},
		{name: "fingerprint injection", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.DnfRepository.SigningKeyFingerprint += "\n" }},
		{name: "missing suite", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.AptRepository.Suite = "" }},
		{name: "suite injection", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.AptRepository.Suite = "stable\nTrusted: yes" }},
		{name: "no components", change: func(c *configv1.ServerConfig) { c.EnrollmentInstructions.AptRepository.Components = nil }},
		{name: "duplicate components", change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.AptRepository.Components = []string{"main", "main"}
		}},
		{name: "component injection", change: func(c *configv1.ServerConfig) {
			c.EnrollmentInstructions.AptRepository.Components = []string{"main trusted=yes"}
		}},
		{name: "empty device origin", change: func(c *configv1.ServerConfig) { c.DevicePublicUrl = proto.String("") }},
		{name: "device origin path", change: func(c *configv1.ServerConfig) { c.DevicePublicUrl = proto.String("https://devices.example/rpc") }},
		{name: "bootstrap missing device origin", change: func(c *configv1.ServerConfig) { c.DevicePublicUrl = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := executionSigningSchemaConfig()
			cfg.EnrollmentInstructions = &configv1.EnrollmentInstructionsConfig{
				AptRepository: &configv1.EnrollmentAPTRepositoryConfig{BaseUrl: "https://packages.example/apt", SigningKeyUrl: "https://packages.example/key.asc", SigningKeyFingerprint: strings.Repeat("A", 40), Suite: "stable", Components: []string{"main"}},
				DnfRepository: &configv1.EnrollmentDNFRepositoryConfig{BaseUrl: "https://packages.example/rpm", SigningKeyUrl: "https://packages.example/key.asc", SigningKeyFingerprint: strings.Repeat("B", 40)},
			}
			if test.change != nil {
				test.change(cfg)
			}
			if err := validator.Validate(cfg); (err == nil) != test.valid {
				t.Fatalf("validation = %v, want valid %t", err, test.valid)
			}
			encoded, err := protojson.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			writeFixtureFile(t, dir, "server.json", encoded)
			document, err := Load(filepath.Join(dir, "server.json"))
			if (err == nil) != test.valid {
				t.Fatalf("load = %v, want valid %t", err, test.valid)
			}
			if test.valid && !proto.Equal(cfg, document.Proto) {
				t.Fatal("loading changed authoritative enrollment configuration")
			}
		})
	}
}

func TestExecutionBootstrapRetainsExactPublicDocuments(t *testing.T) {
	fixture := newExecutionConfigFixture(t)
	resources, err := fixture.document.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer resources.HTTPClient.CloseIdleConnections()
	for name, actual := range map[string][]byte{
		"execution-root.json": resources.ExecutionBootstrap.RootJSON,
		"bootstrap.dsse.json": resources.ExecutionBootstrap.Envelope,
	} {
		if string(actual) != string(executionConfigFile(t, fixture.document.base, name)) {
			t.Fatalf("%s was replaced or reserialized", name)
		}
	}
}
