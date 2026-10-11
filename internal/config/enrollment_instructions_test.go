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

func TestNativeRepositoryConfiguration(t *testing.T) {
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
		{name: "optional publication absent", valid: true, change: func(c *configv1.ServerConfig) { c.ReleaseRepository.NativeRepositories = nil }},
		{name: "one family only", valid: true, change: func(c *configv1.ServerConfig) { c.ReleaseRepository.NativeRepositories.RpmSigningKeyFingerprint = nil }},
		{name: "v6 fingerprint", valid: true, change: func(c *configv1.ServerConfig) {
			c.ReleaseRepository.NativeRepositories.RpmSigningKeyFingerprint = proto.String(strings.Repeat("A", 64))
		}},
		{name: "empty fingerprint", change: func(c *configv1.ServerConfig) {
			c.ReleaseRepository.NativeRepositories.RpmSigningKeyFingerprint = proto.String("")
		}},
		{name: "short key ID", change: func(c *configv1.ServerConfig) {
			c.ReleaseRepository.NativeRepositories.AptSigningKeyFingerprint = proto.String("0123456789ABCDEF")
		}},
		{name: "lowercase fingerprint", change: func(c *configv1.ServerConfig) {
			c.ReleaseRepository.NativeRepositories.AptSigningKeyFingerprint = proto.String(strings.Repeat("a", 40))
		}},
		{name: "fingerprint injection", change: func(c *configv1.ServerConfig) {
			c.ReleaseRepository.NativeRepositories.ArchSigningKeyFingerprint = proto.String(strings.Repeat("A", 40) + "\n")
		}},
		{name: "empty device origin", change: func(c *configv1.ServerConfig) { c.DevicePublicUrl = proto.String("") }},
		{name: "device origin path", change: func(c *configv1.ServerConfig) { c.DevicePublicUrl = proto.String("https://devices.example/rpc") }},
		{name: "bootstrap missing device origin", change: func(c *configv1.ServerConfig) { c.DevicePublicUrl = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := executionSigningSchemaConfig()
			cfg.ReleaseRepository = &configv1.ReleaseRepositoryConfig{
				Directory: "release-repository",
				NativeRepositories: &configv1.NativeRepositoriesConfig{
					AptSigningKeyFingerprint: proto.String(strings.Repeat("A", 40)),
					RpmSigningKeyFingerprint: proto.String(strings.Repeat("B", 40)),
				},
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
				t.Fatal("loading changed native signer configuration")
			}
		})
	}
}

func TestExternalEnrollmentRepositoryConfigurationRejected(t *testing.T) {
	for _, encoded := range []string{
		`{"enrollmentInstructions":{"aptRepository":{"baseUrl":"https://outside.example/apt"}}}`,
		`{"releaseRepository":{"directory":"repo","nativeRepositories":{"baseUrl":"https://outside.example/rpm"}}}`,
	} {
		var cfg configv1.ServerConfig
		if err := protojson.Unmarshal([]byte(encoded), &cfg); err == nil {
			t.Fatal("obsolete external repository configuration was accepted")
		}
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
