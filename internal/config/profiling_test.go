// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestProfilingConfiguration(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&configv1.ServerConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*configv1.ServerConfig)
		valid  bool
	}{
		{name: "disabled default", valid: true, change: func(c *configv1.ServerConfig) { c.Profiling = nil }},
		{name: "loopback IPv4", valid: true},
		{name: "loopback IPv6", valid: true, change: func(c *configv1.ServerConfig) { c.Profiling.Listener.Address = "::1" }},
		{name: "wildcard IPv4", change: func(c *configv1.ServerConfig) { c.Profiling.Listener.Address = "0.0.0.0" }},
		{name: "wildcard IPv6", change: func(c *configv1.ServerConfig) { c.Profiling.Listener.Address = "::" }},
		{name: "remote", change: func(c *configv1.ServerConfig) { c.Profiling.Listener.Address = "192.0.2.1" }},
		{name: "hostname", change: func(c *configv1.ServerConfig) { c.Profiling.Listener.Address = "localhost" }},
		{name: "missing listener", change: func(c *configv1.ServerConfig) { c.Profiling.Listener = nil }},
		{name: "unspecified port", change: func(c *configv1.ServerConfig) { c.Profiling.Listener.Port = 0 }},
		{name: "admin port", change: func(c *configv1.ServerConfig) { c.Profiling.Listener = c.AdminListener }},
		{name: "device port", change: func(c *configv1.ServerConfig) { c.Profiling.Listener = c.DeviceListener }},
		{name: "zero CPU duration", change: func(c *configv1.ServerConfig) { c.Profiling.CpuProfileSeconds = 0 }},
		{name: "excess CPU duration", change: func(c *configv1.ServerConfig) { c.Profiling.CpuProfileSeconds = 61 }},
		{name: "zero mutex sampling", change: func(c *configv1.ServerConfig) { c.Profiling.MutexProfileFraction = 0 }},
		{name: "excess mutex sampling", change: func(c *configv1.ServerConfig) { c.Profiling.MutexProfileFraction = 1000001 }},
		{name: "zero block sampling", change: func(c *configv1.ServerConfig) { c.Profiling.BlockProfileRateNs = 0 }},
		{name: "excess block sampling", change: func(c *configv1.ServerConfig) { c.Profiling.BlockProfileRateNs = 1000000001 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := executionSigningSchemaConfig()
			cfg.Profiling = &configv1.ProfilingConfig{
				Listener:          &configv1.ListenerConfig{Address: "127.0.0.1", Port: 19090},
				CpuProfileSeconds: 30, MutexProfileFraction: 1, BlockProfileRateNs: 1000000,
			}
			if test.change != nil {
				test.change(cfg)
			}
			if err := validator.Validate(cfg); (err == nil) != test.valid {
				t.Fatalf("validation = %v, want valid %t", err, test.valid)
			}
			data, err := protojson.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			writeFixtureFile(t, dir, "server.json", data)
			document, err := Load(filepath.Join(dir, "server.json"))
			if (err == nil) != test.valid {
				t.Fatalf("load = %v, want valid %t", err, test.valid)
			}
			if test.name == "disabled default" && document.Proto.GetProfiling() != nil {
				t.Fatal("loading enabled absent profiling configuration")
			}
		})
	}
}
