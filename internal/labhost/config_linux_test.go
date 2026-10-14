// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestValidateHosts(t *testing.T) {
	cases := []struct {
		name   string
		change func(*labv1.LabConfig)
	}{
		{"no-hosts", func(c *labv1.LabConfig) { c.Hosts = nil }},
		{"nil-host", func(c *labv1.LabConfig) { c.Hosts[0] = nil }},
		{"duplicate-name", func(c *labv1.LabConfig) { c.Hosts = append(c.Hosts, fixtureHost("local", "/tmp/lab")) }},
		{"invalid-name", func(c *labv1.LabConfig) { c.Hosts[0].Name = "../host" }},
		{"invalid-transport", func(c *labv1.LabConfig) { c.Hosts[0].Transport = "http" }},
		{"ssh-without-alias", func(c *labv1.LabConfig) { c.Hosts[0].Transport = "ssh" }},
		{"local-with-alias", func(c *labv1.LabConfig) { c.Hosts[0].SshAlias = "remote" }},
		{"ssh-option", func(c *labv1.LabConfig) { c.Hosts[0].Transport = "ssh"; c.Hosts[0].SshAlias = "-Ffile" }},
		{"noncanonical-architecture", func(c *labv1.LabConfig) { c.Hosts[0].Architectures = []string{"aarch64"} }},
		{"duplicate-architecture", func(c *labv1.LabConfig) { c.Hosts[0].Architectures = []string{"arm64", "arm64"} }},
		{"no-architecture", func(c *labv1.LabConfig) { c.Hosts[0].Architectures = nil }},
		{"zero-slots", func(c *labv1.LabConfig) { c.Hosts[0].MaxGuests = 0 }},
		{"zero-vcpus", func(c *labv1.LabConfig) { c.Hosts[0].MaxVcpus = 0 }},
		{"zero-memory", func(c *labv1.LabConfig) { c.Hosts[0].MaxMemoryMib = 0 }},
		{"relative-directory", func(c *labv1.LabConfig) { c.Hosts[0].WorkDirectory = "work/lab" }},
		{"shell-directory", func(c *labv1.LabConfig) { c.Hosts[0].WorkDirectory = "~/$(id)" }},
		{"home-escape", func(c *labv1.LabConfig) { c.Hosts[0].WorkDirectory = "~/../other" }},
		{"dot-directory", func(c *labv1.LabConfig) { c.Hosts[0].WorkDirectory = "/tmp/./lab" }},
		{"invalid-runtime", func(c *labv1.LabConfig) { c.Hosts[0].Runtime = "docker" }},
		{"container-without-image", func(c *labv1.LabConfig) { c.Hosts[0].Runtime = "container" }},
		{"container-tag", func(c *labv1.LabConfig) {
			c.Hosts[0].Runtime = "container"
			c.Hosts[0].RunnerImage = "registry/runner:latest"
		}},
		{"native-with-image", func(c *labv1.LabConfig) { c.Hosts[0].RunnerImage = "registry/runner@sha256:" + strings.Repeat("a", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &labv1.LabConfig{Hosts: []*labv1.LabHost{fixtureHost("local", "/tmp/lab")}}
			tc.change(cfg)
			if err := Validate(cfg); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	if err := Validate(nil); err == nil {
		t.Fatal("nil config accepted")
	}
	for _, transport := range []string{"local", "ssh"} {
		for _, runtime := range []string{"native", "container"} {
			host := fixtureHost("valid", "~/work/lindm-lab")
			host.Transport, host.Runtime = transport, runtime
			if transport == "ssh" {
				host.SshAlias = "configured-alias"
			}
			if runtime == "container" {
				host.RunnerImage = "registry.example:5000/lab/runner@sha256:" + strings.Repeat("a", 64)
			}
			if err := Validate(&labv1.LabConfig{Hosts: []*labv1.LabHost{host}}); err != nil {
				t.Fatalf("valid %s/%s config: %v", transport, runtime, err)
			}
		}
	}
}

func TestLoadPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LINDM_LAB_CONFIG", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 1 || cfg.Hosts[0].Name != "local" || cfg.Hosts[0].Architectures[0] != runtime.GOARCH || cfg.Hosts[0].Runtime != "native" {
		t.Fatalf("unexpected local defaults: %v", cfg)
	}
	// Built-in configuration must require native KVM even on a machine without
	// usable /dev/kvm; availability is reported separately, never a TCG default.
	if !cfg.Hosts[0].Kvm {
		t.Fatal("built-in local configuration silently downgraded native KVM")
	}
	if _, err := Select(cfg, &Requirements{Architecture: runtime.GOARCH, RequireKVM: true}); err != nil {
		t.Fatalf("built-in native KVM requirement: %v", err)
	}
	defaultPath := filepath.Join(home, ".config", "lindm", "lab.json")
	writeConfig(t, defaultPath, fixtureHost("home", "~/work/lindm-lab"))
	cfg, err = Load()
	if err != nil || cfg.Hosts[0].Name != "home" {
		t.Fatalf("home config: %v, %v", cfg, err)
	}
	explicitPath := filepath.Join(home, "explicit.json")
	writeConfig(t, explicitPath, fixtureHost("explicit", "/tmp/lab"))
	t.Setenv("LINDM_LAB_CONFIG", explicitPath)
	cfg, err = Load()
	if err != nil || cfg.Hosts[0].Name != "explicit" {
		t.Fatalf("explicit config: %v, %v", cfg, err)
	}
	t.Setenv("LINDM_LAB_CONFIG", filepath.Join(home, "missing.json"))
	if _, err := Load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit missing file must not fall back: %v", err)
	}
	t.Setenv("LINDM_LAB_CONFIG", "")
	if err := os.WriteFile(defaultPath, []byte(`{"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("invalid home config fell back to local defaults")
	}
}

func TestLoadFileRejectsInvalidInput(t *testing.T) {
	for _, contents := range []string{`{"hosts":[],"typo":true}`, `{"hosts":[],"hosts":[]}`, `{`, strings.Repeat(" ", maxConfigBytes+1)} {
		filename := filepath.Join(t.TempDir(), "lab.json")
		if err := os.WriteFile(filename, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(filename); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if _, err := LoadFile(t.TempDir()); err == nil {
		t.Fatal("directory accepted as config")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(fifo); err == nil {
		t.Fatal("FIFO accepted as config")
	}
}

func TestDefaultCapacity(t *testing.T) {
	for _, tc := range []struct {
		cpus   int
		memory uint64
		slots  uint32
	}{
		{1, 1024, 1},
		{8, 65536, 1},
		{64, 16384, 3},
		{16, 32768, 3},
		{24, 62 * 1024, 4},
	} {
		for _, architecture := range []string{"amd64", "arm64"} {
			for _, kvm := range []bool{true, false} {
				cfg := defaultConfig(architecture, tc.cpus, tc.memory, kvm)
				if err := Validate(cfg); err != nil {
					t.Fatal(err)
				}
				host := cfg.Hosts[0]
				if host.MaxGuests != tc.slots || host.MaxVcpus != 4 || host.MaxMemoryMib != 4096 || host.Kvm != kvm || host.Architectures[0] != architecture {
					t.Fatalf("CPU %d memory %d: %v", tc.cpus, tc.memory, host)
				}
			}
		}
	}
}

func TestResolveWorkDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	host := fixtureHost("remote", "~/work/lindm-lab")
	host.Transport, host.SshAlias = "ssh", "remote"
	filename := filepath.Join(t.TempDir(), "lab.json")
	writeConfig(t, filename, host)
	cfg, err := LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hosts[0].WorkDirectory != "~/work/lindm-lab" {
		t.Fatal("loader expanded remote host's home on orchestration machine")
	}
	resolved, err := ResolveWorkDirectory(cfg.Hosts[0])
	if err != nil || resolved != filepath.Join(home, "work", "lindm-lab") {
		t.Fatalf("resolve execution-host home: %q, %v", resolved, err)
	}
}
