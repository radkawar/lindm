package labhost

import (
	"slices"
	"strings"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestSelectPreference(t *testing.T) {
	foreign := fixtureHost("foreign", "/tmp/lab")
	foreign.Architectures = []string{"arm64"}
	tcg := fixtureHost("tcg", "/tmp/lab")
	tcg.Kvm = false
	container := fixtureHost("container", "/tmp/lab")
	container.Runtime = "container"
	container.RunnerImage = "registry/runner@sha256:" + strings.Repeat("b", 64)
	first := fixtureHost("first", "/tmp/lab")
	second := fixtureHost("second", "/tmp/lab")
	cfg := &labv1.LabConfig{Hosts: []*labv1.LabHost{foreign, tcg, container, first, second}}
	selected, err := Select(cfg, &Requirements{Architecture: "x86_64"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, host := range selected {
		names = append(names, host.Name)
	}
	if !slices.Equal(names, []string{"first", "second", "container", "tcg", "foreign"}) {
		t.Fatalf("candidate preference: %v", names)
	}
	if cfg.Hosts[0] != foreign {
		t.Fatal("selection reordered configuration")
	}
	selected, err = Select(cfg, &Requirements{Architecture: "arm64", RequireKVM: true})
	if err != nil || len(selected) != 1 || selected[0] != foreign {
		t.Fatalf("native arm64 KVM selection: %v, %v", selected, err)
	}
}

func TestSelectOverrideAndCapacity(t *testing.T) {
	host := fixtureHost("local", "/tmp/lab")
	cfg := &labv1.LabConfig{Hosts: []*labv1.LabHost{host}}
	for _, req := range []*Requirements{
		{Host: "unknown"},
		{Architecture: "mips"},
		{Architecture: "arm64", RequireKVM: true},
		{Vcpus: 3},
		{MemoryMib: 4097},
	} {
		if _, err := Select(cfg, req); err == nil {
			t.Fatalf("ineligible request accepted: %+v", req)
		}
	}
	for _, req := range []*Requirements{
		nil,
		{Host: "local", Architecture: "amd64", RequireKVM: true},
		{Host: "local", Architecture: "aarch64"},
		{MemoryMib: 4096, Vcpus: 2},
	} {
		selected, err := Select(cfg, req)
		if err != nil || len(selected) != 1 || selected[0] != host {
			t.Fatalf("eligible request %+v: %v, %v", req, selected, err)
		}
	}
}

func TestNormalizeArchitecture(t *testing.T) {
	for input, want := range map[string]string{"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"} {
		got, err := NormalizeArchitecture(input)
		if err != nil || got != want {
			t.Fatalf("normalize %q: %q, %v", input, got, err)
		}
	}
	if _, err := NormalizeArchitecture("AMD64"); err == nil {
		t.Fatal("unsupported architecture accepted")
	}
}
