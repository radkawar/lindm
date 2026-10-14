// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"errors"
	"fmt"
	"runtime"
	"slices"

	labv1 "lindm/gen/lindm/lab/v1"
)

// Requirements describes one guest. Zero resource values select the existing
// ordinary cloud defaults (2 vCPU, 2048 MiB); encrypted callers supply 4096 MiB.
// Host is an exact configured name, never an implicit SSH destination.
type Requirements struct {
	Host         string
	Architecture string
	Vcpus        uint32
	MemoryMib    uint32
	RequireKVM   bool
}

// NormalizeArchitecture maps image/uname spellings to canonical Go names.
// Configured architectures themselves must already use canonical names.
func NormalizeArchitecture(architecture string) (string, error) {
	switch architecture {
	case "amd64", "x86_64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("lab hosts: unsupported architecture %q", architecture)
	}
}

// Select returns eligible hosts in stable preference order: native-architecture
// KVM before native-architecture TCG before foreign-architecture TCG; within each
// tier native runtime precedes container runtime. Configuration order breaks ties.
// Selection does not reserve capacity. The caller must acquire a local lease on
// the selected execution host, trying subsequent candidates if appropriate.
func Select(cfg *labv1.LabConfig, requirements *Requirements) ([]*labv1.LabHost, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	var req Requirements
	if requirements != nil {
		req = *requirements
	}
	if req.Architecture == "" {
		req.Architecture = runtime.GOARCH
	}
	architecture, err := NormalizeArchitecture(req.Architecture)
	if err != nil {
		return nil, err
	}
	if req.Vcpus == 0 {
		req.Vcpus = 2
	}
	if req.MemoryMib == 0 {
		req.MemoryMib = 2048
	}
	candidates := make([]*labv1.LabHost, 0, len(cfg.Hosts))
	found := req.Host == ""
	for _, host := range cfg.Hosts {
		if req.Host != "" && req.Host != host.Name {
			continue
		}
		found = true
		if host.MaxVcpus < req.Vcpus || host.MaxMemoryMib < req.MemoryMib {
			continue
		}
		if req.RequireKVM && (!host.Kvm || !slices.Contains(host.Architectures, architecture)) {
			continue
		}
		candidates = append(candidates, host)
	}
	if !found {
		return nil, fmt.Errorf("lab hosts: unknown host %q", req.Host)
	}
	if len(candidates) == 0 {
		return nil, errors.New("lab hosts: no host satisfies guest architecture, acceleration and resource requirements")
	}
	slices.SortStableFunc(candidates, func(a, b *labv1.LabHost) int {
		return preference(a, architecture) - preference(b, architecture)
	})
	return candidates, nil
}

func preference(host *labv1.LabHost, architecture string) int {
	rank := 4 // Foreign guests always use TCG, even on KVM-capable hosts.
	if slices.Contains(host.Architectures, architecture) {
		rank = 2
		if host.Kvm {
			rank = 0
		}
	}
	if host.Runtime == "container" {
		rank++
	}
	return rank
}
