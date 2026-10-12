package main

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/demolab"
	"lindm/internal/labhost"
)

// planDemoBindings reserves the demo's retained footprint, not today's free
// slots. FIFO admission still waits for unrelated transient workloads. An
// augmenting placement can move an unpinned device aside for a later pinned one.
func planDemoBindings(name string, spec *demolab.Spec, cfg *labv1.LabConfig) (*labv1.DemoState, error) {
	eligible := make([][]*labv1.LabHost, len(spec.Devices))
	for i, device := range spec.Devices {
		arch, err := labhost.NormalizeArchitecture(device.Manifest.GetArchitecture())
		if err != nil {
			return nil, err
		}
		hosts, err := labhost.Select(cfg, &labhost.Requirements{Host: device.Config.GetHost(), Architecture: arch, Vcpus: 2, MemoryMib: 4096, RequireKVM: true})
		if err != nil {
			return nil, err
		}
		for _, host := range hosts {
			if host.Runtime == "native" {
				eligible[i] = append(eligible[i], host)
			}
		}
	}
	selected := make([]*labv1.LabHost, len(spec.Devices))
	occupied := make(map[string][]int, len(cfg.Hosts))
	var place func(int, map[string]bool) bool
	place = func(device int, visited map[string]bool) bool {
		for _, host := range eligible[device] {
			if visited[host.Name] {
				continue
			}
			visited[host.Name] = true
			residents := occupied[host.Name]
			if len(residents) < int(host.MaxGuests) {
				occupied[host.Name] = append(residents, device)
				selected[device] = host
				return true
			}
			for slot, other := range residents {
				if place(other, visited) {
					residents[slot] = device
					selected[device] = host
					return true
				}
			}
		}
		return false
	}
	for i, device := range spec.Devices {
		if !place(i, make(map[string]bool, len(cfg.Hosts))) {
			return nil, fmt.Errorf("demo device %s cannot fit aggregate native host capacity; change its placement or host max_guests", device.Config.GetKey())
		}
	}
	state := &labv1.DemoState{Bindings: make([]*labv1.DemoBinding, 0, len(spec.Devices))}
	for i, device := range spec.Devices {
		state.Bindings = append(state.Bindings, &labv1.DemoBinding{Key: device.Config.GetKey(), DemoName: name + "-" + device.Config.GetKey(), Host: proto.CloneOf(selected[i]), Device: proto.CloneOf(device.Config), ManifestSha256: device.Manifest.GetSha256()})
	}
	return state, nil
}
