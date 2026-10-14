// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
)

// demoBatchRequests orders capacity namespaces globally, not by device order.
// Every demo takes each complete host footprint in that order before launching
// any device; two multi-host demos therefore cannot form a hold-and-wait cycle.
func (r *demoRun) demoBatchRequests() ([]labhost.BatchRequest, error) {
	return demoFootprints(r.state.GetBindings(), r.options.build, r.options.lab)
}

func demoFootprints(bindings []*labv1.DemoBinding, repository, binary string) ([]labhost.BatchRequest, error) {
	byHost := make(map[string]labhost.BatchRequest)
	for _, binding := range bindings {
		host := binding.GetHost()
		if host == nil || host.GetName() == "" {
			return nil, errors.New("demo: bound host identity is required for batch admission")
		}
		request, exists := byHost[host.GetName()]
		if exists && !proto.Equal(request.Host, host) {
			return nil, fmt.Errorf("demo: conflicting bound capacity namespace %s", host.GetName())
		}
		request.Host, request.Repository, request.LabBinary = host, repository, binary
		request.Guests++
		if request.Guests > host.GetMaxGuests() {
			return nil, fmt.Errorf("demo: host %s footprint %d exceeds capacity %d", host.GetName(), request.Guests, host.GetMaxGuests())
		}
		byHost[host.GetName()] = request
	}
	names := make([]string, 0, len(byHost))
	for name := range byHost {
		names = append(names, name)
	}
	slices.Sort(names)
	requests := make([]labhost.BatchRequest, 0, len(names))
	for _, name := range names {
		requests = append(requests, byHost[name])
	}
	return requests, nil
}
