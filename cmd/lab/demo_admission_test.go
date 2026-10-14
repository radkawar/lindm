// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestDemoBatchFootprintsUseGlobalHostOrder(t *testing.T) {
	a := &labv1.LabHost{Name: "a", MaxGuests: 2}
	b := &labv1.LabHost{Name: "b", MaxGuests: 2}
	bindings := []*labv1.DemoBinding{{Host: b}, {Host: a}, {Host: b}, {Host: a}}
	for range 2 {
		requests, err := demoFootprints(bindings, "/repo", "/lab")
		if err != nil {
			t.Fatal(err)
		}
		if len(requests) != 2 || requests[0].Host.GetName() != "a" || requests[1].Host.GetName() != "b" || requests[0].Guests != 2 || requests[1].Guests != 2 {
			t.Fatalf("incorrect whole-host reservation order: %+v", requests)
		}
		slices.Reverse(bindings)
	}
}

func TestDemoBatchRejectsImpossibleOrAmbiguousNamespace(t *testing.T) {
	host := &labv1.LabHost{Name: "one", MaxGuests: 1}
	bindings := []*labv1.DemoBinding{{Host: host}, {Host: host}}
	if _, err := demoFootprints(bindings, "repo", "lab"); err == nil || !strings.Contains(err.Error(), "exceeds capacity") {
		t.Fatalf("impossible footprint error = %v", err)
	}
	other := proto.CloneOf(host)
	other.MaxGuests = 2
	bindings[1].Host = other
	if _, err := demoFootprints(bindings, "repo", "lab"); err == nil || !strings.Contains(err.Error(), "conflicting bound capacity namespace") {
		t.Fatalf("ambiguous namespace error = %v", err)
	}
}
