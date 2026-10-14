// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

func monitorStartResults(nodes ...uint32) map[string]dbus.Variant {
	streams := make([]portalStream, 0, len(nodes))
	for _, node := range nodes {
		streams = append(streams, portalStream{Node: node, Properties: map[string]dbus.Variant{"size": dbus.MakeVariant(struct{ Width, Height int32 }{1280, 800})}})
	}
	return map[string]dbus.Variant{"streams": dbus.MakeVariant(streams)}
}

func TestGrantedMonitorDescriptorsAreBoundedAndSelectionNeverFallsBack(t *testing.T) {
	streams, err := grantedStreams(monitorStartResults(51, 72))
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 2 || streams[0].ID != "monitor-1" || streams[1].ID != "monitor-2" || streams[1].NodeID != 72 {
		t.Fatalf("descriptors = %+v", streams)
	}
	grant := &portalGrant{streams: streams, stream: streams[0]}
	if err := grant.SelectStream("monitor-2"); err != nil {
		t.Fatal(err)
	}
	if grant.stream.NodeID != 72 || grant.stream.Width != 1280 || grant.stream.Height != 800 {
		t.Fatalf("wrong selected pointer space: %+v", grant.stream)
	}
	if err := grant.SelectStream("arbitrary-pipewire-node"); err == nil {
		t.Fatal("ungranted selection accepted")
	}
	if grant.stream.NodeID != 72 {
		t.Fatal("failed selection silently fell back")
	}
	for _, nodes := range [][]uint32{{}, {0}, {51, 51}, {1, 2, 3, 4, 5, 6, 7, 8, 9}} {
		if _, err := grantedStreams(monitorStartResults(nodes...)); err == nil {
			t.Fatalf("invalid grants accepted: %v", nodes)
		}
	}
	if _, err := grantedStreams(map[string]dbus.Variant{"streams": dbus.MakeVariant([]portalStream{{Node: 12, Properties: map[string]dbus.Variant{}}})}); err == nil {
		t.Fatal("unknown geometry invented")
	}
}
