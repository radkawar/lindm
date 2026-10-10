//go:build linux

package inventory

import (
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestDefaultRouteSchemaAvailability(t *testing.T) {
	network := routeTestNetwork()
	validator, err := protovalidate.New(protovalidate.WithMessages(network))
	if err != nil {
		t.Fatal(err)
	}
	// Historical observations have neither field. Their absence must not be
	// rewritten as a successful false observation or rejected by validation.
	if err := validator.Validate(network); err != nil {
		t.Fatalf("historical network observation: %v", err)
	}
	for _, test := range []struct {
		name  string
		value *inventoryv1.ObservedBool
		valid bool
	}{
		{name: "historical absence", valid: true},
		{name: "observed default", value: &inventoryv1.ObservedBool{Status: success, Value: true}, valid: true},
		{name: "observed not default", value: &inventoryv1.ObservedBool{Status: success}, valid: true},
		{name: "unavailable", value: &inventoryv1.ObservedBool{Status: unavailable}, valid: true},
		{name: "permission denied", value: &inventoryv1.ObservedBool{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED}, valid: true},
		{name: "timeout", value: &inventoryv1.ObservedBool{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT}, valid: true},
		{name: "capacity", value: &inventoryv1.ObservedBool{Status: capacity}, valid: true},
		{name: "invalid native table", value: &inventoryv1.ObservedBool{Status: invalid}, valid: true},
		{name: "missing status", value: &inventoryv1.ObservedBool{}},
		{name: "unknown status", value: &inventoryv1.ObservedBool{Status: inventoryv1.CollectionStatus(999)}},
		{name: "unavailable with membership", value: &inventoryv1.ObservedBool{Status: unavailable, Value: true}},
		{name: "denied with membership", value: &inventoryv1.ObservedBool{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED, Value: true}},
		{name: "timeout with membership", value: &inventoryv1.ObservedBool{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT, Value: true}},
		{name: "capacity with membership", value: &inventoryv1.ObservedBool{Status: capacity, Value: true}},
		{name: "invalid with membership", value: &inventoryv1.ObservedBool{Status: invalid, Value: true}},
	} {
		for _, family := range []string{"IPv4", "IPv6"} {
			t.Run(family+"/"+test.name, func(t *testing.T) {
				changed := proto.CloneOf(network)
				iface := changed.Interfaces[1]
				if family == "IPv4" {
					iface.DefaultRouteIpv4 = test.value
				} else {
					iface.DefaultRouteIpv6 = test.value
				}
				err := validator.Validate(changed)
				if (err == nil) != test.valid {
					t.Fatalf("valid = %t, validation error = %v", test.valid, err)
				}
				if !test.valid {
					return
				}
				data, err := proto.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
				var restored inventoryv1.NetworkDetails
				if err := proto.Unmarshal(data, &restored); err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(changed, &restored) {
					t.Fatalf("wire round trip changed route presence/value: %v", &restored)
				}
			})
		}
	}
}

func TestCollectedDefaultRoutesValidate(t *testing.T) {
	network := routeTestNetwork()
	sources := detailSources{readFile: func(path string) ([]byte, error) {
		if path == "/proc/net/route" {
			return []byte(routeTestIPv4Header + routeTestIPv4Row), nil
		}
		return []byte("malformed IPv6 route\n"), nil
	}}
	markDefaultRoutes(t.Context(), sources, network)
	validator, err := protovalidate.New(protovalidate.WithMessages(network))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(network); err != nil {
		t.Fatalf("collected independent route observations: %v", err)
	}
	for _, iface := range network.Interfaces {
		if iface.DefaultRouteIpv4 == nil || iface.DefaultRouteIpv6 == nil {
			t.Fatalf("collector left historically optional route fields absent: %v", iface)
		}
	}
}
