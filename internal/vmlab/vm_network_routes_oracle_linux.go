// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Default-route truth uses iproute2's netlink view, independently of the agent's
// proc-table parser. IPv4's proc view is the main table; IPv6 exposes all tables.
func (o vmInventoryOracle) defaultRoutes(ipv6 bool) (map[string]bool, inventoryv1.CollectionStatus, error) {
	path, command := "/proc/net/route", "ip -j -4 route show table main default"
	if ipv6 {
		path, command = "/proc/net/ipv6_route", "ip -j -6 route show table all default"
	}
	data, err := o.command("if [ ! -e " + path + " ]; then printf 'unavailable\\n'; elif [ ! -r " + path + " ]; then printf 'denied\\n'; else printf 'success\\n'; " + command + "; fi")
	if err != nil {
		return nil, 0, err
	}
	data, status, err := parseTruthStatus(data)
	if err != nil || status != truthSuccess {
		return nil, status, err
	}
	routes, err := parseTruthDefaultRoutes(data, ipv6)
	return routes, status, err
}

func parseTruthDefaultRoutes(data []byte, ipv6 bool) (map[string]bool, error) {
	var rows []struct {
		Destination string `json:"dst"`
		Type        string `json:"type"`
		Device      string `json:"dev"`
		Nexthops    []struct {
			Device string `json:"dev"`
		} `json:"nexthops"`
	}
	if err := json.Unmarshal(data, &rows); err != nil || rows == nil {
		return nil, errors.New("invalid native default-route JSON")
	}
	zero := "0.0.0.0/0"
	if ipv6 {
		zero = "::/0"
	}
	result := make(map[string]bool)
	for _, row := range rows {
		if row.Destination != "default" && row.Destination != zero {
			return nil, errors.New("native default-route query returned a nondefault destination")
		}
		switch row.Type {
		case "", "unicast":
		case "unreachable", "prohibit", "blackhole", "throw":
			continue
		default:
			return nil, errors.New("unexpected native default-route type")
		}
		if row.Device == "" && len(row.Nexthops) == 0 {
			return nil, errors.New("native default route has no interface")
		}
		if row.Device != "" {
			result[row.Device] = true
		}
		for _, next := range row.Nexthops {
			if next.Device == "" {
				return nil, errors.New("native default-route nexthop has no interface")
			}
			result[next.Device] = true
		}
	}
	return result, nil
}
