// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"reflect"
	"testing"
)

func TestTruthDefaultRoutes(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
		ipv6 bool
		want map[string]bool
	}{
		{name: "empty", json: `[]`, want: map[string]bool{}},
		{name: "ipv4 default", json: `[{"dst":"default","gateway":"10.0.2.2","dev":"eth0","protocol":"dhcp","metric":100,"flags":[]}]`, want: map[string]bool{"eth0": true}},
		{name: "multiple interfaces not preferred", json: `[{"dst":"0.0.0.0/0","dev":"eth0","metric":100},{"dst":"default","dev":"wlan0","metric":600}]`, want: map[string]bool{"eth0": true, "wlan0": true}},
		{name: "source specific ipv6", json: `[{"dst":"default","from":"2001:db8::/64","dev":"eth0"},{"dst":"::/0","dev":"wlan0","table":100}]`, ipv6: true, want: map[string]bool{"eth0": true, "wlan0": true}},
		{name: "reject defaults excluded", json: `[{"dst":"default","type":"unreachable","dev":"lo"},{"dst":"default","type":"prohibit"},{"dst":"default","type":"blackhole"},{"dst":"default","type":"throw"}]`, want: map[string]bool{}},
		{name: "multipath", json: `[{"dst":"default","nexthops":[{"gateway":"10.0.2.2","dev":"eth0","weight":1},{"gateway":"10.0.3.2","dev":"eth1","weight":1}]}]`, want: map[string]bool{"eth0": true, "eth1": true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseTruthDefaultRoutes([]byte(test.json), test.ipv6)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("default-route membership = %v, %v; want %v", got, err, test.want)
			}
		})
	}
}

func TestTruthDefaultRoutesRejectInvalidEvidence(t *testing.T) {
	for _, data := range []string{
		``, `null`, `{}`, `[`, `[] []`,
		`[{"dst":"default"}]`,
		`[{"dst":"10.0.2.0/24","dev":"eth0"}]`,
		`[{"dst":"::/0","dev":"eth0"}]`,
		`[{"dst":"default","type":"mystery","dev":"eth0"}]`,
		`[{"dst":"default","nexthops":[{"gateway":"10.0.2.2"}]}]`,
		`[{"dst":"default","dev":12}]`,
	} {
		if _, err := parseTruthDefaultRoutes([]byte(data), false); err == nil {
			t.Errorf("accepted invalid route evidence %q", data)
		}
	}
}
