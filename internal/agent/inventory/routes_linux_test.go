//go:build linux

package inventory

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const (
	routeTestIPv4Header = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	routeTestIPv4Row    = "eth0 00000000 010200C0 0003 0 0 100 00000000 0 0 0\n"
	routeTestIPv6Row    = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000000 00000000 00000003 eth0\n"
)

func TestParseDefaultRoutes(t *testing.T) {
	for _, test := range []struct {
		name string
		ipv6 bool
		data string
		want []string
	}{
		{name: "IPv4 empty table", data: routeTestIPv4Header},
		{name: "IPv6 empty table", ipv6: true},
		{
			name: "IPv4 multiple metrics and duplicate routes",
			data: routeTestIPv4Header + routeTestIPv4Row + routeTestIPv4Row +
				strings.ReplaceAll(strings.ReplaceAll(routeTestIPv4Row, "eth0", "wlan0"), "100", "900"),
			want: []string{"eth0", "wlan0"},
		},
		{
			name: "IPv6 multiple metrics and duplicate routes", ipv6: true,
			data: routeTestIPv6Row + routeTestIPv6Row +
				strings.ReplaceAll(strings.ReplaceAll(routeTestIPv6Row, "eth0", "wlan0"), "00000064", "00000384"),
			want: []string{"eth0", "wlan0"},
		},
		{
			name: "IPv4 direct default needs no gateway",
			data: routeTestIPv4Header + "tun0 00000000 00000000 0001 0 0 0 00000000 0 0 0\n",
			want: []string{"tun0"},
		},
		{
			name: "IPv6 direct source specific default", ipv6: true,
			data: "00000000000000000000000000000000 00 20010db8000000000000000000000000 40 00000000000000000000000000000000 00000000 00000000 00000000 00000001 tun0\n",
			want: []string{"tun0"},
		},
		{
			name: "IPv4 down reject and specific routes excluded",
			data: routeTestIPv4Header +
				"down0 00000000 010200C0 0002 0 0 0 00000000 0 0 0\n" +
				"reject0 00000000 00000000 0201 0 0 0 00000000 0 0 0\n" +
				"eth0 00000000 00000000 0001 0 0 0 000000FF 0 0 0\n" +
				"eth1 000200C0 00000000 0001 0 0 0 00FFFFFF 0 0 0\n",
		},
		{
			name: "IPv6 down reject and specific routes excluded", ipv6: true,
			data: strings.ReplaceAll(routeTestIPv6Row, "00000003", "00000002") +
				strings.ReplaceAll(routeTestIPv6Row, "00000003", "00200201") +
				strings.Replace(routeTestIPv6Row, " 00 ", " 40 ", 1) +
				"20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth1\n",
		},
		{
			name: "IPv4 unrelated flags and maximum metric",
			data: routeTestIPv4Header + "eth0 00000000 010200c0 10000003 0 0 4294967295 00000000 0 0 0\n",
			want: []string{"eth0"},
		},
		{
			name: "IPv6 unrelated flags and uppercase hex", ipv6: true,
			data: strings.ReplaceAll(strings.ReplaceAll(routeTestIPv6Row, "fe800", "FE800"), "00000003", "80000003"),
			want: []string{"eth0"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseDefaultRoutes([]byte(test.data), nil, test.ipv6)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("default interfaces = %v, want %v", got, test.want)
			}
			for _, name := range test.want {
				if !got[name] {
					t.Fatalf("missing default interface %s: %v", name, got)
				}
			}
		})
	}
}

func TestDefaultRouteMalformedRowsDiscardAllMemberships(t *testing.T) {
	for _, test := range []struct {
		name   string
		ipv6   bool
		header string
		row    string
		bad    []string
	}{
		{
			name: "IPv4", header: routeTestIPv4Header, row: routeTestIPv4Row,
			bad: []string{"invalid/name", "ZZ000000", "010200C", "+003", "-1", "4294967296", "many", "0000000_", "18446744073709551616", "+1", "1.0"},
		},
		{
			name: "IPv6", ipv6: true, row: routeTestIPv6Row,
			bad: []string{"0000000000000000000000000000000Z", "81", "0000000000000000000000000000000", "ff", "0000000000000000+000000000000001", "0000000_", "+0000000", "100000000", "0000000g", "interface-too-long"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for i, bad := range test.bad {
				fields := strings.Fields(test.row)
				fields[i] = bad
				data := test.header + test.row + strings.Join(fields, " ") + "\n"
				got, err := parseDefaultRoutes([]byte(data), nil, test.ipv6)
				if !errors.Is(err, errInvalid) || got != nil {
					t.Fatalf("malformed field %d: memberships %v, error %v", i, got, err)
				}
			}
			for _, suffix := range []string{"\n", "broken\n", test.row + "extra\n", strings.TrimSuffix(test.row, "\n"), "\x00\n", "\xff\n"} {
				got, err := parseDefaultRoutes([]byte(test.header+test.row+suffix), nil, test.ipv6)
				if !errors.Is(err, errInvalid) || got != nil {
					t.Fatalf("malformed suffix %q: memberships %v, error %v", suffix, got, err)
				}
			}
		})
	}
	for _, data := range []string{"", routeTestIPv4Row, strings.Replace(routeTestIPv4Header, "Gateway", "Unknown", 1), strings.TrimSuffix(routeTestIPv4Header, "\n"), routeTestIPv4Header + "\n"} {
		if got, err := parseDefaultRoutes([]byte(data), nil, false); !errors.Is(err, errInvalid) || got != nil {
			t.Fatalf("malformed IPv4 table %q: memberships %v, error %v", data, got, err)
		}
	}
}

func TestDefaultRouteInputCapacity(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		data := routeTestIPv4Header + strings.TrimSuffix(routeTestIPv4Row, "\n")
		if ipv6 {
			data = strings.TrimSuffix(routeTestIPv6Row, "\n")
		}
		data += strings.Repeat(" ", maxDetailFile-len(data)-1) + "\n"
		if got, err := parseDefaultRoutes([]byte(data), nil, ipv6); err != nil || !got["eth0"] {
			t.Fatalf("exact capacity IPv6=%t: memberships %v, error %v", ipv6, got, err)
		}
		if got, err := parseDefaultRoutes([]byte(data+"\n"), nil, ipv6); !errors.Is(err, errCapacity) || got != nil {
			t.Fatalf("over capacity IPv6=%t: memberships %v, error %v", ipv6, got, err)
		}
	}
}

func routeTestNetwork() *inventoryv1.NetworkDetails {
	result := &inventoryv1.NetworkDetails{Status: success}
	for _, name := range []string{"lo", "eth0", "wlan0"} {
		result.Interfaces = append(result.Interfaces, &inventoryv1.NetworkInterface{
			Name: name, Mac: observed("", fs.ErrNotExist), Link: observed("", fs.ErrNotExist),
			Addresses: &inventoryv1.ObservedStrings{Status: success},
		})
	}
	return result
}

func TestMarkDefaultRoutesMatchesEveryInterface(t *testing.T) {
	network := routeTestNetwork()
	sources := detailSources{readFile: func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/route":
			return []byte(routeTestIPv4Header + routeTestIPv4Row + strings.ReplaceAll(routeTestIPv4Row, "eth0", "wlan0")), nil
		case "/proc/net/ipv6_route":
			return []byte(strings.ReplaceAll(routeTestIPv6Row, "eth0", "wlan0")), nil
		default:
			t.Fatalf("unexpected route source %s", path)
			return nil, fs.ErrNotExist
		}
	}}
	markDefaultRoutes(t.Context(), sources, network)
	for _, iface := range network.Interfaces {
		ipv4, ipv6 := iface.DefaultRouteIpv4, iface.DefaultRouteIpv6
		if ipv4 == nil || ipv6 == nil || ipv4.Status != success || ipv6.Status != success || ipv4.Value != (iface.Name != "lo") || ipv6.Value != (iface.Name == "wlan0") {
			t.Fatalf("wrong route membership for %s: %v", iface.Name, iface)
		}
	}
}

func TestMarkDefaultRoutesIndependentAvailability(t *testing.T) {
	for _, test := range []struct {
		name   string
		data   string
		err    error
		status inventoryv1.CollectionStatus
	}{
		{name: "missing including disabled IPv6", err: fs.ErrNotExist, status: unavailable},
		{name: "denied", err: fs.ErrPermission, status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED},
		{name: "timed out", err: context.DeadlineExceeded, status: inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT},
		{name: "cancelled", err: context.Canceled, status: inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT},
		{name: "read failure with partial data", data: routeTestIPv6Row, err: errors.New("read failed"), status: invalid},
		{name: "malformed", data: "broken\n", status: invalid},
		{name: "capacity", data: strings.Repeat(" ", maxDetailFile+1), status: capacity},
	} {
		for _, failedFamily := range []string{"/proc/net/route", "/proc/net/ipv6_route"} {
			t.Run(test.name+failedFamily, func(t *testing.T) {
				network := routeTestNetwork()
				sources := detailSources{readFile: func(path string) ([]byte, error) {
					if path == failedFamily {
						return []byte(test.data), test.err
					}
					if path == "/proc/net/route" {
						return []byte(routeTestIPv4Header + routeTestIPv4Row), nil
					}
					return []byte(routeTestIPv6Row), nil
				}}
				markDefaultRoutes(t.Context(), sources, network)
				if network.Status != success {
					t.Fatalf("route error erased independent network evidence: %v", network)
				}
				for _, iface := range network.Interfaces {
					failed, healthy := iface.DefaultRouteIpv4, iface.DefaultRouteIpv6
					if failedFamily == "/proc/net/ipv6_route" {
						failed, healthy = healthy, failed
					}
					if failed == nil || failed.Status != test.status || failed.Value || healthy == nil || healthy.Status != success || healthy.Value != (iface.Name == "eth0") {
						t.Fatalf("independent availability for %s: %v", iface.Name, iface)
					}
				}
			})
		}
	}
}

func TestMarkDefaultRoutesEmptyAndUnknownInterfaces(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		network := routeTestNetwork()
		sources := detailSources{readFile: func(path string) ([]byte, error) {
			if path == "/proc/net/route" {
				data := routeTestIPv4Header
				if unknown {
					data += strings.ReplaceAll(routeTestIPv4Row, "eth0", "gone0")
				}
				return []byte(data), nil
			}
			if unknown {
				return []byte(strings.ReplaceAll(routeTestIPv6Row, "eth0", "gone0")), nil
			}
			return nil, nil
		}}
		markDefaultRoutes(t.Context(), sources, network)
		for _, iface := range network.Interfaces {
			if iface.DefaultRouteIpv4 == nil || iface.DefaultRouteIpv6 == nil || iface.DefaultRouteIpv4.Status != success || iface.DefaultRouteIpv6.Status != success || iface.DefaultRouteIpv4.Value || iface.DefaultRouteIpv6.Value {
				t.Fatalf("empty/unknown route guessed membership: %v", iface)
			}
		}
	}
}

func TestMarkDefaultRoutesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sources := detailSources{readFile: func(string) ([]byte, error) {
		t.Fatal("cancelled collection must not read procfs")
		return nil, nil
	}}
	network := routeTestNetwork()
	markDefaultRoutes(ctx, sources, network)
	for _, iface := range network.Interfaces {
		if iface.DefaultRouteIpv4 == nil || iface.DefaultRouteIpv6 == nil || iface.DefaultRouteIpv4.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT || iface.DefaultRouteIpv6.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT || iface.DefaultRouteIpv4.Value || iface.DefaultRouteIpv6.Value {
			t.Fatalf("cancelled route collection: %v", iface)
		}
	}
}
