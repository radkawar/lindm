//go:build linux

package inventory

import (
	"context"
	"strconv"
	"strings"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// markDefaultRoutes observes route membership, not a preferred interface or
// connectivity. Multiple interfaces (including source-specific IPv6 defaults)
// can have active destination-default routes. Each family fails independently.
func markDefaultRoutes(ctx context.Context, s detailSources, network *inventoryv1.NetworkDetails) {
	if len(network.GetInterfaces()) == 0 {
		return
	}
	data, err := s.file(ctx, "/proc/net/route")
	ipv4, ipv4Err := parseDefaultRoutes(data, err, false)
	data, err = s.file(ctx, "/proc/net/ipv6_route")
	ipv6, ipv6Err := parseDefaultRoutes(data, err, true)
	for _, iface := range network.Interfaces {
		iface.DefaultRouteIpv4 = boolean(ipv4[iface.Name], ipv4Err)
		iface.DefaultRouteIpv6 = boolean(ipv6[iface.Name], ipv6Err)
	}
}

// parseDefaultRoutes validates the entire bounded proc table before publishing
// any memberships. A header-only IPv4 table or empty IPv6 table is a successful
// empty observation; a missing IPv6 file (for example when disabled) is not.
func parseDefaultRoutes(data []byte, err error, ipv6 bool) (map[string]bool, error) {
	if err != nil {
		return nil, err
	}
	if len(data) > maxDetailFile {
		return nil, errCapacity
	}
	if !nativeText(data) || (len(data) > 0 && data[len(data)-1] != '\n') {
		return nil, errInvalid
	}
	table := strings.TrimSuffix(string(data), "\n")
	var fields [11]string
	fieldCount := len(fields)
	if ipv6 {
		fieldCount = 10
		if len(data) == 0 {
			return nil, nil
		}
	} else {
		header, rest, hasRows := strings.Cut(table, "\n")
		if !routeFields(header, fields[:]) {
			return nil, errInvalid
		}
		for i, want := range [...]string{"Iface", "Destination", "Gateway", "Flags", "RefCnt", "Use", "Metric", "Mask", "MTU", "Window", "IRTT"} {
			if fields[i] != want {
				return nil, errInvalid
			}
		}
		table = rest
		if !hasRows {
			return nil, nil
		}
	}
	var defaults map[string]bool
	for line := range strings.SplitSeq(table, "\n") {
		if !routeFields(line, fields[:fieldCount]) {
			return nil, errInvalid
		}
		var name string
		var isDefault bool
		if ipv6 {
			name, isDefault, err = ipv6DefaultRoute(fields[:fieldCount])
		} else {
			name, isDefault, err = ipv4DefaultRoute(fields[:fieldCount])
		}
		if err != nil {
			return nil, err
		}
		if isDefault {
			if defaults == nil {
				defaults = make(map[string]bool)
			}
			defaults[name] = true
		}
	}
	return defaults, nil
}

// Fixed field storage avoids allocating a slice for every native route row.
func routeFields(line string, fields []string) bool {
	i := 0
	for field := range strings.FieldsSeq(line) {
		if i == len(fields) {
			return false
		}
		fields[i] = field
		i++
	}
	return i == len(fields)
}

func routeHex(value string, width int) (uint64, error) {
	if len(value) != width || value[0] == '+' {
		return 0, errInvalid
	}
	n, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return 0, errInvalid
	}
	return n, nil
}

func routeInterfaceName(name string) bool {
	// Linux IFNAMSIZ includes the trailing NUL. Whitespace has already been
	// excluded by the fixed-column parser; these are dev_valid_name exclusions.
	return name != "" && len(name) < 16 && name != "." && name != ".." && !strings.ContainsAny(name, "/:")
}

func ipv4DefaultRoute(fields []string) (string, bool, error) {
	if !routeInterfaceName(fields[0]) {
		return "", false, errInvalid
	}
	for _, i := range [...]int{1, 2, 7} {
		if _, err := routeHex(fields[i], 8); err != nil {
			return "", false, err
		}
	}
	// The kernel prints flags with a minimum of four hexadecimal digits.
	if len(fields[3]) < 4 || len(fields[3]) > 8 {
		return "", false, errInvalid
	}
	flags, err := routeHex(fields[3], len(fields[3]))
	if err != nil {
		return "", false, err
	}
	for _, i := range [...]int{4, 5, 6, 8, 9, 10} {
		n, err := decimal(fields[i])
		if err != nil || n > 1<<32-1 {
			return "", false, errInvalid
		}
	}
	return fields[0], fields[1] == "00000000" && fields[7] == "00000000" && flags&0x1 != 0 && flags&0x200 == 0, nil
}

func ipv6DefaultRoute(fields []string) (string, bool, error) {
	if !routeInterfaceName(fields[9]) {
		return "", false, errInvalid
	}
	for _, i := range [...]int{0, 2, 4} {
		if len(fields[i]) != 32 {
			return "", false, errInvalid
		}
		for offset := 0; offset < 32; offset += 16 {
			if _, err := routeHex(fields[i][offset:offset+16], 16); err != nil {
				return "", false, err
			}
		}
	}
	for _, i := range [...]int{1, 3} {
		prefix, err := routeHex(fields[i], 2)
		if err != nil || prefix > 128 {
			return "", false, errInvalid
		}
	}
	var flags uint64
	for i := 5; i <= 8; i++ {
		value, err := routeHex(fields[i], 8)
		if err != nil {
			return "", false, err
		}
		if i == 8 {
			flags = value
		}
	}
	return fields[9], fields[0] == "00000000000000000000000000000000" && fields[1] == "00" && flags&0x1 != 0 && flags&0x200 == 0, nil
}
