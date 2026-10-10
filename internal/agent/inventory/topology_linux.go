//go:build linux

package inventory

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func decodeNative(reader io.Reader, target any) inventoryv1.CollectionStatus {
	limited := &io.LimitedReader{R: reader, N: maxDetailFile + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(target); err != nil {
		if limited.N == 0 {
			return capacity
		}
		return invalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if limited.N == 0 {
			return capacity
		}
		return invalid
	}
	if limited.N == 0 {
		return capacity
	}
	return success
}

type nativeInterface struct {
	Name      string `json:"ifname"`
	MAC       string `json:"address"`
	Link      string `json:"operstate"`
	Addresses []struct {
		Family string  `json:"family"`
		Local  string  `json:"local"`
		Prefix *uint32 `json:"prefixlen"`
	} `json:"addr_info"`
}

func parseNetwork(reader io.Reader) *inventoryv1.NetworkDetails {
	var native []nativeInterface
	result := &inventoryv1.NetworkDetails{Status: decodeNative(reader, &native)}
	if result.Status != success {
		return result
	}
	if native == nil {
		result.Status = invalid
		return result
	}
	if len(native) > 256 {
		result.Status = capacity
		return result
	}
	seen := make(map[string]bool)
	for _, iface := range native {
		if iface.Name == "" || len(iface.Name) > 256 || seen[iface.Name] {
			result.Status = invalid
			break
		}
		seen[iface.Name] = true
		item := &inventoryv1.NetworkInterface{Name: iface.Name, Mac: observed(iface.MAC, nil), Link: observed(iface.Link, nil), Addresses: &inventoryv1.ObservedStrings{Status: success}}
		if iface.MAC != "" {
			if _, err := net.ParseMAC(iface.MAC); err != nil {
				item.Mac = observed("", errInvalid)
			}
		}
		if iface.Addresses == nil {
			item.Addresses.Status = unavailable
		}
		if len(iface.Addresses) > 64 {
			item.Addresses.Status = capacity
		} else {
			for _, address := range iface.Addresses {
				ip := net.ParseIP(address.Local)
				if ip == nil || address.Prefix == nil || (address.Family != "inet" && address.Family != "inet6") || (address.Family == "inet" && (ip.To4() == nil || *address.Prefix > 32)) || (address.Family == "inet6" && (ip.To4() != nil || *address.Prefix > 128)) {
					item.Addresses.Status = invalid
					break
				}
				item.Addresses.Values = append(item.Addresses.Values, address.Local+"/"+strconv.FormatUint(uint64(*address.Prefix), 10))
			}
		}
		if item.Addresses.Status != success {
			item.Addresses.Values = nil
		}
		result.Interfaces = append(result.Interfaces, item)
	}
	if result.Status != success {
		result.Interfaces = nil
	}
	return result
}

func collectNetwork(ctx context.Context, run nativeRunner) *inventoryv1.NetworkDetails {
	var parsed *inventoryv1.NetworkDetails
	status := run(ctx, backend{name: "ip", path: "/usr/bin/ip", args: []string{"-json", "address", "show"}}, func(reader io.Reader) inventoryv1.CollectionStatus {
		parsed = parseNetwork(reader)
		return parsed.Status
	})
	// iproute2 is installed under /usr/sbin on Debian-family systems.
	if status == unavailable {
		status = run(ctx, backend{name: "ip", path: "/usr/sbin/ip", args: []string{"-json", "address", "show"}}, func(reader io.Reader) inventoryv1.CollectionStatus {
			parsed = parseNetwork(reader)
			return parsed.Status
		})
	}
	if status != success {
		return &inventoryv1.NetworkDetails{Status: status}
	}
	return parsed
}

func readApplicationOutput(reader io.Reader) ([]byte, inventoryv1.CollectionStatus) {
	data, err := io.ReadAll(io.LimitReader(reader, maxDetailFile+1))
	if len(data) > maxDetailFile {
		return nil, capacity
	}
	if err != nil {
		return nil, statusFor(err)
	}
	return data, success
}

func parseFlatpak(reader io.Reader) *inventoryv1.ApplicationDetails {
	data, status := readApplicationOutput(reader)
	if status != success {
		return &inventoryv1.ApplicationDetails{Status: status}
	}
	return parseFlatpakData(data)
}

func parseFlatpakData(data []byte) *inventoryv1.ApplicationDetails {
	result := &inventoryv1.ApplicationDetails{Status: success}
	if !nativeText(data) || (len(data) > 0 && data[len(data)-1] != '\n') {
		result.Status = invalid
		return result
	}
	lines := strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n")
	for line := range lines {
		if line == "" && len(data) == 0 {
			break
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			result.Status = invalid
			break
		}
		name, version, arch := fields[0], fields[1], fields[2]
		if name == "" || len(name) > 512 {
			result.Status = invalid
			break
		}
		if len(result.Applications) == 2048 {
			result.Status = capacity
			break
		}
		result.Applications = append(result.Applications, &inventoryv1.Application{Name: name, Version: observed(version, nil), Architecture: observed(arch, nil), Scope: observed("system", nil)})
	}
	if result.Status != success {
		result.Applications = nil
	}
	return result
}

// Flatpak deliberately inventories system-installed applications, not runtimes
// or the service account's user installation. It never enumerates employee HOME
// directories.
func collectFlatpak(ctx context.Context, run nativeRunner) *inventoryv1.ApplicationDetails {
	selected := backend{name: "flatpak", path: "/usr/bin/flatpak", args: []string{"list", "--system", "--app", "--columns=application,version,arch"}}
	var parsed *inventoryv1.ApplicationDetails
	status := run(ctx, selected, func(reader io.Reader) inventoryv1.CollectionStatus {
		data, status := readApplicationOutput(reader)
		if status != success {
			return status
		}
		parsed = parseFlatpakData(data)
		// Output reached bounded EOF: allow the runner to observe native exit
		// and diagnostics before reporting semantic parse failure.
		// Capacity/read failures still abort immediately and retain precedence.
		if parsed.Status == invalid {
			return success
		}
		return parsed.Status
	})
	if status != success {
		return &inventoryv1.ApplicationDetails{Status: status}
	}
	return parsed
}
