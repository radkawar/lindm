// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capabilitypolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"lindm/internal/agent/firewallprovider"
	"lindm/internal/agent/inventory"
	"lindm/internal/custody"
	"lindm/internal/platform"
)

const (
	maxKeyBytes    = 4 << 20
	maxInterfaces  = 256
	maxSysfsBytes  = 64
	sysfsNetworks  = "/sys/class/net"
	arphrdLoopback = "772"
)

var permanentMAC = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)

// Interface is one network interface the host reports.
type Interface struct {
	Name string
	// PermanentMAC is the hardware address when the kernel reports it as
	// permanent (addr_assign_type 0); empty otherwise.
	PermanentMAC string
	Loopback     bool
}

// Host is the local evidence derivation reads. Every field is observed by the
// agent itself; nothing comes from the signed policy. DetectHost builds the
// production host; tests build literals.
type Host struct {
	// Release is the registry row identified from os-release.
	Release *platform.Release
	// Architecture is the kernel machine name (x86_64, aarch64); APT sources
	// use the Debian spelling derived from it.
	Architecture string
	// Interfaces lists the host's network interfaces.
	Interfaces func() ([]Interface, error)
	// ReadVendorKey reads a registry vendor key file under root custody.
	ReadVendorKey func(path string) ([]byte, error)
	// PathPresent reports whether a registry variant marker exists; any
	// error other than absence counts as present.
	PathPresent func(path string) bool
	// FirewallRestoreReady reports the firewall restore unit's custody; it
	// observes the host afresh on every call.
	FirewallRestoreReady func() bool
}

// DetectHost observes the running release, architecture and seams.
func DetectHost(ctx context.Context) (Host, error) {
	release, err := inventory.HostRelease(ctx)
	if err != nil {
		return Host{}, fmt.Errorf("detect capability host: %w", err)
	}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return Host{}, fmt.Errorf("detect capability host architecture: %w", err)
	}
	machine := make([]byte, 0, len(uts.Machine))
	for _, c := range uts.Machine {
		if c == 0 {
			break
		}
		machine = append(machine, byte(c))
	}
	return Host{
		Release:              platform.Identify(release),
		Architecture:         string(machine),
		Interfaces:           sysfsInterfaces,
		ReadVendorKey:        func(path string) ([]byte, error) { return custody.ReadRoot(path, maxKeyBytes, false) },
		PathPresent:          pathPresent,
		FirewallRestoreReady: firewallprovider.RestoreReady,
	}, nil
}

func pathPresent(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// sysfsInterfaces reads /sys/class/net, bounded.
func sysfsInterfaces() ([]Interface, error) {
	directory, err := os.Open(sysfsNetworks)
	if err != nil {
		return nil, err
	}
	names, err := directory.Readdirnames(maxInterfaces + 1)
	if closeErr := directory.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if len(names) > maxInterfaces {
		return nil, errors.New("too many network interfaces")
	}
	slices.Sort(names)
	interfaces := make([]Interface, 0, len(names))
	for _, name := range names {
		kind, err := sysfsValue(name, "type")
		if err != nil {
			return nil, err
		}
		item := Interface{Name: name, Loopback: kind == arphrdLoopback}
		assign, err := sysfsValue(name, "addr_assign_type")
		if err != nil {
			return nil, err
		}
		address, err := sysfsValue(name, "address")
		if err != nil {
			return nil, err
		}
		if assign == "0" && permanentMAC.MatchString(address) && address != "00:00:00:00:00:00" {
			item.PermanentMAC = address
		}
		interfaces = append(interfaces, item)
	}
	return interfaces, nil
}

func sysfsValue(name, attribute string) (string, error) {
	file, err := os.Open(sysfsNetworks + "/" + name + "/" + attribute)
	if err != nil {
		return "", err
	}
	buffer := make([]byte, maxSysfsBytes+1)
	n, err := file.Read(buffer)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	// Interfaces without a hardware address report EINVAL for some attributes.
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EINVAL) {
		return "", err
	}
	if n > maxSysfsBytes {
		return "", errors.New("oversized network interface attribute")
	}
	return strings.TrimSpace(string(buffer[:n])), nil
}
