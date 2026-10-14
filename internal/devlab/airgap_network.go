// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// IsolatedNetwork is an exact-owned Docker "none" network namespace: loopback
// only, no interfaces with addresses outside 127.0.0.0/8 and ::1, no routes.
// The container only holds the namespace; it runs no service.
type IsolatedNetwork struct {
	ContainerID string `json:"container_id"`
	PID         int    `json:"pid"`
	Label       string `json:"label"`
	Image       string `json:"image"`
}

// OpenIsolatedNetwork creates the namespace holder from the pinned PostgreSQL
// image already used by dedicated lab clusters.
func OpenIsolatedNetwork(ctx context.Context) (_ *IsolatedNetwork, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	n := &IsolatedNetwork{Label: "lindm.airgap.owned=" + uuid.NewString(), Image: loadPostgresImage}
	output, err := loadDocker(ctx, "run", "--detach", "--network", "none", "--label", n.Label, "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL", "--entrypoint", "sleep", loadPostgresImage, "infinity")
	if err != nil {
		return nil, err
	}
	n.ContainerID = strings.TrimSpace(string(output))
	if !loadContainerIDPattern.MatchString(n.ContainerID) {
		return nil, errors.New("docker did not return an exact namespace holder ID")
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, n.Close())
		}
	}()
	output, err = loadDocker(ctx, "inspect", "--format", "{{json .State.Pid}} {{json .HostConfig.NetworkMode}}", n.ContainerID)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 || fields[1] != `"none"` {
		return nil, errors.New("namespace holder is not attached to the Docker none network")
	}
	n.PID, err = strconv.Atoi(fields[0])
	if err != nil || n.PID <= 1 {
		return nil, errors.New("namespace holder has no running process")
	}
	return n, nil
}

// NamespacePath is the holder's network namespace for nsenter.
func (n *IsolatedNetwork) NamespacePath() string {
	return fmt.Sprintf("/proc/%d/ns/net", n.PID)
}

// Close removes only the exact holder container.
func (n *IsolatedNetwork) Close() error {
	if n == nil || n.ContainerID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := loadDocker(ctx, "rm", "--force", n.ContainerID); err != nil {
		return fmt.Errorf("namespace holder %s retained: %w", n.ContainerID, err)
	}
	n.ContainerID = ""
	return nil
}

// EgressEvidence is observed from inside the caller's current namespace.
type EgressEvidence struct {
	Interfaces     []string `json:"interfaces"`
	IPv4Routes     []string `json:"ipv4_routes"`
	IPv6Routes     []string `json:"ipv6_routes"`
	DefaultRoute   bool     `json:"default_route"`
	PublicIPv4Dial string   `json:"public_ipv4_dial"`
	PublicIPv6Dial string   `json:"public_ipv6_dial"`
	PublicDNS      string   `json:"public_dns"`
}

// ObserveEgress records the namespace's interfaces/routes and proves public
// IPv4/IPv6 connections and DNS resolution fail. It fails if any succeeds.
func ObserveEgress(ctx context.Context) (*EgressEvidence, error) {
	evidence := &EgressEvidence{}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(addresses))
		for _, address := range addresses {
			names = append(names, address.String())
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("namespace has non-loopback address %s on %s", address, iface.Name)
			}
		}
		evidence.Interfaces = append(evidence.Interfaces, iface.Name+" "+iface.Flags.String()+" "+strings.Join(names, ","))
	}
	for path, target := range map[string]*[]string{"/proc/net/route": &evidence.IPv4Routes, "/proc/net/ipv6_route": &evidence.IPv6Routes} {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] == "Iface" {
				continue
			}
			*target = append(*target, line)
			if path == "/proc/net/route" && len(fields) > 2 && fields[1] == "00000000" {
				evidence.DefaultRoute = true
			}
			if path == "/proc/net/ipv6_route" && len(fields) > 9 && fields[0] == strings.Repeat("0", 32) && fields[1] == "00" && fields[9] != "lo" {
				evidence.DefaultRoute = true
			}
		}
	}
	if evidence.DefaultRoute {
		return evidence, errors.New("namespace has a default route")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	for address, target := range map[string]*string{"1.1.1.1:443": &evidence.PublicIPv4Dial, "[2606:4700:4700::1111]:443": &evidence.PublicIPv6Dial} {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return evidence, fmt.Errorf("public connection to %s succeeded", address)
		}
		*target = err.Error()
	}
	resolver := net.Resolver{PreferGo: true}
	lookup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := resolver.LookupHost(lookup, "deb.debian.org")
	if err == nil {
		return evidence, fmt.Errorf("public DNS resolved %v", addresses)
	}
	evidence.PublicDNS = err.Error()
	return evidence, nil
}
