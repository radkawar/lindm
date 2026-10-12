//go:build linux

package capabilitypolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

var (
	testKey     = []byte("test vendor key bytes")
	testKeyHash = func() string { sum := sha256.Sum256(testKey); return hex.EncodeToString(sum[:]) }()
)

const (
	testDeployment = "11111111-1111-4111-8111-111111111111"
	testDevice     = "22222222-2222-4222-8222-222222222222"
	testGeneration = "33333333-3333-4333-8333-333333333333"
)

// testRelease copies a registry row with its vendor key digests replaced by the
// test key's, so derivation runs on the row's real repositories and gates.
func testRelease(t *testing.T, key string) *platform.Release {
	t.Helper()
	row, ok := platform.Lookup(key)
	if !ok {
		t.Fatalf("registry row %s missing", key)
	}
	release := *row
	release.VendorRepositories = nil
	for _, vendor := range row.VendorRepositories {
		vendor.KeySHA256 = []string{testKeyHash}
		release.VendorRepositories = append(release.VendorRepositories, vendor)
	}
	return &release
}

func testHost(t *testing.T, key string) Host {
	t.Helper()
	return Host{
		Release:      testRelease(t, key),
		Architecture: "x86_64",
		Interfaces: func() ([]Interface, error) {
			return []Interface{
				{Name: "wlp2s0", PermanentMAC: "02:00:00:00:00:02"},
				{Name: "lo", Loopback: true},
				{Name: "enp1s0", PermanentMAC: "02:00:00:00:00:01"},
				{Name: "veth0"},
			}, nil
		},
		ReadVendorKey: func(path string) ([]byte, error) {
			if path == "" {
				return nil, errors.New("no key path")
			}
			return bytes.Clone(testKey), nil
		},
		PathPresent:          func(string) bool { return false },
		FirewallRestoreReady: func() bool { return true },
	}
}

func firewallSettings() *agentv1.CapabilityFirewallSettings {
	peer := &agentv1.ConnectivityProbePeer{Origin: "https://probe.example.com", PublicKey: bytes.Repeat([]byte{7}, 32)}
	probe := func(id, address string, verdict agentv1.ConnectivityProbeVerdict) *agentv1.ConnectivityProbeTarget {
		return &agentv1.ConnectivityProbeTarget{Id: id, Address: address, Port: 443, Expected: verdict, SourceAddress: address, SourcePort: 40000,
			Direction: agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT, Protocol: agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP, Receiver: peer}
	}
	return &agentv1.CapabilityFirewallSettings{
		ManagementEndpoints: []*agentv1.NativeFirewallEndpoint{{Address: "192.0.2.10", Port: 18445}},
		DnsServers:          []string{"192.0.2.53"},
		ConnectivityGuard: &agentv1.ConnectivityGuardConfig{ConfirmationPublicKey: bytes.Repeat([]byte{9}, 32), Probes: []*agentv1.ConnectivityProbeTarget{
			probe("44444444-4444-4444-8444-444444444441", "192.0.2.20", agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW),
			probe("44444444-4444-4444-8444-444444444442", "192.0.2.21", agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY),
			probe("44444444-4444-4444-8444-444444444443", "2001:db8::20", agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW),
			probe("44444444-4444-4444-8444-444444444444", "2001:db8::21", agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY),
		}},
	}
}

// testRecord grants capabilities; firewall and sysctl settings follow the
// policy's own consistency rules.
func testRecord(active bool, capabilities ...agentv1.ManagementCapability) *agentv1.CapabilityPolicyRecord {
	policy := &agentv1.AgentCapabilityPolicy{
		FormatVersion: 1, DeploymentId: testDeployment, DeviceId: testDevice, EnrollmentGeneration: testGeneration,
		Version: 3, IssuedAt: timestamppb.New(time.Unix(1_800_000_000, 0)), Capabilities: capabilities,
	}
	for _, c := range capabilities {
		switch c {
		case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL:
			policy.Firewall = firewallSettings()
		case agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_SETTINGS:
			policy.SysctlKeys = []string{"net.ipv4.ip_forward", "kernel.sysrq"}
		}
	}
	return &agentv1.CapabilityPolicyRecord{FormatVersion: 1, PolicyEnvelope: []byte("envelope"), Policy: policy, AcceptedAt: timestamppb.New(time.Unix(1_800_000_100, 0)), Active: active}
}

func statusOf(t *testing.T, effective *Effective, c agentv1.ManagementCapability) *agentv1.CapabilityObservation {
	t.Helper()
	if len(effective.Status) != 9 {
		t.Fatalf("status has %d entries, want 9", len(effective.Status))
	}
	for _, observed := range effective.Status {
		if observed.GetCapability() == c {
			return observed
		}
	}
	t.Fatalf("status for %s missing", c)
	return nil
}

func wantStatus(t *testing.T, effective *Effective, c agentv1.ManagementCapability, s agentv1.CapabilityStatus, detail string) {
	t.Helper()
	got := statusOf(t, effective, c)
	if got.GetStatus() != s || got.GetDetail() != detail {
		t.Fatalf("%s = %s %q, want %s %q", c, got.GetStatus(), got.GetDetail(), s, detail)
	}
}

func derive(t *testing.T, local *agentv1.AgentConfig, record *agentv1.CapabilityPolicyRecord, host Host) *Effective {
	t.Helper()
	effective, err := Derive(local, record, host)
	if err != nil {
		t.Fatal(err)
	}
	return effective
}

func clone[T proto.Message](m T) T { return proto.CloneOf(m) }
