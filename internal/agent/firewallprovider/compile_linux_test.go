//go:build linux

package firewallprovider

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/google/uuid"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func compilerFixture(t *testing.T) (*agentv1.FirewallPersistentState, *agentv1.NativeFirewallProviderConfig) {
	t.Helper()
	owner := &agentv1.ResourceOwnershipBinding{AssignmentId: uuid.NewString(), ResourceId: uuid.NewString(), Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: uuid.NewString(), ProfileRevision: uuid.NewString(), ResourceId: uuid.NewString()}}, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}}
	binding := &resourcev1.InterfaceSelector{Identity: &resourcev1.InterfaceSelector_PermanentMac{PermanentMac: "02:00:00:00:00:01"}, Ifname: proto.String("eth0")}
	config := &agentv1.NativeFirewallProviderConfig{AllowedInterfaces: []*resourcev1.InterfaceSelector{binding}, ManagementEndpoints: []*agentv1.NativeFirewallEndpoint{{Address: "192.0.2.2", Port: 443}, {Address: "2001:db8::2", Port: 443}}, DnsServers: []string{"192.0.2.53"}}
	state := &agentv1.FirewallPersistentState{FormatVersion: 1, Desired: &resourcev1.FirewallZoneDesired{ZoneId: uuid.NewString(), Presence: resourcev1.Presence_PRESENCE_PRESENT, Interfaces: []*resourcev1.InterfaceSelector{proto.CloneOf(binding)}, DefaultIngress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_DROP, DefaultEgress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_DROP}, Owner: owner, Generation: uuid.NewString(), AppliedBootId: uuid.NewString(), ConfigurationSha256: bytes.Repeat([]byte{1}, 32), Phase: agentv1.FirewallPersistencePhase_FIREWALL_PERSISTENCE_PHASE_COMMITTED, DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString()}
	return state, config
}
func typedTCPRule() *resourcev1.FirewallRule {
	return &resourcev1.FirewallRule{RuleId: uuid.NewString(), Direction: resourcev1.FirewallDirection_FIREWALL_DIRECTION_INPUT, Family: resourcev1.IPFamily_IP_FAMILY_IPV4, Protocol: resourcev1.IPProtocol_IP_PROTOCOL_TCP, Verdict: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT, DestinationPorts: []*resourcev1.PortRange{{First: 8000, Last: 8010}}, Sources: []*resourcev1.CIDR{{NetworkAddress: "198.51.100.0", PrefixLength: 24}}}
}
func TestCompileOwnershipAndQuarantinePriorities(t *testing.T) {
	state, config := compilerFixture(t)
	state.Desired.Rules = []*resourcev1.FirewallRule{typedTCPRule()}
	compiled, err := compile(state, config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(compiled.name, "lindm_z_") || strings.HasPrefix(compiled.name, "lindm_q_") {
		t.Fatal("profile entered quarantine namespace")
	}
	base := 0
	for _, chain := range compiled.chains {
		if chain.Hook != nil {
			base++
			if chain.GetPriority() <= -10 || chain.GetPolicy() != acceptPolicy || chain.GetType() != "filter" {
				t.Fatal("profile base chain would bypass quarantine or claim global policy")
			}
		}
		if !bytes.HasPrefix(chain.GetUserdata(), compiled.userdata) {
			t.Fatal("chain lacks exact ownership generation")
		}
	}
	if base != 3 {
		t.Fatal("input/output/forward base hooks missing")
	}
	for _, rule := range compiled.rules {
		if !bytes.HasPrefix(rule.identity.GetUserdata(), compiled.userdata) || len(rule.identity.GetExpressionsSha256()) != 32 {
			t.Fatal("unbound native rule")
		}
	}
	second := proto.CloneOf(state)
	second.Generation = uuid.NewString()
	other, err := compile(second, config)
	if err != nil {
		t.Fatal(err)
	}
	if nativeEqual(compiled.snapshot(), other.snapshot()) {
		t.Fatal("ownership generation not bound")
	}
}
func TestCompilerSelectorAlternativesGrowLinearly(t *testing.T) {
	state, config := compilerFixture(t)
	rule := typedTCPRule()
	rule.Sources = nil
	rule.Destinations = nil
	rule.SourcePorts = nil
	rule.DestinationPorts = nil
	for i := range 32 {
		rule.Sources = append(rule.Sources, &resourcev1.CIDR{NetworkAddress: "198.51.100.0", PrefixLength: 24})
		rule.Destinations = append(rule.Destinations, &resourcev1.CIDR{NetworkAddress: "203.0.113.0", PrefixLength: 24})
		rule.SourcePorts = append(rule.SourcePorts, &resourcev1.PortRange{First: uint32(1000 + i), Last: uint32(1000 + i)})
		rule.DestinationPorts = append(rule.DestinationPorts, &resourcev1.PortRange{First: uint32(8000 + i), Last: uint32(8000 + i)})
	}
	state.Desired.Rules = []*resourcev1.FirewallRule{rule}
	compiled, err := compile(state, config)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range compiled.rules {
		if strings.HasPrefix(r.identity.GetChain(), "r000_") {
			count++
		}
	}
	if count != 129 {
		t.Fatalf("selector expansion is not linear: got %d rules", count)
	}
}
func TestTypedProtocolFamilyAndBindingValidation(t *testing.T) {
	state, config := compilerFixture(t)
	rule := typedTCPRule()
	rule.Protocol = resourcev1.IPProtocol_IP_PROTOCOL_ICMPV6
	state.Desired.Rules = []*resourcev1.FirewallRule{rule}
	if _, err := compile(state, config); err == nil {
		t.Fatal("ICMPv6/IPv4 with TCP port selectors accepted")
	}
	state.Desired.Rules = nil
	state.Desired.Interfaces[0].Ifname = proto.String("eth9")
	if _, err := compile(state, config); err == nil {
		t.Fatal("unapproved interface accepted")
	}
}
func TestIPv6SourceAndPortByteIdentity(t *testing.T) {
	state, config := compilerFixture(t)
	rule := typedTCPRule()
	rule.Family = resourcev1.IPFamily_IP_FAMILY_IPV6
	rule.Sources = []*resourcev1.CIDR{{NetworkAddress: "2001:db8:1::", PrefixLength: 64}}
	state.Desired.Rules = []*resourcev1.FirewallRule{rule}
	compiled, err := compile(state, config)
	if err != nil {
		t.Fatal(err)
	}
	var address, port bool
	for _, r := range compiled.rules {
		if !strings.HasPrefix(r.identity.GetChain(), "r000_") {
			continue
		}
		attrs, err := netlink.UnmarshalAttributes(r.expressions)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range attrs {
			fields, err := netlink.UnmarshalAttributes(item.Data)
			if err != nil {
				t.Fatal(err)
			}
			if len(fields) != 2 {
				t.Fatal("malformed expression")
			}
			name, err := exactString(fields[0].Data)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "payload":
				p := &expr.Payload{}
				if err := expr.Unmarshal(unix.NFPROTO_INET, fields[1].Data, p); err != nil {
					t.Fatal(err)
				}
				if p.Base == expr.PayloadBaseNetworkHeader && p.Offset == 8 && p.Len == 16 {
					address = true
				}
			case "range":
				p := &expr.Range{}
				if err := expr.Unmarshal(unix.NFPROTO_INET, fields[1].Data, p); err != nil {
					t.Fatal(err)
				}
				if binary.BigEndian.Uint16(p.FromData) == 8000 && binary.BigEndian.Uint16(p.ToData) == 8010 {
					port = true
				}
			}
		}
	}
	if !address || !port {
		t.Fatal("IPv6 source or network-order destination port range missing")
	}
}
func TestUnknownExpressionAndAttributeCannotDisappear(t *testing.T) {
	unknown, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_EXPR_NAME, Data: []byte("unmodelled\x00")}, {Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: []byte{}}})
	if err != nil {
		t.Fatal(err)
	}
	list, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: unknown}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expressionDigest(list); err == nil {
		t.Fatal("unknown expression silently ignored")
	}
	base, err := expr.Marshal(unix.NFPROTO_INET, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	if err != nil {
		t.Fatal(err)
	}
	list, err = netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: base}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := expressionDigest(list)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := netlink.UnmarshalAttributes(base)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: 500, Data: []byte{1, 2, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	fields[1].Data = append(fields[1].Data, extra...)
	base, err = netlink.MarshalAttributes(fields)
	if err != nil {
		t.Fatal(err)
	}
	list, err = netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: base}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := expressionDigest(list)
	if err == nil && bytes.Equal(before, after) {
		t.Fatal("unmodelled expression attribute disappeared")
	}
}
func TestReplacementNeverFlushesUnmanagedObjects(t *testing.T) {
	state, config := compilerFixture(t)
	compiled, err := compile(state, config)
	if err != nil {
		t.Fatal(err)
	}
	before := compiled.snapshot()
	messages, err := replacementMessages(before, compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		attrs, err := decodeAttrs(message)
		if err != nil {
			t.Fatal(err)
		}
		table, err := exactString(attrs[1])
		if err != nil || table != compiled.name {
			t.Fatal("transaction contains a foreign or wildcard table effect")
		}
	}
	if messages[0].Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELTABLE) {
		t.Fatal("owned replacement is not an atomic delete/create batch")
	}
}
