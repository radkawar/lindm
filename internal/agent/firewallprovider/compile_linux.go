//go:build linux

package firewallprovider

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

const filterPriority = 10 // quarantine's -10 DROP is final; ACCEPT is never global.

type compiledRule struct {
	identity    *agentv1.FirewallNativeRule
	expressions []byte
}
type compiledTable struct {
	name     string
	userdata []byte
	chains   []*agentv1.FirewallNativeChain
	rules    []compiledRule
}

func tableName(zone string) string { return "lindm_z_" + strings.ReplaceAll(zone, "-", "") }
func u32(v uint32) []byte          { return binary.BigEndian.AppendUint32(nil, v) }
func u16(v uint32) []byte          { return binary.BigEndian.AppendUint16(nil, uint16(v)) }
func familyMatch(v6 bool) []expr.Any {
	family := byte(unix.NFPROTO_IPV4)
	if v6 {
		family = unix.NFPROTO_IPV6
	}
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}}}
}
func protocolMatch(protocol byte) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}}}
}
func interfaceMatch(name string, output bool) []expr.Any {
	key := expr.MetaKeyIIFNAME
	if output {
		key = expr.MetaKeyOIFNAME
	}
	data := make([]byte, 16)
	copy(data, name)
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}}
}
func addressMatch(prefix netip.Prefix, destination bool) []expr.Any {
	prefix = prefix.Masked()
	address := prefix.Addr()
	length, offset := uint32(4), uint32(12)
	if address.Is6() {
		length, offset = 16, 8
	}
	if destination {
		offset += length
	}
	mask := make([]byte, length)
	for i := range mask {
		bits := prefix.Bits() - i*8
		if bits >= 8 {
			mask[i] = 255
		} else if bits > 0 {
			mask[i] = byte(255 << (8 - bits))
		}
	}
	result := familyMatch(address.Is6())
	return append(result, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: mask, Xor: make([]byte, length)}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: address.AsSlice()})
}
func portMatch(port *resourcev1.PortRange, destination bool) []expr.Any {
	offset := uint32(0)
	if destination {
		offset = 2
	}
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2}, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: u16(port.GetFirst()), ToData: u16(port.GetLast())}}
}
func verdict(v resourcev1.FirewallVerdict) expr.Any {
	switch v {
	case resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT:
		return &expr.Verdict{Kind: expr.VerdictAccept}
	case resourcev1.FirewallVerdict_FIREWALL_VERDICT_DROP:
		return &expr.Verdict{Kind: expr.VerdictDrop}
	default:
		return &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED}
	}
}
func (c *compiledTable) chain(name string, hook *uint32) {
	chain := &agentv1.FirewallNativeChain{Name: name, Userdata: append(append([]byte(nil), c.userdata...), []byte(":"+name)...), Hook: hook}
	if hook != nil {
		chain.Priority = proto.Int32(filterPriority)
		chain.Policy = proto.Uint32(acceptPolicy)
		chain.Type = "filter"
	}
	c.chains = append(c.chains, chain)
}
func (c *compiledTable) rule(chain string, expressions []expr.Any) error {
	if len(c.rules) >= 4096 || len(c.chains) > 2048 {
		return fmt.Errorf("%w: compiled object bound", ErrUnsupported)
	}
	attrs := make([]netlink.Attribute, len(expressions))
	for i, e := range expressions {
		data, err := expr.Marshal(unix.NFPROTO_INET, e)
		if err != nil {
			return err
		}
		attrs[i] = netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: data}
	}
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return err
	}
	digest, err := expressionDigest(data)
	if err != nil {
		return err
	}
	userdata := []byte(fmt.Sprintf("%s:%s:%d", c.userdata, chain, len(c.rules)))
	c.rules = append(c.rules, compiledRule{identity: &agentv1.FirewallNativeRule{Chain: chain, Userdata: userdata, ExpressionsSha256: digest}, expressions: data})
	return nil
}

// compile uses linear selector chains rather than a Cartesian product of CIDRs
// and port ranges. A failed selector returns to the next typed rule; GOTO between
// selector stages avoids growing nft's bounded jump stack. Priority then UUID is
// deterministic; ACCEPT ends this base chain only, never another owner's chain.
func compile(state *agentv1.FirewallPersistentState, config *agentv1.NativeFirewallProviderConfig) (*compiledTable, error) {
	d := state.GetDesired()
	if err := validateMessage(d); err != nil {
		return nil, err
	}
	owner, err := messageDigest(state.GetOwner())
	if err != nil {
		return nil, err
	}
	c := &compiledTable{name: tableName(d.GetZoneId()), userdata: []byte("lindm-fw:v1:" + state.GetGeneration() + ":" + hex.EncodeToString(owner))}
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return c, nil
	}
	for _, binding := range d.GetInterfaces() {
		if binding.GetIfname() == "" || !slices.ContainsFunc(config.GetAllowedInterfaces(), func(allowed *resourcev1.InterfaceSelector) bool { return proto.Equal(binding, allowed) }) {
			return nil, fmt.Errorf("%w: interface binding", ErrUnsupported)
		}
	}
	ordered := slices.Clone(d.GetRules())
	slices.SortFunc(ordered, func(a, b *resourcev1.FirewallRule) int {
		if a.GetPriority() < b.GetPriority() {
			return -1
		}
		if a.GetPriority() > b.GetPriority() {
			return 1
		}
		return strings.Compare(a.GetRuleId(), b.GetRuleId())
	})
	for _, direction := range []struct {
		name      string
		hook      uint32
		direction resourcev1.FirewallDirection
	}{{"input", unix.NF_INET_LOCAL_IN, resourcev1.FirewallDirection_FIREWALL_DIRECTION_INPUT}, {"output", unix.NF_INET_LOCAL_OUT, resourcev1.FirewallDirection_FIREWALL_DIRECTION_OUTPUT}, {"forward", unix.NF_INET_FORWARD, resourcev1.FirewallDirection_FIREWALL_DIRECTION_FORWARD}} {
		base, zone, scope := direction.name, "zone_"+direction.name, "scope_"+direction.name
		c.chain(base, proto.Uint32(direction.hook))
		c.chain(scope, nil)
		c.chain(zone, nil)
		if base != "forward" {
			if err := c.management(base, config); err != nil {
				return nil, err
			}
		}
		// The root allowlist is an outer boundary, including source-only zones.
		for _, binding := range config.GetAllowedInterfaces() {
			e := interfaceMatch(binding.GetIfname(), base == "output")
			if err := c.rule(base, append(e, &expr.Verdict{Kind: expr.VerdictJump, Chain: scope})); err != nil {
				return nil, err
			}
		}
		// Interface and remote-network bindings are a union, matching zone semantics.
		for _, binding := range d.GetInterfaces() {
			e := interfaceMatch(binding.GetIfname(), base == "output")
			if err := c.rule(scope, append(e, &expr.Verdict{Kind: expr.VerdictJump, Chain: zone})); err != nil {
				return nil, err
			}
		}
		for _, network := range d.GetSourceNetworks() {
			prefix, err := cidr(network)
			if err != nil {
				return nil, err
			}
			e := addressMatch(prefix, base == "output")
			if err := c.rule(scope, append(e, &expr.Verdict{Kind: expr.VerdictJump, Chain: zone})); err != nil {
				return nil, err
			}
		}
		if len(d.GetInterfaces()) == 0 && len(d.GetSourceNetworks()) == 0 {
			if err := c.rule(scope, []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: zone}}); err != nil {
				return nil, err
			}
		}
		for index, r := range ordered {
			if r.GetDirection() != direction.direction {
				continue
			}
			if err := c.typedRule(zone, index, r); err != nil {
				return nil, err
			}
		}
		v := d.GetDefaultIngress()
		if base == "output" {
			v = d.GetDefaultEgress()
		}
		if err := c.rule(zone, []expr.Any{verdict(v)}); err != nil {
			return nil, err
		}
	}
	return c, nil
}
func cidr(c *resourcev1.CIDR) (netip.Prefix, error) {
	address, err := netip.ParseAddr(c.GetNetworkAddress())
	if err != nil {
		return netip.Prefix{}, err
	}
	p := netip.PrefixFrom(address, int(c.GetPrefixLength()))
	if !p.IsValid() || p != p.Masked() {
		return netip.Prefix{}, ErrUnsupported
	}
	return p, nil
}
func (c *compiledTable) typedRule(zone string, index int, r *resourcev1.FirewallRule) error {
	protocol := byte(unix.IPPROTO_TCP)
	switch r.GetProtocol() {
	case resourcev1.IPProtocol_IP_PROTOCOL_UDP:
		protocol = unix.IPPROTO_UDP
	case resourcev1.IPProtocol_IP_PROTOCOL_ICMP:
		protocol = unix.IPPROTO_ICMP
	case resourcev1.IPProtocol_IP_PROTOCOL_ICMPV6:
		protocol = unix.IPPROTO_ICMPV6
	}
	prefix := fmt.Sprintf("r%03d", index)
	first := prefix + "_0"
	e := append(familyMatch(r.GetFamily() == resourcev1.IPFamily_IP_FAMILY_IPV6), protocolMatch(protocol)...)
	if r.IcmpType != nil {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(r.GetIcmpType())}})
	}
	if r.IcmpCode != nil {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 1, Len: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(r.GetIcmpCode())}})
	}
	if err := c.rule(zone, append(e, &expr.Verdict{Kind: expr.VerdictJump, Chain: first})); err != nil {
		return err
	}
	stages := make([][][]expr.Any, 0, 4)
	for i, networks := range [][]*resourcev1.CIDR{r.GetSources(), r.GetDestinations()} {
		if len(networks) == 0 {
			continue
		}
		alternatives := make([][]expr.Any, 0, len(networks))
		for _, network := range networks {
			p, err := cidr(network)
			if err != nil {
				return err
			}
			alternatives = append(alternatives, addressMatch(p, i == 1))
		}
		stages = append(stages, alternatives)
	}
	for i, ports := range [][]*resourcev1.PortRange{r.GetSourcePorts(), r.GetDestinationPorts()} {
		if len(ports) == 0 {
			continue
		}
		alternatives := make([][]expr.Any, 0, len(ports))
		for _, port := range ports {
			alternatives = append(alternatives, portMatch(port, i == 1))
		}
		stages = append(stages, alternatives)
	}
	for i, alternatives := range stages {
		name := fmt.Sprintf("%s_%d", prefix, i)
		next := fmt.Sprintf("%s_%d", prefix, i+1)
		c.chain(name, nil)
		for _, match := range alternatives {
			if err := c.rule(name, append(match, &expr.Verdict{Kind: expr.VerdictGoto, Chain: next})); err != nil {
				return err
			}
		}
	}
	last := fmt.Sprintf("%s_%d", prefix, len(stages))
	c.chain(last, nil)
	return c.rule(last, []expr.Any{verdict(r.GetVerdict())})
}
func (c *compiledTable) management(chain string, config *agentv1.NativeFirewallProviderConfig) error {
	output := chain == "output"
	if err := c.rule(chain, append(interfaceMatch("lo", output), &expr.Verdict{Kind: expr.VerdictAccept})); err != nil {
		return err
	}
	// Only protected endpoint traffic is exempted, not all established flows.
	endpoints := config.GetManagementEndpoints()
	for _, endpoint := range endpoints {
		if err := c.endpoint(chain, endpoint.GetAddress(), endpoint.GetPort(), unix.IPPROTO_TCP); err != nil {
			return err
		}
	}
	for _, address := range config.GetDnsServers() {
		for _, protocol := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			if err := c.endpoint(chain, address, 53, protocol); err != nil {
				return err
			}
		}
	}
	// Neighbor discovery is necessary for the pinned IPv6 endpoint to remain
	// reachable. Limit exemptions to root-approved links and hop limit 255.
	for _, binding := range config.GetAllowedInterfaces() {
		for _, kind := range []byte{133, 134, 135, 136} {
			e := interfaceMatch(binding.GetIfname(), output)
			e = append(e, familyMatch(true)...)
			e = append(e, protocolMatch(unix.IPPROTO_ICMPV6)...)
			e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{255}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{kind}}, &expr.Verdict{Kind: expr.VerdictAccept})
			if err := c.rule(chain, e); err != nil {
				return err
			}
		}
	}
	for _, binding := range config.GetAllowedInterfaces() {
		for _, v6 := range []bool{false, true} {
			source, destination := uint32(68), uint32(67)
			if v6 {
				source, destination = 546, 547
			}
			if !output {
				source, destination = destination, source
			}
			e := interfaceMatch(binding.GetIfname(), output)
			e = append(e, familyMatch(v6)...)
			e = append(e, protocolMatch(unix.IPPROTO_UDP)...)
			e = append(e, portMatch(&resourcev1.PortRange{First: source, Last: source}, false)...)
			e = append(e, portMatch(&resourcev1.PortRange{First: destination, Last: destination}, true)...)
			if err := c.rule(chain, append(e, &expr.Verdict{Kind: expr.VerdictAccept})); err != nil {
				return err
			}
		}
		// Related ICMP errors preserve path-MTU discovery, not new TCP flows.
		for _, protocol := range []byte{unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6} {
			e := interfaceMatch(binding.GetIfname(), output)
			e = append(e, protocolMatch(protocol)...)
			e = append(e, conntrackState(expr.CtStateBitRELATED)...)
			if err := c.rule(chain, append(e, &expr.Verdict{Kind: expr.VerdictAccept})); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *compiledTable) endpoint(chain, address string, port uint32, protocol byte) error {
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
		return ErrUnsupported
	}
	output := chain == "output"
	e := addressMatch(netip.PrefixFrom(ip, ip.BitLen()), output)
	e = append(e, protocolMatch(protocol)...)
	e = append(e, portMatch(&resourcev1.PortRange{First: port, Last: port}, output)...)
	if !output {
		e = append(e, conntrackState(expr.CtStateBitESTABLISHED)...)
	}
	return c.rule(chain, append(e, &expr.Verdict{Kind: expr.VerdictAccept}))
}
func conntrackState(mask uint32) []expr.Any {
	return []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binary.NativeEndian.AppendUint32(nil, mask), Xor: []byte{0, 0, 0, 0}}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}}}
}
func (c *compiledTable) snapshot() *agentv1.FirewallNativeSnapshot {
	s := &agentv1.FirewallNativeSnapshot{Table: c.name}
	if len(c.chains) == 0 {
		return s
	}
	s.Userdata = c.userdata
	s.Chains = c.chains
	s.Rules = make([]*agentv1.FirewallNativeRule, len(c.rules))
	for i, r := range c.rules {
		s.Rules[i] = r.identity
	}
	return s
}
