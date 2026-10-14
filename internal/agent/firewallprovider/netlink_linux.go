// SPDX-License-Identifier: Apache-2.0

//go:build linux

package firewallprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
)

// The maintained nftables package encodes all expressions. This narrow adjunct
// exists because its Table/Chain APIs omit userdata, and its rule decoder drops
// unknown expressions. We retain the actual kernel expression bytes' digest and
// reject unmodelled object attributes, rather than trusting a lossy round trip.
// Netlink framing, sequence validation and attribute encoding remain mdlayher's.
const (
	tableUserdata = 6
	chainUserdata = 12
	// Stable Linux UAPI attributes not exported by x/sys/unix.
	tableHandle       = 4
	tablePad          = 5
	bitwiseOp         = 6
	attributeTypeMask = ^(netlink.Nested | netlink.NetByteOrder)
	acceptPolicy      = uint32(nftables.ChainPolicyAccept)
	chainFlags        = 10
	maxNativeBytes    = 1024 * 1024
)

type nativeConn struct {
	conn     *netlink.Conn
	deadline time.Time
}

func openNetlink(ctx context.Context) (*nativeConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, err := dialNetlink(deadline)
	if err != nil {
		return nil, err
	}
	return &nativeConn{conn: conn, deadline: deadline}, nil
}
func dialNetlink(deadline time.Time) (*netlink.Conn, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if err := conn.SetReadBuffer(maxNativeBytes); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if err := conn.SetWriteBuffer(maxNativeBytes); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return conn, nil
}

// redial replaces the socket after a batch: a batch replayed by the kernel for
// module autoloading can leave late duplicate acknowledgments queued, which must
// not be read as replies to the following observation.
func (n *nativeConn) redial() error {
	conn, err := dialNetlink(n.deadline)
	if err != nil {
		return err
	}
	old := n.conn
	n.conn = conn
	return old.Close()
}
func (n *nativeConn) close() error { return n.conn.Close() }
func objectMessage(kind uint16, flags netlink.HeaderFlags, attrs []netlink.Attribute) (netlink.Message, error) {
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return netlink.Message{}, err
	}
	return netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | kind), Flags: netlink.Request | flags}, Data: append([]byte{unix.NFPROTO_INET, 0, 0, 0}, data...)}, nil
}
func (n *nativeConn) query(kind uint16, attrs []netlink.Attribute, dump bool) ([]netlink.Message, error) {
	flags := netlink.HeaderFlags(0)
	if dump {
		flags = netlink.Dump
	}
	message, err := objectMessage(kind, flags, attrs)
	if err != nil {
		return nil, err
	}
	messages, err := n.conn.Execute(message)
	if err != nil {
		return nil, err
	}
	total := 0
	for _, m := range messages {
		total += len(m.Data)
		if len(m.Data) < 4 || (kind != unix.NFT_MSG_GETGEN && m.Data[0] != unix.NFPROTO_INET) || total > maxNativeBytes || len(messages) > 6144 || m.Header.Flags&netlink.DumpInterrupted != 0 {
			return nil, ErrUnsupported
		}
	}
	return messages, nil
}
func decodeAttrs(message netlink.Message) (map[uint16][]byte, error) {
	if len(message.Data) < 4 {
		return nil, ErrConflict
	}
	attrs, err := netlink.UnmarshalAttributes(message.Data[4:])
	if err != nil {
		return nil, err
	}
	result := make(map[uint16][]byte, len(attrs))
	for _, a := range attrs {
		kind := a.Type & attributeTypeMask
		messageKind := uint16(message.Header.Type) & 255
		pad := uint16(0)
		switch messageKind {
		case unix.NFT_MSG_NEWTABLE:
			pad = tablePad
		case unix.NFT_MSG_NEWCHAIN:
			pad = unix.NFTA_CHAIN_PAD
		case unix.NFT_MSG_NEWRULE:
			pad = unix.NFTA_RULE_PAD
		}
		if pad != 0 && kind == pad && len(a.Data) == 0 {
			continue
		}
		if _, exists := result[kind]; exists {
			return nil, ErrConflict
		}
		result[kind] = a.Data
	}
	return result, nil
}
func exactString(data []byte) (string, error) {
	if len(data) == 0 || data[len(data)-1] != 0 || bytes.IndexByte(data[:len(data)-1], 0) >= 0 {
		return "", ErrConflict
	}
	return string(data[:len(data)-1]), nil
}
func fieldU32(data []byte) (uint32, error) {
	if len(data) != 4 {
		return 0, ErrConflict
	}
	return binary.BigEndian.Uint32(data), nil
}
func (n *nativeConn) generation() (uint32, error) {
	messages, err := n.query(unix.NFT_MSG_GETGEN, nil, false)
	if err != nil {
		return 0, err
	}
	if len(messages) != 1 {
		return 0, ErrConflict
	}
	a, err := decodeAttrs(messages[0])
	if err != nil {
		return 0, err
	}
	generation, err := fieldU32(a[unix.NFTA_GEN_ID])
	if err != nil || generation == 0 {
		return 0, errors.Join(ErrConflict, err)
	}
	return generation, nil
}
func tableAttr(name string) netlink.Attribute {
	return netlink.Attribute{Type: 1, Data: []byte(name + "\x00")}
}
func (n *nativeConn) observe(table string) (*agentv1.FirewallNativeSnapshot, []string, error) {
	generation, err := n.generation()
	if err != nil {
		return nil, nil, err
	}
	snapshot := &agentv1.FirewallNativeSnapshot{Table: table, RulesetGeneration: generation}
	tables, err := n.query(unix.NFT_MSG_GETTABLE, nil, true)
	if err != nil {
		return nil, nil, err
	}
	if len(tables) > 256 {
		return nil, nil, ErrUnsupported
	}
	var foreign []string
	exists := false
	for _, message := range tables {
		a, err := decodeAttrs(message)
		if err != nil {
			return nil, nil, err
		}
		name, err := exactString(a[unix.NFTA_TABLE_NAME])
		if err != nil {
			return nil, nil, err
		}
		if name != table {
			foreign = append(foreign, name)
			continue
		}
		exists = true
		snapshot.Userdata = bytes.Clone(a[tableUserdata])
		flags, err := fieldU32(a[unix.NFTA_TABLE_FLAGS])
		if err != nil {
			return nil, nil, err
		}
		if flags != 0 {
			snapshot.Conflict = true
		}
		for kind := range a {
			switch kind {
			case unix.NFTA_TABLE_NAME, unix.NFTA_TABLE_FLAGS, unix.NFTA_TABLE_USE, tableHandle, tablePad, tableUserdata:
			default:
				snapshot.Conflict = true
			}
		}
	}
	if exists {
		chains, err := n.query(unix.NFT_MSG_GETCHAIN, []netlink.Attribute{tableAttr(table)}, true)
		if err != nil {
			return nil, nil, err
		}
		if len(chains) > 2048 {
			return nil, nil, ErrUnsupported
		}
		for _, message := range chains {
			if matches, err := objectInTable(message, table); err != nil {
				return nil, nil, err
			} else if !matches {
				continue
			}
			chain, conflict, err := decodeChain(message, table)
			if err != nil {
				return nil, nil, err
			}
			snapshot.Conflict = snapshot.Conflict || conflict
			snapshot.Chains = append(snapshot.Chains, chain)
		}
		rules, err := n.query(unix.NFT_MSG_GETRULE, []netlink.Attribute{tableAttr(table)}, true)
		if err != nil {
			return nil, nil, err
		}
		if len(rules) > 4096 {
			return nil, nil, ErrUnsupported
		}
		for _, message := range rules {
			if matches, err := objectInTable(message, table); err != nil {
				return nil, nil, err
			} else if !matches {
				continue
			}
			rule, conflict, err := decodeRule(message, table)
			if err != nil {
				return nil, nil, err
			}
			snapshot.Conflict = snapshot.Conflict || conflict
			snapshot.Rules = append(snapshot.Rules, rule)
		}
		// A dedicated table may contain only the compiled chains/rules. In
		// particular, release must never delete a foreign set, object or flowtable.
		for _, kind := range []uint16{unix.NFT_MSG_GETSET, unix.NFT_MSG_GETOBJ, unix.NFT_MSG_GETFLOWTABLE} {
			objects, err := n.query(kind, []netlink.Attribute{tableAttr(table)}, true)
			if err != nil {
				return nil, nil, err
			}
			for _, object := range objects {
				matches, err := objectInTable(object, table)
				if err != nil {
					return nil, nil, err
				}
				if matches {
					snapshot.Conflict = true
				}
			}
		}
		if len(snapshot.Userdata) == 0 {
			snapshot.Conflict = true
		}
	}
	after, err := n.generation()
	if err != nil {
		return nil, nil, err
	}
	if after != generation {
		return nil, nil, ErrConflict
	}
	slices.Sort(foreign)
	sortNative(snapshot)
	return snapshot, foreign, nil
}
func objectInTable(message netlink.Message, table string) (bool, error) {
	attrs, err := decodeAttrs(message)
	if err != nil {
		return false, err
	}
	name, err := exactString(attrs[1])
	return name == table, err
}
func decodeChain(message netlink.Message, table string) (*agentv1.FirewallNativeChain, bool, error) {
	a, err := decodeAttrs(message)
	if err != nil {
		return nil, false, err
	}
	name, err := exactString(a[unix.NFTA_CHAIN_TABLE])
	if err != nil || name != table {
		return nil, false, ErrConflict
	}
	name, err = exactString(a[unix.NFTA_CHAIN_NAME])
	if err != nil {
		return nil, false, err
	}
	c := &agentv1.FirewallNativeChain{Name: name, Userdata: bytes.Clone(a[chainUserdata])}
	conflict := len(c.Userdata) == 0
	for kind, data := range a {
		switch kind {
		case unix.NFTA_CHAIN_TABLE, unix.NFTA_CHAIN_NAME, unix.NFTA_CHAIN_HANDLE, unix.NFTA_CHAIN_USE, unix.NFTA_CHAIN_PAD, chainUserdata:
		case chainFlags:
		case unix.NFTA_CHAIN_TYPE:
			c.Type, err = exactString(data)
		case unix.NFTA_CHAIN_POLICY:
			var value uint32
			value, err = fieldU32(data)
			c.Policy = proto.Uint32(value)
		case unix.NFTA_CHAIN_HOOK:
			var attrs []netlink.Attribute
			attrs, err = netlink.UnmarshalAttributes(data)
			if err != nil {
				break
			}
			for _, attr := range attrs {
				switch attr.Type & attributeTypeMask {
				case unix.NFTA_HOOK_HOOKNUM:
					var value uint32
					value, err = fieldU32(attr.Data)
					c.Hook = proto.Uint32(value)
				case unix.NFTA_HOOK_PRIORITY:
					var value uint32
					value, err = fieldU32(attr.Data)
					c.Priority = proto.Int32(int32(value))
				default:
					conflict = true
				}
				if err != nil {
					break
				}
			}
		case unix.NFTA_CHAIN_COUNTERS: // Base-chain packet/byte counters are volatile.
		default:
			conflict = true
		}
		if err != nil {
			return nil, false, err
		}
	}
	if data, ok := a[chainFlags]; ok {
		flags, err := fieldU32(data)
		if err != nil {
			return nil, false, err
		}
		expected := uint32(0)
		if c.Hook != nil {
			expected = 1
		}
		if flags != expected {
			conflict = true
		}
	}
	return c, conflict, nil
}
func decodeRule(message netlink.Message, table string) (*agentv1.FirewallNativeRule, bool, error) {
	a, err := decodeAttrs(message)
	if err != nil {
		return nil, false, err
	}
	name, err := exactString(a[unix.NFTA_RULE_TABLE])
	if err != nil || name != table {
		return nil, false, ErrConflict
	}
	chain, err := exactString(a[unix.NFTA_RULE_CHAIN])
	if err != nil {
		return nil, false, err
	}
	r := &agentv1.FirewallNativeRule{Chain: chain, Userdata: bytes.Clone(a[unix.NFTA_RULE_USERDATA])}
	conflict := len(r.Userdata) == 0
	if len(a[unix.NFTA_RULE_HANDLE]) != 8 {
		return nil, false, ErrConflict
	}
	r.Handle = binary.BigEndian.Uint64(a[unix.NFTA_RULE_HANDLE])
	raw, ok := a[unix.NFTA_RULE_EXPRESSIONS]
	if !ok {
		return nil, false, ErrConflict
	}
	rawDigest := sha256.Sum256(raw)
	r.RawExpressionsSha256 = rawDigest[:]
	digest, err := expressionDigest(raw)
	if err != nil {
		conflict = true
		r.ExpressionsSha256 = rawDigest[:]
	} else {
		r.ExpressionsSha256 = digest
	}
	for kind, data := range a {
		switch kind {
		case unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN, unix.NFTA_RULE_HANDLE, unix.NFTA_RULE_EXPRESSIONS, unix.NFTA_RULE_USERDATA, unix.NFTA_RULE_PAD:
		case unix.NFTA_RULE_POSITION:
			if len(data) != 8 {
				conflict = true
			}
		default:
			conflict = true
		}
	}
	return r, conflict, nil
}
func sortNative(s *agentv1.FirewallNativeSnapshot) {
	slices.SortFunc(s.Chains, func(a, b *agentv1.FirewallNativeChain) int { return strings.Compare(a.GetName(), b.GetName()) })
	slices.SortStableFunc(s.Rules, func(a, b *agentv1.FirewallNativeRule) int { return strings.Compare(a.GetChain(), b.GetChain()) })
}
func nativeDigest(s *agentv1.FirewallNativeSnapshot) ([]byte, error) {
	return journal.FirewallNativeIdentity(s)
}
func nativeEqual(a, b *agentv1.FirewallNativeSnapshot) bool {
	x, err := nativeDigest(a)
	if err != nil {
		return false
	}
	y, err := nativeDigest(b)
	return err == nil && bytes.Equal(x, y)
}
func replacementMessages(before *agentv1.FirewallNativeSnapshot, target *compiledTable) ([]netlink.Message, error) {
	var messages []netlink.Message
	appendMessage := func(kind uint16, flags netlink.HeaderFlags, attrs []netlink.Attribute) error {
		message, err := objectMessage(kind, flags|netlink.Acknowledge, attrs)
		if err != nil {
			return err
		}
		messages = append(messages, message)
		return nil
	}
	if len(before.GetUserdata()) != 0 {
		if err := appendMessage(unix.NFT_MSG_DELTABLE, 0, []netlink.Attribute{tableAttr(before.GetTable())}); err != nil {
			return nil, err
		}
	}
	if len(target.chains) == 0 {
		return messages, nil
	}
	if err := appendMessage(unix.NFT_MSG_NEWTABLE, netlink.Create|netlink.Excl, []netlink.Attribute{tableAttr(target.name), {Type: unix.NFTA_TABLE_FLAGS, Data: u32(0)}, {Type: tableUserdata, Data: target.userdata}}); err != nil {
		return nil, err
	}
	for _, c := range target.chains {
		attrs := []netlink.Attribute{tableAttr(target.name), {Type: unix.NFTA_CHAIN_NAME, Data: []byte(c.GetName() + "\x00")}, {Type: chainUserdata, Data: c.GetUserdata()}}
		if c.Hook != nil {
			hook, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_HOOK_HOOKNUM, Data: u32(c.GetHook())}, {Type: unix.NFTA_HOOK_PRIORITY, Data: u32(uint32(c.GetPriority()))}})
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_CHAIN_HOOK, Data: hook}, netlink.Attribute{Type: unix.NFTA_CHAIN_TYPE, Data: []byte("filter\x00")}, netlink.Attribute{Type: unix.NFTA_CHAIN_POLICY, Data: u32(acceptPolicy)})
		}
		if err := appendMessage(unix.NFT_MSG_NEWCHAIN, netlink.Create|netlink.Excl, attrs); err != nil {
			return nil, err
		}
	}
	for _, r := range target.rules {
		attrs := []netlink.Attribute{tableAttr(target.name), {Type: unix.NFTA_RULE_CHAIN, Data: []byte(r.identity.GetChain() + "\x00")}, {Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: r.expressions}, {Type: unix.NFTA_RULE_USERDATA, Data: r.identity.GetUserdata()}}
		if err := appendMessage(unix.NFT_MSG_NEWRULE, netlink.Create|netlink.Append, attrs); err != nil {
			return nil, err
		}
	}
	return messages, nil
}

// errGenerationChanged reports that the kernel refused a whole batch because
// the ruleset generation moved after the snapshot (NFNL_BATCH_GENID). The
// kernel checks it before the first object message, so nothing was applied.
var errGenerationChanged = errors.New("firewallprovider: ruleset generation changed")

// maxGenerationAttempts bounds batches refused by foreign generation bumps,
// such as firewalld starting or reloading beside the boot restoration.
const maxGenerationAttempts = 3

func (n *nativeConn) replace(before *agentv1.FirewallNativeSnapshot, target *compiledTable) error {
	for attempt := 1; ; attempt++ {
		err := n.sendReplacement(before, target)
		if redialErr := n.redial(); redialErr != nil {
			return errors.Join(ErrOutcomeUnknown, err, redialErr)
		}
		if !errors.Is(err, errGenerationChanged) {
			return err
		}
		if attempt == maxGenerationAttempts {
			return fmt.Errorf("%w: %w", ErrConflict, err)
		}
		// Another writer changed some table. Retry the identical atomic batch only
		// while lindm's own table still has exactly the observed state.
		fresh, _, err := n.observe(before.GetTable())
		if err != nil {
			return err
		}
		if !nativeEqual(fresh, before) {
			return ErrConflict
		}
		before = fresh
	}
}
func (n *nativeConn) sendReplacement(before *agentv1.FirewallNativeSnapshot, target *compiledTable) error {
	messages, err := replacementMessages(before, target)
	if err != nil {
		return err
	}
	if len(messages) == 0 {
		return nil
	}
	generation, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFNL_BATCH_GENID, Data: u32(before.GetRulesetGeneration())}})
	if err != nil {
		return err
	}
	batch := make([]netlink.Message, 0, len(messages)+2)
	batch = append(batch, netlink.Message{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_BEGIN, Flags: netlink.Request}, Data: append([]byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}, generation...)})
	batch = append(batch, messages...)
	batch = append(batch, netlink.Message{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_END, Flags: netlink.Request}, Data: []byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}})
	total := 0
	for _, m := range batch {
		total += len(m.Data) + 16
	}
	if total > maxNativeBytes {
		return ErrUnsupported
	}
	sent, err := n.conn.SendMessages(batch)
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	acks := newBatchAcks(sent)
	for acks.remaining != 0 {
		replies, err := n.conn.Receive()
		if err != nil {
			return receiveFailure(err, acks.remaining != len(messages))
		}
		if len(replies) == 0 {
			return ErrOutcomeUnknown
		}
		for _, reply := range replies {
			if err := acks.accept(reply); err != nil {
				return err
			}
		}
	}
	return nil
}

// receiveFailure classifies an error while reading a batch's acknowledgments.
// The netlink library reports a nonzero acknowledgment as a receive error.
// nfnetlink answers a stale NFNL_BATCH_GENID with ERESTART on BATCH_BEGIN before
// processing any object, so ERESTART ahead of every object acknowledgment is
// effect-free; anything else may have been applied.
func receiveFailure(err error, acknowledged bool) error {
	if errors.Is(err, unix.ERESTART) && !acknowledged {
		return errGenerationChanged
	}
	return errors.Join(ErrOutcomeUnknown, err)
}

// batchAcks tracks the object acknowledgments of one sent batch (BATCH_BEGIN
// and BATCH_END are not acknowledged). A kernel that replays the batch after
// autoloading a module (observed at boot on EL 9's 5.14 kernel) acknowledges an
// object twice; the repeat is accepted because the applied table is verified
// independently by read-back. Anything else leaves the outcome unknown.
type batchAcks struct {
	objects    map[uint32]bool // sequence -> already acknowledged
	begin, end uint32
	remaining  int
}

func newBatchAcks(sent []netlink.Message) *batchAcks {
	a := &batchAcks{objects: make(map[uint32]bool, len(sent)-2), begin: sent[0].Header.Sequence, end: sent[len(sent)-1].Header.Sequence, remaining: len(sent) - 2}
	for _, m := range sent[1 : len(sent)-1] {
		a.objects[m.Header.Sequence] = false
	}
	return a
}

func (a *batchAcks) accept(ack netlink.Message) error {
	if ack.Header.Type != netlink.Error || len(ack.Data) < 4 {
		return fmt.Errorf("%w: invalid batch acknowledgment type %d sequence %d", ErrOutcomeUnknown, ack.Header.Type, ack.Header.Sequence)
	}
	code := int32(binary.NativeEndian.Uint32(ack.Data[:4]))
	acknowledged, object := a.objects[ack.Header.Sequence]
	if object && code == 0 {
		if !acknowledged {
			a.objects[ack.Header.Sequence] = true
			a.remaining--
		}
		return nil
	}
	var kind, flags uint16
	if len(ack.Data) >= 20 {
		kind, flags = binary.NativeEndian.Uint16(ack.Data[8:10]), binary.NativeEndian.Uint16(ack.Data[10:12])
	}
	return fmt.Errorf("%w: batch acknowledgment errno %d for request type %#x flags %#x sequence %d (batch %d..%d)", ErrOutcomeUnknown, -code, kind, flags, ack.Header.Sequence, a.begin, a.end)
}
