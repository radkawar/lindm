// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connectivityguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Diagnostic tables have kernel socket ownership and NOT the persist flag. The
// kernel destroys them if the worker is killed, its socket closes, or on reboot.
// No rule grants or denies traffic: exact nonce selectors only enable nftrace.
// Foreign processes cannot acquire/modify a socket-owned table. There is no
// cleanup replay or best-effort foreign table deletion after a crash.
type packetTrace struct {
	nft      *nftables.Conn
	monitor  *netlink.Conn
	table    *nftables.Table
	marker   uint64
	id       uint32
	digest   hash.Hash
	seenHook bool
	target   *agentv1.ConnectivityProbeTarget
	applied  *agentv1.FirewallNativeSnapshot
	events   int
}

func startTrace(ctx context.Context, target *agentv1.ConnectivityProbeTarget, nonce []byte, applied *agentv1.FirewallNativeSnapshot) (*packetTrace, error) {
	source, destination, err := packetAddresses(target)
	if err != nil {
		return nil, err
	}
	if len(nonce) != 32 || applied == nil {
		return nil, ErrConflict
	}
	monitor, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{Groups: 1 << (unix.NFNLGRP_NFTRACE - 1)})
	if err != nil {
		return nil, err
	}
	if err := monitor.SetReadBuffer(1 << 20); err != nil {
		return nil, errors.Join(err, monitor.Close())
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, err := nftables.New(nftables.AsLasting(), nftables.WithSockOptions(func(c *netlink.Conn) error {
		return errors.Join(c.SetReadBuffer(1<<20), c.SetWriteBuffer(1<<16), c.SetDeadline(deadline))
	}))
	if err != nil {
		return nil, errors.Join(err, monitor.Close())
	}
	trace := &packetTrace{nft: conn, monitor: monitor, table: &nftables.Table{Name: "lindm_probe_" + hex.EncodeToString(nonce[:16]), Family: nftables.TableFamilyINet, Flags: nftables.TableFlagOwner}, digest: sha256.New(), target: target, applied: applied}
	fail := func(err error) (*packetTrace, error) { return nil, errors.Join(err, trace.close()) }
	hook := nftables.ChainHookPrerouting
	if target.GetDirection() == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT {
		hook = nftables.ChainHookOutput
	}
	policy := nftables.ChainPolicyAccept
	chain := &nftables.Chain{Name: "mark", Table: trace.table, Type: nftables.ChainTypeFilter, Hooknum: hook, Priority: nftables.ChainPriorityRef(-450), Policy: &policy}
	family := byte(unix.NFPROTO_IPV6)
	offset, size := uint32(8), uint32(16)
	if source.Is4() {
		family = unix.NFPROTO_IPV4
		offset, size = 12, 4
	}
	expressions := []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}}, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(packetProtocol(target))}}}
	match := func(base expr.PayloadBase, offset uint32, data []byte) {
		expressions = append(expressions, &expr.Payload{DestRegister: 1, Base: base, Offset: offset, Len: uint32(len(data))}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data})
	}
	match(expr.PayloadBaseNetworkHeader, offset, source.AsSlice())
	match(expr.PayloadBaseNetworkHeader, offset+size, destination.AsSlice())
	ports := binary.BigEndian.AppendUint16(nil, uint16(target.GetSourcePort()))
	ports = binary.BigEndian.AppendUint16(ports, uint16(target.GetPort()))
	match(expr.PayloadBaseTransportHeader, 0, ports)
	payloadOffset := uint32(8)
	if packetProtocol(target) == unix.IPPROTO_TCP {
		payloadOffset = 20
		match(expr.PayloadBaseTransportHeader, 12, []byte{0x50, 0x02})
	}
	match(expr.PayloadBaseTransportHeader, payloadOffset, nonce[:16])
	match(expr.PayloadBaseTransportHeader, payloadOffset+16, nonce[16:])
	expressions = append(expressions, &expr.Immediate{Register: 1, Data: []byte{1}}, &expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1})
	conn.AddTable(trace.table)
	conn.AddChain(chain)
	conn.AddRule(&nftables.Rule{Table: trace.table, Chain: chain, Exprs: expressions, UserData: nonce})
	// A last-priority empty base chain is a trace observation point, not an
	// exemption. Its ACCEPT policy cannot override another base chain's DROP.
	// It also lets release-to-absence prove effective connectivity without
	// inventing a rule handle for the table that was deliberately removed.
	witnessHook := nftables.ChainHookInput
	if target.GetDirection() == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT {
		witnessHook = nftables.ChainHookOutput
	} else if target.GetDirection() == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_FORWARD {
		witnessHook = nftables.ChainHookForward
	}
	conn.AddChain(&nftables.Chain{Name: "witness", Table: trace.table, Type: nftables.ChainTypeFilter, Hooknum: witnessHook, Priority: nftables.ChainPriorityRef(2147483647), Policy: &policy})
	// The native helper itself has a bounded lifetime; the permanent netlink
	// socket is additionally closed on context cancellation to unblock a kernel
	// request rather than stalling rollback behind an orphaned helper.
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseLasting() })
	defer stop()
	if err := conn.Flush(); err != nil {
		return fail(err)
	}
	tables, err := conn.ListTables()
	if err != nil {
		return fail(err)
	}
	owned := false
	for _, table := range tables {
		if table.Name == trace.table.Name && table.Family == trace.table.Family && table.Flags == nftables.TableFlagOwner && table.Owner != 0 {
			owned = true
		}
	}
	if !owned {
		return fail(ErrConflict)
	}
	rules, err := conn.GetRules(trace.table, chain)
	if err != nil {
		return fail(err)
	}
	if len(rules) != 1 || !bytes.Equal(rules[0].UserData, nonce) || rules[0].Handle == 0 {
		return fail(ErrConflict)
	}
	trace.marker = rules[0].Handle
	return trace, nil
}
func (t *packetTrace) close() error { return errors.Join(t.monitor.Close(), t.nft.CloseLasting()) }

type traceEvent struct {
	table, chain string
	family       nftables.TableFamily
	handle       uint64
	id, kind     uint32
	verdict      uint32
	hasVerdict   bool
}

func decodeTrace(data []byte) (traceEvent, error) {
	var event traceEvent
	if len(data) < 4 {
		return event, ErrConflict
	}
	event.family = nftables.TableFamily(data[0])
	attributes, err := netlink.UnmarshalAttributes(data[4:])
	if err != nil {
		return event, err
	}
	seen := map[uint16]bool{}
	for _, attribute := range attributes {
		kind := attribute.Type & 0x3fff
		if seen[kind] {
			return event, ErrConflict
		}
		seen[kind] = true
		switch kind {
		case 1, 2:
			if len(attribute.Data) == 0 || attribute.Data[len(attribute.Data)-1] != 0 {
				return event, ErrConflict
			}
			value := string(attribute.Data[:len(attribute.Data)-1])
			if kind == 1 {
				event.table = value
			} else {
				event.chain = value
			}
		case 3:
			if len(attribute.Data) != 8 {
				return event, ErrConflict
			}
			event.handle = binary.BigEndian.Uint64(attribute.Data)
		case 4, 6, 16:
			if len(attribute.Data) != 4 {
				return event, ErrConflict
			}
			value := binary.BigEndian.Uint32(attribute.Data)
			switch kind {
			case 4:
				event.kind = value
			case 6:
				event.id = value
			case 16:
				event.verdict = value
				event.hasVerdict = true
			}
		case 5:
			nested, err := netlink.UnmarshalAttributes(attribute.Data)
			if err != nil {
				return event, err
			}
			for _, verdict := range nested {
				if verdict.Type&0x3fff == 1 {
					if len(verdict.Data) != 4 {
						return event, ErrConflict
					}
					event.verdict = binary.BigEndian.Uint32(verdict.Data)
					event.hasVerdict = true
				}
			}
		}
	}
	if event.id == 0 || event.table == "" || event.chain == "" {
		return event, ErrConflict
	}
	return event, nil
}
func (t *packetTrace) observe(ctx context.Context) (*agentv1.ConnectivityProbeEvidence, error) {
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := t.monitor.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	hook := uint32(unix.NF_INET_LOCAL_IN)
	if t.target.GetDirection() == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT {
		hook = unix.NF_INET_LOCAL_OUT
	} else if t.target.GetDirection() == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_FORWARD {
		hook = unix.NF_INET_FORWARD
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		messages, err := t.monitor.Receive()
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			t.events++
			if t.events > 4096 || len(message.Data) > 16384 {
				return nil, ErrUnconfirmed
			}
			if message.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_TRACE) {
				continue
			}
			event, err := decodeTrace(message.Data)
			if err != nil {
				return nil, err
			}
			if t.id == 0 && event.family == nftables.TableFamilyINet && event.table == t.table.Name && event.chain == "mark" && event.handle == t.marker {
				t.id = event.id
			}
			if t.id == 0 || event.id != t.id {
				continue
			}
			_, _ = t.digest.Write(message.Data)
			// Hooks, not caller labels, establish INPUT/OUTPUT/FORWARD evidence.
			// A foreign DROP is real effective denial but never transfers ownership.
			// Query only the exact traced chain, never list/flush a foreign ruleset.
			if event.family != nftables.TableFamilyINet || event.table != t.table.Name || event.chain == "witness" {
				nativeChain, err := t.nft.ListChain(&nftables.Table{Name: event.table, Family: event.family}, event.chain)
				if err != nil {
					return nil, err
				}
				if nativeChain.Hooknum != nil && uint32(*nativeChain.Hooknum) == hook {
					t.seenHook = true
				}
			}
			if !t.seenHook || !event.hasVerdict || (event.verdict != 0 && event.verdict != 1) {
				continue
			}
			if event.family == nftables.TableFamilyINet && event.table == t.applied.GetTable() {
				known := false
				if event.kind == 1 && event.handle == 0 {
					for _, chain := range t.applied.GetChains() {
						if chain.GetName() == event.chain && chain.Hook != nil && chain.GetHook() == hook && chain.Policy != nil && chain.GetPolicy() == event.verdict {
							known = true
						}
					}
				} else {
					for _, rule := range t.applied.GetRules() {
						if rule.GetChain() == event.chain && rule.GetHandle() == event.handle && event.handle != 0 {
							known = true
						}
					}
				}
				if !known {
					return nil, ErrConflict
				}
			}
			expected := uint32(0)
			if t.target.GetExpected() == agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW {
				expected = 1
			}
			if event.verdict != expected {
				if event.verdict == 0 {
					return nil, ErrUnconfirmed
				}
				continue
			}
			// An ALLOW additionally requires actual post-filter receiver evidence;
			// a mere ACCEPT in one table is deliberately insufficient on its own.
			source, _, err := packetAddresses(t.target)
			if err != nil {
				return nil, err
			}
			family := uint32(6)
			if source.Is4() {
				family = 4
			}
			return &agentv1.ConnectivityProbeEvidence{Target: t.target, AddressFamily: family, Table: event.table, Chain: event.chain, RuleHandle: event.handle, TraceId: event.id, NativeVerdict: event.verdict, TraceSha256: t.digest.Sum(nil)}, nil
		}
	}
}
