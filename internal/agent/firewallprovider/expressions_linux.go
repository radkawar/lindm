// SPDX-License-Identifier: Apache-2.0

//go:build linux

package firewallprovider

import (
	"bytes"
	"crypto/sha256"
	"slices"

	"github.com/mdlayher/netlink"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// expressionDigest normalizes only netlink attribute ordering/transport flags
// and the kernel's explicit boolean-bitwise default. It never decodes through
// nftables' lossy unknown-expression fallback. Every expression, attribute and
// value remains present, so unknown data changes the digest or fails closed.
// Separately stored raw_expressions_sha256 binds the exact kernel read-back bytes
// for release: normalization does not weaken drift/ownership byte identity.
func expressionDigest(raw []byte) ([]byte, error) {
	list, err := netlink.UnmarshalAttributes(raw)
	if err != nil {
		return nil, err
	}
	for index, item := range list {
		if item.Type&attributeTypeMask != unix.NFTA_LIST_ELEM {
			return nil, ErrConflict
		}
		fields, err := netlink.UnmarshalAttributes(item.Data)
		if err != nil {
			return nil, err
		}
		name := ""
		for _, field := range fields {
			if field.Type&attributeTypeMask == unix.NFTA_EXPR_NAME {
				name, err = exactString(field.Data)
				if err != nil {
					return nil, err
				}
			}
		}
		switch name {
		case "meta", "payload", "cmp", "range", "bitwise", "immediate", "reject", "ct":
		default:
			return nil, ErrUnsupported
		}
		for i, field := range fields {
			kind := field.Type & attributeTypeMask
			if kind == unix.NFTA_EXPR_DATA {
				data, err := canonicalAttributes(field.Data, name)
				if err != nil {
					return nil, err
				}
				fields[i].Data = data
			} else if kind != unix.NFTA_EXPR_NAME {
				return nil, ErrUnsupported
			}
			// MarshalAttributes keeps a decoded nonzero Length: a dropped
			// default attribute would otherwise leave a stale header length.
			fields[i].Type, fields[i].Length = kind, 0
		}
		if len(fields) != 2 {
			return nil, ErrConflict
		}
		slices.SortFunc(fields, attributeOrder)
		data, err := netlink.MarshalAttributes(fields)
		if err != nil {
			return nil, err
		}
		list[index] = netlink.Attribute{Type: unix.NFTA_LIST_ELEM, Data: data}
	}
	data, err := netlink.MarshalAttributes(list)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}
func attributeOrder(a, b netlink.Attribute) int { return int(a.Type) - int(b.Type) }
func canonicalAttributes(raw []byte, kind string) ([]byte, error) {
	attrs, err := netlink.UnmarshalAttributes(raw)
	if err != nil {
		return nil, err
	}
	result := attrs[:0]
	seen := map[uint16]bool{}
	for _, a := range attrs {
		a.Type &= attributeTypeMask
		a.Length = 0
		if seen[a.Type] {
			return nil, ErrConflict
		}
		seen[a.Type] = true
		nested := ""
		switch kind {
		case "cmp":
			if a.Type == unix.NFTA_CMP_DATA {
				nested = "data"
			}
		case "range":
			if a.Type == unix.NFTA_RANGE_FROM_DATA || a.Type == unix.NFTA_RANGE_TO_DATA {
				nested = "data"
			}
		case "bitwise":
			if a.Type == bitwiseOp && bytes.Equal(a.Data, []byte{0, 0, 0, 0}) {
				continue
			}
			if a.Type == unix.NFTA_BITWISE_MASK || a.Type == unix.NFTA_BITWISE_XOR {
				nested = "data"
			}
		case "immediate":
			if a.Type == unix.NFTA_IMMEDIATE_DATA {
				nested = "data"
			}
		case "data":
			if a.Type == unix.NFTA_DATA_VERDICT {
				nested = "verdict"
			}
		}
		if nested != "" {
			a.Data, err = canonicalAttributes(a.Data, nested)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, a)
	}
	slices.SortFunc(result, attributeOrder)
	return netlink.MarshalAttributes(result)
}
func rawExpressionsMatch(a, b []*agentv1.FirewallNativeRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i, r := range a {
		if r.GetChain() != b[i].GetChain() || len(r.GetRawExpressionsSha256()) != 32 || !bytes.Equal(r.GetRawExpressionsSha256(), b[i].GetRawExpressionsSha256()) {
			return false
		}
	}
	return true
}
