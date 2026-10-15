// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Separate census and authority probes are intentional: huge immutable file
// lists, unavailable header export, and slow RPMDB reads cannot erase an
// otherwise successful package census. Evidence joins the exact native tuple
// and module; a package changed between probes cannot inherit another header.
var rpmAuthorityBackend = backend{
	name: "rpm", path: "/usr/bin/rpm",
	args: []string{"--query", "--all", "--queryformat", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{MODULARITYLABEL}\t%{HEADERIMMUTABLE}\t%{RSAHEADER}\n"},
}

// RPM 4.16 and 4.19 have no :json formatter. Their unformatted BIN values
// are unwrapped hexadecimal, unlike :base64 (which inserts embedded newlines).
// Keep this bound independent of the small census line bound. A larger header
// is drained without allocation and degrades only its own package authority.
const maxRpmAuthorityRecordBytes = 2 << 20

func rpmAuthorityIdentity(record []byte) *inventoryv1.Package {
	end := 0
	for range 6 {
		next := bytes.IndexByte(record[end:], '\t')
		if next < 0 {
			return nil
		}
		end += next + 1
	}
	if end > maxLineBytes {
		return nil
	}
	p, err := parsePackageLine(string(record[:end-1]), "rpm")
	if err != nil {
		return nil
	}
	return p
}

func parseRpmAuthority(ctx context.Context, input io.Reader, limits parseLimits) ([]*inventoryv1.Package, inventoryv1.CollectionStatus) {
	limited := &io.LimitedReader{R: input, N: limits.bytes + 1}
	reader := bufio.NewReaderSize(limited, maxRpmAuthorityRecordBytes)
	var packages []*inventoryv1.Package
	var count, encoded int
	for {
		if ctx.Err() != nil {
			return nil, statusFor(ctx.Err())
		}
		record, err := reader.ReadSlice('\n')
		if limited.N == 0 {
			return nil, capacity
		}
		if errors.Is(err, io.EOF) {
			if len(record) != 0 {
				return nil, invalid
			}
			break
		}
		var p *inventoryv1.Package
		if errors.Is(err, bufio.ErrBufferFull) {
			p = rpmAuthorityIdentity(record)
			if p != nil {
				p.RpmAuthority = &inventoryv1.RpmAuthority{Status: capacity}
			}
			// The identity has its own small bound; do not retain or copy the
			// oversized optional bytes while draining this physical record.
			for errors.Is(err, bufio.ErrBufferFull) {
				if ctx.Err() != nil {
					return nil, statusFor(ctx.Err())
				}
				_, err = reader.ReadSlice('\n')
				if limited.N == 0 {
					return nil, capacity
				}
			}
			if err != nil {
				return nil, invalid
			}
		} else {
			if err != nil {
				return nil, invalid
			}
			p, err = parsePackageLine(string(record[:len(record)-1]), "rpm")
			if err != nil {
				p = rpmAuthorityIdentity(record)
				if p != nil {
					p.RpmAuthority = &inventoryv1.RpmAuthority{Status: statusFor(err)}
				}
			}
		}
		count++
		if count > limits.records {
			return nil, capacity
		}
		// Malformed identity cannot join any census row; that row remains
		// explicitly unavailable rather than borrowing another package's proof.
		if p == nil {
			continue
		}
		encoded += proto.Size(p) + 6
		if int64(encoded) > limits.bytes {
			return nil, capacity
		}
		packages = append(packages, p)
	}
	return packages, success
}

// Mirrors spool.MaxBatchEncoded and device/core.MaxBatchBytes: even a single
// record plus its PackageBatch framing must fit the existing upload protocol.
const maxRpmPackageWire = 768 << 10

func attachRpmAuthority(ctx context.Context, packages []*inventoryv1.Package, run nativeRunner, byteBudget int64) {
	var evidence []*inventoryv1.Package
	status := run(ctx, rpmAuthorityBackend, func(reader io.Reader) inventoryv1.CollectionStatus {
		var parsed inventoryv1.CollectionStatus
		evidence, parsed = parseRpmAuthority(ctx, reader, parseLimits{maxRecords, byteBudget})
		return parsed
	})
	if ctx.Err() != nil {
		status = statusFor(ctx.Err())
	}
	if status != success {
		for _, p := range packages {
			p.RpmAuthority = &inventoryv1.RpmAuthority{Status: status}
		}
		return
	}
	type tuple struct{ name, version, arch string }
	indexed := make(map[tuple]*inventoryv1.Package, len(evidence))
	for _, p := range evidence {
		key := tuple{p.Name, p.Version, p.Architecture}
		if previous, exists := indexed[key]; exists && (previous == nil || !proto.Equal(previous, p)) {
			indexed[key] = nil // Ambiguous RPMDB instances supply no authority.
		} else {
			indexed[key] = p
		}
	}
	var encoded int64
	for _, p := range packages {
		p.RpmAuthority = &inventoryv1.RpmAuthority{Status: unavailable}
		if e := indexed[tuple{p.Name, p.Version, p.Architecture}]; e != nil && proto.Equal(e.Module, p.Module) {
			p.RpmAuthority, p.SourceName, p.SourceVersion, p.SourceArchitecture = e.RpmAuthority, e.SourceName, e.SourceVersion, e.SourceArchitecture
			if proto.Size(p)+6 > maxRpmPackageWire {
				p.RpmAuthority = &inventoryv1.RpmAuthority{Status: capacity}
			}
		}
		encoded += int64(proto.Size(p) + 6)
	}
	if encoded > maxOutputBytes {
		// The census already fits. Only the optional authority layer is
		// discarded, never the installed package rows or their SUCCESS status.
		for _, p := range packages {
			p.RpmAuthority = &inventoryv1.RpmAuthority{Status: capacity}
			p.SourceName, p.SourceVersion, p.SourceArchitecture = "", "", ""
		}
	}
}
