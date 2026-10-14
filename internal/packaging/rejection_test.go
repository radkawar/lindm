// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectionRPMPayloadSkipsSignaturePaddingAndMainHeader(t *testing.T) {
	// One signature index with an odd-sized store requires padding before
	// the main header. Both headers and the signature must remain untouched.
	signatureEnd := 96 + 16 + 16 + 3
	mainStart := (signatureEnd + 7) &^ 7
	payloadStart := mainStart + 16 + 2*16 + 5
	data := make([]byte, payloadStart+32)
	copy(data, []byte{0xed, 0xab, 0xee, 0xdb})
	for _, header := range []struct {
		offset, entries, store int
	}{{96, 1, 3}, {mainStart, 2, 5}} {
		copy(data[header.offset:], []byte{0x8e, 0xad, 0xe8, 1})
		binary.BigEndian.PutUint32(data[header.offset+8:], uint32(header.entries))
		binary.BigEndian.PutUint32(data[header.offset+12:], uint32(header.store))
	}
	path := filepath.Join(t.TempDir(), "fixture.rpm")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	offset, err := rejectionRPMPayload(path)
	if err != nil {
		t.Fatal(err)
	}
	if offset != int64(payloadStart) {
		t.Fatalf("payload offset = %d, want %d", offset, payloadStart)
	}
	if err := rejectionFlipByte(path, offset+16); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:payloadStart], data[:payloadStart]) {
		t.Fatal("tampering changed signature or main header")
	}
	data[payloadStart+16] ^= 1
	if !bytes.Equal(got, data) {
		t.Fatal("tampering did not change exactly the chosen payload byte")
	}
}

func TestRejectionRPMPayloadRejectsMalformedBounds(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries uint32
		store   uint32
	}{
		{name: "signature-outside-file", entries: 1, store: 1},
		{name: "index-overflow", entries: ^uint32(0)},
		{name: "store-overflow", store: ^uint32(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, 112)
			copy(data, []byte{0xed, 0xab, 0xee, 0xdb})
			copy(data[96:], []byte{0x8e, 0xad, 0xe8, 1})
			binary.BigEndian.PutUint32(data[104:], test.entries)
			binary.BigEndian.PutUint32(data[108:], test.store)
			path := filepath.Join(t.TempDir(), "fixture.rpm")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := rejectionRPMPayload(path); err == nil {
				t.Fatal("accepted signature header beyond file boundary")
			}
		})
	}
}

func TestRejectionCopyFileEnforcesBound(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, []byte("bounded-copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := rejectionCopyFile(file, filepath.Join(dir, "destination"), 4); err == nil {
		t.Fatal("accepted source larger than copy bound")
	}
	got, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bounded-copy" {
		t.Fatal("copy changed the positive source")
	}
}
