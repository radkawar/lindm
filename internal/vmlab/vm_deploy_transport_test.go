// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"testing"
)

func TestDeployBackupWriterBoundsBeforeWriting(t *testing.T) {
	var destination bytes.Buffer
	bounded := deployBackupWriter{writer: &destination, bytes: (2 << 30) - 2}
	if written, err := bounded.Write([]byte("abc")); err == nil || written != 0 || destination.Len() != 0 {
		t.Fatal("oversized encrypted archive wrote beyond the transport bound")
	}
	if written, err := bounded.Write([]byte("ab")); err != nil || written != 2 || destination.String() != "ab" || bounded.bytes != 2<<30 {
		t.Fatalf("exact remaining capacity rejected: written=%d err=%v", written, err)
	}
	if written, err := bounded.Write([]byte("c")); err == nil || written != 0 || destination.String() != "ab" {
		t.Fatal("full transport accepted more ciphertext")
	}
}
