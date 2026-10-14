// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"testing"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

func TestProtectedDeployPipe(t *testing.T) {
	passphrase := []byte("development fixture passphrase not an identity")
	pipe, err := protectedDeployPipe(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pipe.Close(); err != nil {
			t.Error(err)
		}
	})
	var stat unix.Stat_t
	if err := unix.Fstat(int(pipe.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(pipe.Fd()), &filesystem); err != nil {
		t.Fatal(err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFIFO || stat.Mode&0077 != 0 || filesystem.Type != unix.PIPEFS_MAGIC {
		t.Fatal("passphrase must use an owner-private anonymous PIPEFS descriptor")
	}
	received, err := custody.ReadPassphraseFD(context.Background(), int(pipe.Fd()), false)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(received)
	if !bytes.Equal(received, passphrase) {
		t.Fatal("passphrase pipe changed input")
	}
}

func TestProtectedDeployPipeRejectsUnboundedOrMultilineInput(t *testing.T) {
	for _, input := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte("x"), 1025), []byte("twenty-byte phrase\nsecond line"), []byte("twenty-byte phrase\rsecond line"), []byte("twenty-byte phrase\x00second line")} {
		if pipe, err := protectedDeployPipe(input); err == nil {
			_ = pipe.Close()
			t.Fatal("accepted invalid passphrase input")
		}
	}
}
