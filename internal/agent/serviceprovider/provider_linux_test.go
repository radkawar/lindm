// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceprovider

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func localSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var connections [2]*net.UnixConn
	for index, fd := range fds {
		file := os.NewFile(uintptr(fd), "serviceprovider-test-socket")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			if index == 0 {
				_ = unix.Close(fds[1])
			}
			t.Fatal(err)
		}
		socket, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			t.Fatal("socketpair did not produce a Unix connection")
		}
		connections[index] = socket
		t.Cleanup(func() { _ = conn.Close() })
	}
	return connections[0], connections[1]
}

func TestStoppedSetupCancellationDoesNotOwnConnection(t *testing.T) {
	connection, peer := localSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := closeOnCancel(ctx, connection)
	stop()
	stop() // successful setup plus deferred cleanup must be idempotent
	cancel()
	if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte{42}); err != nil {
		t.Fatalf("setup cancellation closed returned connection: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := peer.Read(got[:]); err != nil || got[0] != 42 {
		t.Fatalf("connection unusable after setup: %v", err)
	}
}

func TestActiveCancellationClosesSocketWithoutLeakingCallback(t *testing.T) {
	connection, _ := localSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	stop := closeOnCancel(ctx, connection)
	cancel()
	stop() // joins the callback before any next operation can start
	stop()
	if _, err := connection.Write([]byte{42}); err == nil {
		t.Fatal("canceled operation retained a live socket")
	}
}
