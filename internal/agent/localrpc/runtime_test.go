//go:build linux

package localrpc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSocketPathOwnershipModeConnectionAndCleanup(t *testing.T) {
	testSocketPathLifecycle(t, uint32(os.Getegid()))
}

func TestRootSocketPathOwnershipModeConnectionAndCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to verify assignment to the network account group")
	}
	testSocketPathLifecycle(t, 65534)
}

func testSocketPathLifecycle(t *testing.T, networkGID uint32) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := openRuntimeDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	socket, err := listenSocket(dir, "executor.sock", executorAccess(networkGID))
	if err != nil {
		t.Fatalf("bind real pathname socket: %v", err)
	}
	defer func() { _ = socket.close() }()
	var stat unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), "executor.sock", &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	wantMode, wantGID := uint32(0600), uint32(os.Getegid())
	if os.Geteuid() == 0 {
		wantMode, wantGID = 0660, networkGID
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Mode&07777 != wantMode || stat.Uid != uint32(os.Geteuid()) || stat.Gid != wantGID {
		t.Fatalf("pathname has mode=%#o uid=%d gid=%d, want socket %#o uid=%d gid=%d", stat.Mode, stat.Uid, stat.Gid, wantMode, os.Geteuid(), wantGID)
	}
	if socket.dev != stat.Dev || socket.ino != stat.Ino {
		t.Fatal("cleanup identity is not the bound pathname inode")
	}
	client, err := net.DialTimeout("unix", filepath.Join(directory, "executor.sock"), time.Second)
	if err != nil {
		t.Fatalf("connect to bound pathname: %v", err)
	}
	defer func() { _ = client.Close() }()
	server, err := socket.listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := server.Read(got[:]); err != nil || got[0] != 'x' {
		t.Fatalf("bound pathname did not reach listener: %q, %v", got, err)
	}
	if err := socket.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "executor.sock")); !os.IsNotExist(err) {
		t.Fatalf("close left the bound pathname: %v", err)
	}
}

func TestSocketCleanupPreservesReplacementPathname(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := openRuntimeDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	socket, err := listenSocket(dir, "executor.sock", executorAccess(uint32(os.Getegid())))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = socket.close() }()
	path := filepath.Join(directory, "executor.sock")
	if err := os.Rename(path, filepath.Join(directory, "retired.sock")); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	if err := socket.close(); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("old listener cleanup removed the replacement: %v", err)
	}
	_ = client.Close()
}

func TestSocketUsesRetainedRuntimeDirectory(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "runtime")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := openRuntimeDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	retained := filepath.Join(parent, "retained")
	if err := os.Rename(directory, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	socket, err := listenSocket(dir, "executor.sock", executorAccess(uint32(os.Getegid())))
	if err != nil {
		t.Fatalf("listen through retained directory: %v", err)
	}
	defer func() { _ = socket.close() }()
	if _, err := os.Lstat(filepath.Join(directory, "executor.sock")); !os.IsNotExist(err) {
		t.Fatalf("listener followed the replaced directory pathname: %v", err)
	}
	client, err := net.DialTimeout("unix", filepath.Join(retained, "executor.sock"), time.Second)
	if err != nil {
		t.Fatalf("retained directory did not receive the socket: %v", err)
	}
	_ = client.Close()
	if err := socket.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(retained, "executor.sock")); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not use the retained directory: %v", err)
	}
}
