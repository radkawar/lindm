package localrpc

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPeerCredentialRootGroupMembership(t *testing.T) {
	if path := os.Getenv("LINDM_PEER_GROUP_SOCKET"); path != "" {
		conn, err := net.DialTimeout("unix", path, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to exercise real primary and supplemental process groups")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = executable.Close() }()
	for _, test := range []struct {
		name   string
		gid    uint32
		groups []uint32
		want   bool
	}{
		{"ordinary", 65534, []uint32{65534}, true},
		{"primary-root", 0, []uint32{65534}, false},
		{"supplemental-root", 65534, []uint32{65534, 0}, false},
		{"no-supplemental", 65534, []uint32{}, true},
		{"many-groups", 65534, peerTestGroups(false), true},
		{"many-groups-root", 65534, peerTestGroups(true), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, err := os.MkdirTemp("", "lindm-peer-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(directory) })
			if err := os.Chmod(directory, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "socket")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			if err := os.Chmod(path, 0777); err != nil {
				t.Fatal(err)
			}
			if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// The Go test build directory may be private. Execute the retained
			// descriptor without granting the peer access to its parent.
			child := exec.CommandContext(t.Context(), "/proc/self/fd/3", "-test.run=^TestPeerCredentialRootGroupMembership$")
			child.ExtraFiles = []*os.File{executable}
			child.Env = append(os.Environ(), "LINDM_PEER_GROUP_SOCKET="+path)
			child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: test.gid, Groups: test.groups}}
			if err := child.Start(); err != nil {
				if errors.Is(err, syscall.EPERM) {
					t.Skip("requires setuid/setgid capabilities")
				}
				t.Fatal(err)
			}
			defer func() {
				if err := child.Wait(); err != nil {
					t.Errorf("peer process: %v", err)
				}
			}()
			conn, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			uid, err := peerCredential(conn)
			if (err == nil) != test.want || (test.want && uid != 65534) {
				t.Fatalf("peer credential = %d, %v; want accepted=%t", uid, err, test.want)
			}
		})
	}
}

func peerTestGroups(root bool) []uint32 {
	groups := make([]uint32, 64)
	for i := range groups {
		groups[i] = uint32(i + 1)
	}
	if root {
		groups[len(groups)-1] = 0
	}
	return groups
}
