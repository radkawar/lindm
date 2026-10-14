// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// deployRoute preserves public ports across migration to a fresh server VM. It
// forwards opaque TLS through pinned guest SSH, never terminates application TLS.
// Fence closes all in-flight connections before a backup or restore cutover.
type deployRoute struct {
	listener    net.Listener
	mu          sync.Mutex
	guest       *guestVM
	target      string
	connections map[net.Conn]struct{}
	closed      bool
	wg          sync.WaitGroup
}

func newDeployRoute(ctx context.Context, target string) (*deployRoute, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	route := &deployRoute{listener: listener, target: target, connections: make(map[net.Conn]struct{})}
	route.wg.Add(1)
	go func() {
		defer route.wg.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			route.mu.Lock()
			guest := route.guest
			if route.closed || guest == nil || len(route.connections) >= 128 {
				route.mu.Unlock()
				_ = client.Close()
				continue
			}
			route.connections[client] = struct{}{}
			route.wg.Add(1)
			route.mu.Unlock()
			go route.forward(ctx, guest, client)
		}
	}()
	return route, nil
}

func (r *deployRoute) forward(ctx context.Context, guest *guestVM, client net.Conn) {
	defer r.wg.Done()
	defer func() { _ = client.Close(); r.mu.Lock(); delete(r.connections, client); r.mu.Unlock() }()
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	remote, err := guest.client.DialContext(probe, "tcp", r.target)
	cancel()
	if err != nil {
		return
	}
	r.mu.Lock()
	if r.closed || r.guest != guest {
		r.mu.Unlock()
		_ = remote.Close()
		return
	}
	r.connections[remote] = struct{}{}
	r.mu.Unlock()
	defer func() { _ = remote.Close(); r.mu.Lock(); delete(r.connections, remote); r.mu.Unlock() }()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(remote, client); _ = remote.Close(); _ = client.Close(); close(done) }()
	_, _ = io.Copy(client, remote)
	_ = remote.Close()
	_ = client.Close()
	<-done
}

func (r *deployRoute) fence() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.guest = nil
	for connection := range r.connections {
		_ = connection.Close()
	}
}

func (r *deployRoute) activate(guest *guestVM) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.guest = guest
}

func (r *deployRoute) close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.fence()
	err := r.listener.Close()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return err
	case <-time.After(15 * time.Second):
		return errors.Join(err, errors.New("deploy route cleanup deadline"))
	}
}

func uploadDeployFile(ctx context.Context, vm *guestVM, destination string, input io.Reader) error {
	_, err := serverGuestCommand(ctx, vm, "transfer protected deployment input", "umask 077; cat > "+nativeQuote(destination)+"; chmod 0600 "+nativeQuote(destination), input)
	return err
}

// uploadDeployDirectory streams an already authenticated release through private
// SSH stdin. It refuses links and special files; unpacking never trusts archive
// names from a downloaded opaque tarball or follows a directory symlink.
func uploadDeployDirectory(ctx context.Context, vm *guestVM, directory, destination string) (err error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	reader, writer := io.Pipe()
	encoded := make(chan error, 1)
	go func() {
		tw := tar.NewWriter(writer)
		var total int64
		walkErr := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if name == "." {
				return nil
			}
			info, err := root.Lstat(name)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
				return errors.New("deploy release contains a link or special file")
			}
			if info.Size() < 0 || info.Size() > 2<<30 {
				return errors.New("deploy release member exceeds size bound")
			}
			total += info.Size()
			if total > 16<<30 {
				return errors.New("deploy release exceeds transfer bound")
			}
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = name
			header.Uid, header.Gid, header.Uname, header.Gname = 0, 0, "", ""
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			file, err := root.Open(name)
			if err != nil {
				return err
			}
			written, copyErr := io.CopyN(tw, file, info.Size())
			if written != info.Size() {
				copyErr = errors.Join(copyErr, errors.New("deploy release changed during transfer"))
			}
			return errors.Join(copyErr, file.Close())
		})
		walkErr = errors.Join(walkErr, tw.Close())
		_ = writer.CloseWithError(walkErr)
		encoded <- walkErr
	}()
	command := "test ! -e " + nativeQuote(destination) + "; install -d -m 0700 " + nativeQuote(destination) + "; tar --extract --no-same-owner --no-same-permissions -C " + nativeQuote(destination)
	_, runErr := serverGuestCommand(ctx, vm, "transfer authenticated release", command, reader)
	_ = reader.Close()
	return errors.Join(runErr, <-encoded)
}

func deployGuestOS(ctx context.Context, vm *guestVM, distribution, version string) ([]string, error) {
	body, err := vm.run(ctx, hostTruthCommand, nil, 4096, 15*time.Second)
	if err != nil {
		return nil, err
	}
	observed := strings.Split(string(body), "\n")
	if len(observed) != 7 || observed[0] != distribution || observed[1] != version || observed[2] != "x86_64" {
		return nil, fmt.Errorf("deploy fresh guest does not match pinned %s %s x86_64", distribution, version)
	}
	if _, err := vm.run(ctx, "sudo -n sh -eu -c 'test ! -e /etc/lindm; test ! -e /var/lib/lindmd; ! command -v lindmd; ! command -v lindm-agent'", nil, 4096, time.Minute); err != nil {
		return nil, errors.New("deploy requires a pristine fresh server")
	}
	return observed, nil
}

func deployBootstrapInventory(ctx context.Context, guest *guestVM) ([]string, error) {
	output, err := guest.run(ctx, "for name in openssl curl rpm apt-get dnf psql; do if command -v \"$name\" >/dev/null 2>&1; then printf '%s:present\\n' \"$name\"; else printf '%s:absent\\n' \"$name\"; fi; done", nil, 4096, time.Minute)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(output)), "\n"), nil
}
