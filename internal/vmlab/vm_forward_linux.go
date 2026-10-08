//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// guestForward moves opaque TCP bytes, preserving application TLS end to end.
// Each forward owns a separately pinned SSH transport so cancellation cannot
// strand channels or interrupt the VM's independent control connection.
type guestForward struct {
	client      *ssh.Client
	listener    net.Listener
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
	once        sync.Once
	done        chan struct{}
}

func loopbackAddress(address string, allowZero bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return errors.New("forward requires literal IPv4 loopback")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || (!allowZero && n == 0) {
		return errors.New("forward requires a valid port")
	}
	return nil
}

func newGuestForward(ctx context.Context, vm *guestVM, guestAddress, hostAddress string) (_ *guestForward, err error) {
	if err := loopbackAddress(guestAddress, true); err != nil {
		return nil, err
	}
	if err := loopbackAddress(hostAddress, false); err != nil {
		return nil, err
	}
	setup, stopSetup := context.WithTimeout(ctx, 15*time.Second)
	defer stopSetup()
	conn, err := (&net.Dialer{}).DialContext(setup, "tcp4", vm.address)
	if err != nil {
		return nil, fmt.Errorf("connect forward transport: %w", err)
	}
	deadline, _ := setup.Deadline()
	_ = conn.SetDeadline(deadline)
	interrupt := context.AfterFunc(setup, func() { _ = conn.Close() })
	defer interrupt()
	sshConn, channels, requests, err := ssh.NewClientConn(conn, vm.address, vm.config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("pin forward transport: %w", err)
	}
	client := ssh.NewClient(sshConn, channels, requests)
	listener, err := client.Listen("tcp4", guestAddress)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("bind guest loopback forward: %w", err)
	}
	if !interrupt() {
		_ = client.Close()
		_ = listener.Close()
		return nil, setup.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	life, cancel := context.WithCancel(ctx)
	f := &guestForward{client: client, listener: listener, cancel: cancel, connections: make(map[net.Conn]struct{}), done: make(chan struct{})}
	f.wg.Add(1)
	go f.accept(life, hostAddress)
	context.AfterFunc(life, func() { _ = f.Close() })
	return f, nil
}

func (f *guestForward) Addr() string { return f.listener.Addr().String() }

func (f *guestForward) track(conn net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || len(f.connections) >= 128 {
		_ = conn.Close()
		return false
	}
	f.connections[conn] = struct{}{}
	return true
}

func (f *guestForward) forget(conn net.Conn) {
	_ = conn.Close()
	f.mu.Lock()
	delete(f.connections, conn)
	f.mu.Unlock()
}

func (f *guestForward) accept(ctx context.Context, host string) {
	defer f.wg.Done()
	for {
		remote, err := f.listener.Accept()
		if err != nil {
			return
		}
		if !f.track(remote) {
			continue
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer f.forget(remote)
			dial, cancel := context.WithTimeout(ctx, 10*time.Second)
			local, err := (&net.Dialer{}).DialContext(dial, "tcp4", host)
			cancel()
			if err != nil {
				return
			}
			if !f.track(local) {
				return
			}
			defer f.forget(local)
			copied := make(chan struct{})
			go func() { _, _ = io.Copy(local, remote); _ = local.Close(); _ = remote.Close(); close(copied) }()
			_, _ = io.Copy(remote, local)
			_ = local.Close()
			_ = remote.Close()
			<-copied
		}()
	}
}

func (f *guestForward) Close() error {
	f.once.Do(func() {
		f.cancel()
		// Closing channels can itself write to SSH; kill its transport first.
		_ = f.client.Close()
		f.mu.Lock()
		f.closed = true
		for conn := range f.connections {
			_ = conn.Close()
		}
		f.mu.Unlock()
		// Kill transport before cancelling the remote listener: SSH's listener
		// Close waits for a server reply, which a dead peer cannot supply.
		_ = f.listener.Close()
		go func() { f.wg.Wait(); close(f.done) }()
	})
	select {
	case <-f.done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("reverse-forward cleanup deadline")
	}
}

// aptPublicServer serves only explicitly opened public repository files. It
// never serves a directory tree, keys, directory listings, or a symlink target.
// The caller supplies public paths (dists metadata and pool packages only).
type aptPublicServer struct {
	server   *http.Server
	listener net.Listener
	files    map[string]*os.File
	once     sync.Once
	closeErr error
}

var aptPublicPath = regexp.MustCompile(`^(dists/stable/(InRelease|Release|Release\.gpg|main/binary-(amd64|arm64)/Packages(\.gz)?)|pool/main/l/lindm-agent/lindm-agent_[0-9]+\.[0-9]+\.[0-9]+_(amd64|arm64)\.deb)$`)

func newAPTPublicServer(root string, names []string) (_ *aptPublicServer, err error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	s := &aptPublicServer{files: make(map[string]*os.File)}
	defer func() {
		err = errors.Join(err, r.Close())
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()
	for _, name := range names {
		if !aptPublicPath.MatchString(name) || path.Clean(name) != name {
			return nil, errors.New("APT public file outside metadata/package allowlist")
		}
		// Check every component; Root additionally confines races to root.
		parts := strings.Split(name, "/")
		for i := range parts {
			info, statErr := r.Lstat(strings.Join(parts[:i+1], "/"))
			if statErr != nil {
				return nil, statErr
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("APT public path contains symlink")
			}
		}
		file, openErr := r.Open(name)
		if openErr != nil {
			return nil, openErr
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			return nil, errors.New("APT public file is not regular")
		}
		if _, exists := s.files["/"+name]; exists {
			_ = file.Close()
			continue
		}
		s.files["/"+name] = file
	}
	s.listener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		file := s.files[req.URL.Path]
		if file == nil || req.URL.RawQuery != "" {
			http.NotFound(w, req)
			return
		}
		info, err := file.Stat()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, req, path.Base(req.URL.Path), time.Time{}, io.NewSectionReader(file, 0, info.Size()))
	})}
	go func() { _ = s.server.Serve(s.listener) }()
	return s, nil
}

func (s *aptPublicServer) Close() error {
	s.once.Do(func() {
		if s.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.closeErr = s.server.Shutdown(ctx)
			cancel()
			s.closeErr = errors.Join(s.closeErr, s.server.Close())
		} else if s.listener != nil {
			s.closeErr = s.listener.Close()
		}
		for _, file := range s.files {
			s.closeErr = errors.Join(s.closeErr, file.Close())
		}
	})
	return s.closeErr
}
