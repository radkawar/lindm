//go:build linux

package vmlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestVMSSHChannelFailureRetainsTransportReason(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			serverResult <- err
			return
		}
		config := &ssh.ServerConfig{NoClientAuth: true}
		config.AddHostKey(signer)
		server, channels, _, err := ssh.NewServerConn(conn, config)
		if err != nil {
			serverResult <- err
			return
		}
		// Exercise an actual encrypted SSH channel-open followed by remote
		// transport loss, not a replacement for any guest qualification oracle.
		if _, ok := <-channels; !ok {
			serverResult <- errors.New("client closed before channel open")
			return
		}
		serverResult <- server.Close()
	}()
	vm := &guestVM{dir: t.TempDir(), address: listener.Addr().String(), done: make(chan struct{}), log: new(vmLog),
		config: &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second}}
	t.Cleanup(func() {
		if vm.client != nil {
			_ = vm.client.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	vm.client, err = ssh.Dial("tcp4", vm.address, vm.config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vm.run(ctx, "true", nil, 128, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "open pinned SSH session") || !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("transport reason lost: %v", err)
	}
	if !sshBootNotReady(err) {
		t.Fatalf("remote EOF hidden by x/crypto channel-close diagnostic: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
