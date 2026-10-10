//go:build linux

package vmlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func TestRebootRequiresChangedPinnedBootIdentity(t *testing.T) {
	previous := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	next := "00000000-0000-4000-8000-000000000002"
	for _, test := range []struct {
		name string
		boot string
		err  error
		want string
	}{
		{name: "new boot without old transport FIN", boot: next},
		{name: "old boot remains reachable", boot: previous.String(), want: "wait for changed guest boot ID"},
		{name: "invalid boot identity", boot: "invalid", want: "boot ID is invalid"},
		{name: "authentication rejected", err: errors.New("ssh: unable to authenticate"), want: "probe reconnected guest boot ID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				calls := 0
				err := waitGuestBootChange(ctx, previous, func(context.Context) (string, error) {
					calls++
					return test.boot, test.err
				})
				if test.want == "" {
					if err != nil || calls != 1 {
						t.Fatalf("new pinned boot was not accepted independently of transport FIN: calls=%d err=%v", calls, err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("boot boundary error=%v, want %q", err, test.want)
				}
				if test.boot == previous.String() {
					if !errors.Is(err, context.DeadlineExceeded) || calls < 2 {
						t.Fatalf("old boot was not bounded: calls=%d err=%v", calls, err)
					}
				} else if calls != 1 {
					t.Fatalf("invalid identity or authentication was retried %d times", calls)
				}
			})
		})
	}
}

func TestRebootObservesOldBootThenTransientShutdownThenNewBoot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := uuid.MustParse("00000000-0000-4000-8000-000000000001")
		calls := 0
		err := waitGuestBootChange(t.Context(), previous, func(context.Context) (string, error) {
			calls++
			switch calls {
			case 1:
				return previous.String(), nil
			case 2:
				return "", io.EOF
			default:
				return "00000000-0000-4000-8000-000000000002", nil
			}
		})
		if err != nil || calls != 3 {
			t.Fatalf("boot transition: calls=%d err=%v", calls, err)
		}
	})
}

func TestSSHBootReadinessFailureClasses(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		poll bool
	}{
		{"closed transport", io.EOF, true},
		{"short transport", io.ErrUnexpectedEOF, true},
		{"deadline-closed socket", net.ErrClosed, true},
		{"new boot session deadline", context.DeadlineExceeded, true},
		{"channel starting", &ssh.OpenChannelError{Reason: ssh.ConnectionFailed}, true},
		{"temporary channel capacity", &ssh.OpenChannelError{Reason: ssh.ResourceShortage}, true},
		{"channel denied", &ssh.OpenChannelError{Reason: ssh.Prohibited}, false},
		{"unknown channel", &ssh.OpenChannelError{Reason: ssh.UnknownChannelType}, false},
		{"authentication rejected", errors.New("ssh: unable to authenticate"), false},
		{"host key rejected", errors.New("ssh: host key mismatch"), false},
		{"protocol violation", errors.New("ssh: unexpected packet in response to channel open: <nil>"), false},
		{"command rejected", errors.New("guest operation exited with status 1"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := sshBootNotReady(test.err); got != test.poll {
				t.Fatalf("poll = %v, want %v", got, test.poll)
			}
		})
	}
}

func TestSSHConnectPollsOnlyBootReadiness(t *testing.T) {
	for _, test := range []struct {
		name       string
		reason     ssh.RejectionReason
		authReject bool
		wantError  string
	}{
		{name: "new boot channel not ready", reason: ssh.ResourceShortage},
		{name: "session authorization rejected", reason: ssh.Prohibited, wantError: "SSH session readiness"},
		{name: "authentication rejected", authReject: true, wantError: "pinned SSH handshake"},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			defer func() { _ = listener.Close() }()
			result := make(chan error, 1)
			go func() {
				config := &ssh.ServerConfig{NoClientAuth: !test.authReject}
				config.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
					return nil, errors.New("rejected test identity")
				}
				config.AddHostKey(signer)
				attempts := 1
				if test.wantError == "" {
					attempts = 2
				}
				for attempt := range attempts {
					conn, err := listener.Accept()
					if err != nil {
						result <- err
						return
					}
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					server, channels, requests, err := ssh.NewServerConn(conn, config)
					if err != nil {
						_ = conn.Close()
						if test.authReject {
							result <- nil
						} else {
							result <- err
						}
						return
					}
					go ssh.DiscardRequests(requests)
					channel, ok := <-channels
					if !ok {
						_ = server.Close()
						result <- errors.New("no command channel")
						return
					}
					if attempt == 0 {
						err = channel.Reject(test.reason, "test boot readiness")
						_ = server.Wait()
					} else {
						var session ssh.Channel
						var commands <-chan *ssh.Request
						session, commands, err = channel.Accept()
						if err == nil {
							request := <-commands
							if request == nil || request.Type != "exec" || string(request.Payload) != string(ssh.Marshal(struct{ Command string }{"true"})) {
								err = errors.New("readiness did not use quiet no-effect command")
							} else {
								err = request.Reply(true, nil)
								if err == nil {
									_, err = session.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								}
							}
							_ = session.Close()
						}
					}
					_ = server.Close()
					if err != nil {
						result <- err
						return
					}
				}
				result <- nil
			}()
			vm := &guestVM{address: listener.Addr().String(), done: make(chan struct{}), log: new(vmLog),
				config: &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("test")}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())}}
			defer func() {
				if vm.client != nil {
					_ = vm.client.Close()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			err = vm.connect(ctx)
			if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("connect = %v, want %q", err, test.wantError)
			}
			_ = listener.Close()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}
