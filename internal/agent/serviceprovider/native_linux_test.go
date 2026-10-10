//go:build linux

package serviceprovider

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestRuntimeCompletionWithoutBusArgumentMatching(t *testing.T) {
	for _, result := range []string{"done", "failed"} {
		t.Run(result, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			socket, peer := localSocketPair(t)
			deadline, _ := ctx.Deadline()
			for _, connection := range []*net.UnixConn{socket, peer} {
				if err := connection.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
			}
			var authorized atomic.Bool
			done := make(chan error, 1)
			go func() { done <- serveJobBus(peer, &authorized, result) }()
			t.Cleanup(func() {
				_ = socket.Close()
				_ = peer.Close()
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			conn, err := dbus.NewConn(socket)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.Auth([]dbus.Auth{dbus.AuthExternal("0")}); err != nil {
				t.Fatal(err)
			}
			provider := &Provider{conn: conn, socket: socket, owner: ":1.0"}
			desired := &agentv1.ServiceDesiredState{Unit: "example.service", Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE}
			err = provider.changeRuntime(ctx, desired, func(context.Context) error {
				if authorized.Swap(true) {
					t.Error("start authorized more than once")
				}
				return nil
			})
			if result == "done" && err != nil {
				t.Fatalf("completed native job was lost: %v", err)
			}
			if result == "failed" && (!errors.Is(err, ErrNotConverged) || errors.Is(err, ErrOutcomeUnknown)) {
				t.Fatalf("exact failed job result was lost or unrelated completion accepted: %v", err)
			}
		})
	}
}

// AlmaLinux 9's dbus-broker 28 accepts AddMatch with arg2='unit', then silently
// omits uoss JobRemoved signals. Native simultaneous private connections showed:
// unique-owner and broad header matches received the same job; unique/well-known
// owner plus arg2 and arg2 alone did not. This wire peer reproduces that delivery
// behavior, including success from AddMatch, rather than mocking changeRuntime.
func serveJobBus(peer *net.UnixConn, authorized *atomic.Bool, result string) error {
	reader := bufio.NewReader(peer)
	line, err := reader.ReadString('\n')
	if err != nil || line != "\x00AUTH\r\n" {
		return fmt.Errorf("test bus authentication discovery: %q: %v", line, err)
	}
	if _, err := io.WriteString(peer, "REJECTED EXTERNAL\r\n"); err != nil {
		return err
	}
	line, err = reader.ReadString('\n')
	if err != nil || line != "AUTH EXTERNAL\r\n" {
		return fmt.Errorf("test bus authentication: %q: %v", line, err)
	}
	if _, err := io.WriteString(peer, "OK 0123456789abcdef0123456789abcdef\r\n"); err != nil {
		return err
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "BEGIN\r\n" {
		return fmt.Errorf("test bus BEGIN: %q: %v", line, err)
	}
	var match string
	for {
		message, err := dbus.DecodeMessage(reader)
		if err != nil {
			return err
		}
		member, _ := message.Headers[dbus.FieldMember].Value().(string)
		var body []any
		switch member {
		case "AddMatch":
			if authorized.Load() {
				return errors.New("job subscription installed after start authorization")
			}
			if err := dbus.Store(message.Body, &match); err != nil {
				return err
			}
		case "StartUnit":
			var unit, mode string
			if err := dbus.Store(message.Body, &unit, &mode); err != nil {
				return err
			}
			if !authorized.Load() || unit != "example.service" || mode != "fail" || match == "" {
				return errors.New("native start lacks authority, expected unit/mode or subscription")
			}
			body = []any{dbus.ObjectPath("/org/freedesktop/systemd1/job/123")}
			if !strings.Contains(match, "arg2=") {
				// Other jobs are now visible. Neither their success nor a forged
				// sender may substitute for the exact submitted job's result.
				for _, signal := range []struct {
					owner, unit, result string
					id                  uint32
				}{
					{":1.0", "other.service", "done", 123},
					{":1.0", "example.service", "done", 124},
					{":1.9", "example.service", "done", 123},
					{":1.0", "example.service", result, 123},
				} {
					path := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/systemd1/job/%d", signal.id))
					m := &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
						dbus.FieldSender: dbus.MakeVariant(signal.owner), dbus.FieldPath: dbus.MakeVariant(managerPath),
						dbus.FieldInterface: dbus.MakeVariant(managerInterface), dbus.FieldMember: dbus.MakeVariant("JobRemoved"),
						dbus.FieldSignature: dbus.MakeVariant(dbus.ParseSignatureMust("uoss")),
					}, Body: []any{signal.id, path, signal.unit, signal.result}}
					if err := m.EncodeTo(peer, binary.LittleEndian); err != nil {
						return err
					}
				}
			}
		case "RemoveMatch":
			var removed string
			if err := dbus.Store(message.Body, &removed); err != nil {
				return err
			}
			if removed != match {
				return errors.New("job subscription cleanup differs from installed match")
			}
		default:
			return fmt.Errorf("unexpected test bus method %q", member)
		}
		reply := &dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldReplySerial: dbus.MakeVariant(message.Serial()), dbus.FieldSender: dbus.MakeVariant("org.freedesktop.DBus"),
		}, Body: body}
		if len(body) != 0 {
			reply.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(body...))
		}
		if err := reply.EncodeTo(peer, binary.LittleEndian); err != nil {
			return err
		}
		if member == "RemoveMatch" {
			return nil
		}
	}
}
