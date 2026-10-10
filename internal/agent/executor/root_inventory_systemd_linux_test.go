//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// fakeSystemd is a direct-connection D-Bus peer that reproduces the sd-bus
// server behaviour the launcher depends on: during authentication it reads
// with recvmsg and drops the connection if any descriptor arrives, and after
// BEGIN it accepts descriptors. Connections are served one at a time.
type fakeSystemd struct {
	t        *testing.T
	listener *net.UnixListener
	address  string
	// authDelay keeps PID 1 "busy" after AGREE_UNIX_FD so that everything the
	// client sends after BEGIN is already queued when the server reads again.
	authDelay time.Duration
	// dropStart closes the connection instead of answering StartTransientUnit.
	dropStart bool
	payload   []byte

	mu          sync.Mutex
	connections int
	authFDs     int
	stranded    int
	starts      []string
	stops       []string
	done        chan struct{}
}

// configure runs before the server starts; the fields are immutable afterwards.
func newFakeSystemd(t *testing.T, configure func(*fakeSystemd)) *fakeSystemd {
	t.Helper()
	address := filepath.Join(t.TempDir(), "private")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSystemd{t: t, listener: listener, address: address, payload: []byte("payload"), done: make(chan struct{})}
	if configure != nil {
		configure(f)
	}
	go f.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		<-f.done
	})
	return f
}

func (f *fakeSystemd) serve() {
	defer close(f.done)
	for {
		conn, err := f.listener.AcceptUnix()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.connections++
		f.mu.Unlock()
		f.handle(conn)
		_ = conn.Close()
	}
}

func (f *fakeSystemd) handle(conn *net.UnixConn) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var pending []byte
	var fds []int
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	read := func() bool {
		buffer, oob := make([]byte, 4096), make([]byte, unix.CmsgSpace(16*4))
		n, oobn, _, _, err := conn.ReadMsgUnix(buffer, oob)
		if err != nil || n == 0 {
			return false
		}
		pending = append(pending, buffer[:n]...)
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return false
		}
		for _, message := range messages {
			rights, err := unix.ParseUnixRights(&message)
			if err == nil {
				fds = append(fds, rights...)
			}
		}
		return true
	}
	// Authentication: line protocol after one NUL byte, as in sd-bus.
	for authenticated := false; !authenticated; {
		line := bytes.Index(pending, []byte("\r\n"))
		if line < 0 {
			if !read() {
				return
			}
			if len(fds) != 0 {
				// sd-bus: descriptors during authentication fail the
				// connection with EIO before any reply is sent.
				f.mu.Lock()
				f.authFDs += len(fds)
				f.mu.Unlock()
				return
			}
			continue
		}
		command := strings.TrimPrefix(string(pending[:line]), "\x00")
		pending = pending[line+2:]
		var reply string
		switch {
		case command == "AUTH":
			reply = "REJECTED EXTERNAL"
		case strings.HasPrefix(command, "AUTH EXTERNAL"):
			reply = "OK 0123456789abcdef0123456789abcdef"
		case command == "NEGOTIATE_UNIX_FD":
			reply = "AGREE_UNIX_FD"
		case command == "BEGIN":
			authenticated = true
			continue
		default:
			return
		}
		if _, err := conn.Write([]byte(reply + "\r\n")); err != nil {
			return
		}
		if reply == "AGREE_UNIX_FD" {
			time.Sleep(f.authDelay)
		}
	}
	// sd-bus leaves bytes read together with BEGIN unparsed until the socket
	// becomes readable again.
	if len(pending) != 0 {
		f.mu.Lock()
		f.stranded++
		f.mu.Unlock()
		if !read() {
			return
		}
	}
	serial := uint32(0)
	send := func(msg *dbus.Message) bool {
		serial++
		var encoded bytes.Buffer
		if err := msg.EncodeTo(&encoded, binary.LittleEndian); err != nil {
			f.t.Errorf("encode fake systemd message: %v", err)
			return false
		}
		data := encoded.Bytes()
		binary.LittleEndian.PutUint32(data[8:12], serial)
		_, err := conn.Write(data)
		return err == nil
	}
	reply := func(call *dbus.Message, body ...any) bool {
		headers := map[dbus.HeaderField]dbus.Variant{dbus.FieldReplySerial: dbus.MakeVariant(call.Serial())}
		if len(body) != 0 {
			headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(body...))
		}
		return send(&dbus.Message{Type: dbus.TypeMethodReply, Headers: headers, Body: body})
	}
	signal := func(path dbus.ObjectPath, member string, body ...any) bool {
		iface := systemdManager
		if member == "PropertiesChanged" {
			iface = "org.freedesktop.DBus.Properties"
		}
		return send(&dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldPath: dbus.MakeVariant(path), dbus.FieldInterface: dbus.MakeVariant(iface),
			dbus.FieldMember: dbus.MakeVariant(member), dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf(body...)),
		}, Body: body})
	}
	for {
		if len(pending) < 16 {
			if !read() {
				return
			}
			continue
		}
		fields := binary.LittleEndian.Uint32(pending[12:16])
		total := 16 + int(fields+7)&^7 + int(binary.LittleEndian.Uint32(pending[4:8]))
		if len(pending) < total {
			if !read() {
				return
			}
			continue
		}
		var count uint32
		msg, err := dbus.DecodeMessageWithFDs(bytes.NewReader(pending[:total]), fds)
		if err == nil {
			if v, ok := msg.Headers[dbus.FieldUnixFDs]; ok {
				count, _ = v.Value().(uint32)
			}
		}
		pending = pending[total:]
		if err != nil {
			f.t.Errorf("decode client message: %v", err)
			return
		}
		member, _ := msg.Headers[dbus.FieldMember].Value().(string)
		switch member {
		case "Ping":
			if !reply(msg) {
				return
			}
		case "StartTransientUnit":
			unit, _ := msg.Body[0].(string)
			f.mu.Lock()
			f.starts = append(f.starts, unit)
			f.mu.Unlock()
			if f.dropStart {
				return
			}
			stdout := -1
			properties, _ := msg.Body[2].([][]any)
			for _, property := range properties {
				name, _ := property[0].(string)
				value, _ := property[1].(dbus.Variant)
				if fd, ok := value.Value().(dbus.UnixFD); ok && name == "StandardOutputFileDescriptor" {
					stdout = int(fd)
				}
			}
			if stdout < 0 {
				f.t.Error("start carried no stdout descriptor")
				return
			}
			if _, err := unix.Write(stdout, f.payload); err != nil {
				f.t.Errorf("write helper output: %v", err)
			}
			for _, fd := range fds[:count] {
				_ = unix.Close(fd)
			}
			fds = fds[count:]
			const job = dbus.ObjectPath("/org/freedesktop/systemd1/job/7")
			path := systemdUnitPath(unit)
			if !reply(msg, job) ||
				!signal(systemdManagerPath, "JobRemoved", uint32(7), job, unit, "done") ||
				!signal(path, "PropertiesChanged", systemdServiceInterface, map[string]dbus.Variant{
					"Result": dbus.MakeVariant("success"), "ExecMainCode": dbus.MakeVariant(cldExited), "ExecMainStatus": dbus.MakeVariant(int32(0)),
				}, []string{}) ||
				!signal(path, "PropertiesChanged", systemdUnitInterface, map[string]dbus.Variant{"ActiveState": dbus.MakeVariant("inactive")}, []string{}) {
				return
			}
		case "StopUnit":
			unit, _ := msg.Body[0].(string)
			f.mu.Lock()
			f.stops = append(f.stops, unit)
			f.mu.Unlock()
			const job = dbus.ObjectPath("/org/freedesktop/systemd1/job/8")
			if !reply(msg, job) || !signal(systemdManagerPath, "JobRemoved", uint32(8), job, unit, "done") {
				return
			}
		default:
			f.t.Errorf("unexpected call %s", member)
			return
		}
	}
}

// A busy PID 1 reads the first call together with BEGIN. With descriptors,
// sd-bus drops the connection ("connection reset by peer"); without them, the
// call stays unparsed until more bytes arrive. Both were observed on Fedora 44.
func TestSystemdLauncherFinishesAuthenticationBeforePassingDescriptors(t *testing.T) {
	f := newFakeSystemd(t, func(f *fakeSystemd) { f.authDelay = 200 * time.Millisecond })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const unit = "lindm-inventory-1e6cec1c-c5ae-4957-804d-a157cf15ed43.service"
	units, err := openSystemdUnit(ctx, f.address, uint32(os.Geteuid()), unit)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := units.close(); err != nil {
			t.Error(err)
		}
	}()
	payload, err := units.run(ctx, rootInventoryProperties())
	f.mu.Lock()
	authFDs, stranded, starts := f.authFDs, f.stranded, append([]string(nil), f.starts...)
	f.mu.Unlock()
	if stranded != 1 {
		t.Fatalf("fixture did not exercise a call read together with BEGIN (%d)", stranded)
	}
	if authFDs != 0 {
		t.Fatalf("descriptors reached the server during authentication (%d)", authFDs)
	}
	if err != nil || string(payload) != "payload" || len(starts) != 1 || starts[0] != unit {
		t.Fatalf("payload %q, starts %v, err %v", payload, starts, err)
	}
}

// A connection lost after the start was sent leaves the outcome ambiguous: the
// unit must be stopped over a new connection, not the closed one.
func TestSystemdLauncherStopsOverFreshConnectionAfterLoss(t *testing.T) {
	f := newFakeSystemd(t, func(f *fakeSystemd) { f.dropStart = true })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const unit = "lindm-inventory-1e6cec1c-c5ae-4957-804d-a157cf15ed43.service"
	units, err := openSystemdUnit(ctx, f.address, uint32(os.Geteuid()), unit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := units.run(ctx, rootInventoryProperties()); err == nil {
		t.Fatal("lost connection produced evidence")
	}
	if err := units.stop(ctx); err != nil {
		t.Fatalf("stop after connection loss: %v", err)
	}
	if err := units.close(); err != nil && !errors.Is(err, dbus.ErrClosed) {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connections != 2 || len(f.stops) != 1 || f.stops[0] != unit {
		t.Fatalf("connections %d, stops %v", f.connections, f.stops)
	}
}

func TestSystemdLauncherRequiresExpectedPeer(t *testing.T) {
	f := newFakeSystemd(t, nil)
	if _, err := openSystemdUnit(t.Context(), f.address, uint32(os.Geteuid())+1, "x.service"); err == nil {
		t.Fatal("unexpected socket owner accepted")
	}
}
