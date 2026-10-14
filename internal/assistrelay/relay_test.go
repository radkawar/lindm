// SPDX-License-Identifier: Apache-2.0

package assistrelay

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pion/turn/v4"

	configv1 "lindm/gen/lindm/config/v1"
)

const testRealm = "relay.test"

func testRelay(t *testing.T, now func() time.Time) *Relay {
	t.Helper()
	// Below the Linux ephemeral range so plain sockets never land in it.
	base := uint32(20000 + rand.IntN(10000))
	relay, err := New(&configv1.AssistanceConfig{Relay: &configv1.AssistanceRelayConfig{
		Listener:     &configv1.ListenerConfig{Address: "127.0.0.1", Port: 3478},
		RelayAddress: "127.0.0.1",
		RelayPortMin: base,
		RelayPortMax: base + 200,
		Urls:         []string{"turn:relay.test:3478?transport=udp", "turn:relay.test:3478?transport=tcp"},
		Realm:        testRealm,
	}}, now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return relay
}

func TestNewRejectsUnsafeRelayAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "::1", "224.0.0.1", "255.255.255.255", "relay.example"} {
		_, err := New(&configv1.AssistanceConfig{Relay: &configv1.AssistanceRelayConfig{
			Listener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 3478}, RelayAddress: address,
			RelayPortMin: 40000, RelayPortMax: 40010, Urls: []string{"turn:relay.test:3478"}, Realm: testRealm,
		}}, time.Now, slog.Default())
		if err == nil {
			t.Fatalf("relay address %q admitted", address)
		}
	}
}

func TestCredentialsVerifyOnlyLiveUnendedSessions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	relay := testRelay(t, func() time.Time { return now })
	session := uuid.New()
	server, err := relay.ICEServer(session, RoleDevice, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(server.GetUrls()) != 2 || !strings.HasSuffix(server.GetUsername(), ":"+session.String()+":device") {
		t.Fatalf("unexpected ICE server %+v", server)
	}
	key, ok := relay.authenticate(server.GetUsername(), testRealm, nil)
	if !ok || !bytes.Equal(key, turn.GenerateAuthKey(server.GetUsername(), testRealm, server.GetCredential())) {
		t.Fatal("minted credential rejected or key differs from the presented password")
	}
	if _, ok := relay.authenticate(server.GetUsername(), "other.realm", nil); ok {
		t.Fatal("foreign realm accepted")
	}
	forged := strings.Replace(server.GetUsername(), ":device", ":console", 1)
	key, ok = relay.authenticate(forged, testRealm, nil)
	if ok && bytes.Equal(key, turn.GenerateAuthKey(forged, testRealm, server.GetCredential())) {
		t.Fatal("role change kept the device password valid")
	}
	for _, name := range []string{"", "1:2:3", "x:" + session.String() + ":device", "1800000060:" + session.String() + ":admin", "1800000060:" + strings.ToUpper(session.String()) + ":device"} {
		if _, ok := relay.authenticate(name, testRealm, nil); ok {
			t.Fatalf("malformed username %q accepted", name)
		}
	}
	other, err := New(&configv1.AssistanceConfig{Relay: &configv1.AssistanceRelayConfig{
		Listener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 3478}, RelayAddress: "127.0.0.1",
		RelayPortMin: 40000, RelayPortMax: 40010, Urls: []string{"turn:relay.test:3478"}, Realm: testRealm,
	}}, func() time.Time { return now }, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _ := other.authenticate(server.GetUsername(), testRealm, nil)
	if bytes.Equal(otherKey, turn.GenerateAuthKey(server.GetUsername(), testRealm, server.GetCredential())) {
		t.Fatal("credential verified under another process secret")
	}
	now = now.Add(time.Minute)
	if _, ok := relay.authenticate(server.GetUsername(), testRealm, nil); ok {
		t.Fatal("expired credential accepted")
	}
	now = now.Add(-30 * time.Second)
	relay.End(session, now.Add(30*time.Second))
	if _, ok := relay.authenticate(server.GetUsername(), testRealm, nil); ok {
		t.Fatal("ended session accepted")
	}
	if _, err := relay.ICEServer(uuid.Nil, RoleDevice, now); err == nil {
		t.Fatal("nil session minted")
	}
	if _, err := relay.ICEServer(session, "admin", now); err == nil {
		t.Fatal("unknown role minted")
	}
}

func TestPermissionHandlerAdmitsOnlyRelayAddress(t *testing.T) {
	relay := testRelay(t, time.Now)
	if !relay.permit(nil, net.ParseIP("127.0.0.1")) || !relay.permit(nil, net.ParseIP("::ffff:127.0.0.1")) {
		t.Fatal("relay address refused")
	}
	for _, ip := range []string{"127.0.0.2", "10.0.0.1", "::1", "0.0.0.0"} {
		if relay.permit(nil, net.ParseIP(ip)) {
			t.Fatalf("peer %s admitted", ip)
		}
	}
	inside := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(relay.minPort)}
	outside := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(relay.maxPort) + 1}
	if !relay.relayPeer(inside) || relay.relayPeer(outside) || relay.relayPeer(&net.TCPAddr{IP: inside.IP, Port: inside.Port}) {
		t.Fatal("relay peer filter admitted a non-relay endpoint")
	}
}

type testAllocation struct {
	client *turn.Client
	relay  net.PacketConn
}

// allocate creates a TURN client allocation; tcp selects TURN-over-TCP control.
func allocate(t *testing.T, relay *Relay, server *Server, session uuid.UUID, role string, tcp bool) testAllocation {
	t.Helper()
	ice, err := relay.ICEServer(session, role, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	address := server.UDPAddr().String()
	var conn net.PacketConn
	if tcp {
		address = server.TCPAddr().String()
		stream, err := net.Dial("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		conn = turn.NewSTUNConn(stream)
	} else if conn, err = net.ListenPacket("udp4", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: address, TURNServerAddr: address, Conn: conn,
		Username: ice.GetUsername(), Password: ice.GetCredential(), Realm: testRealm,
		LoggerFactory: loggerFactory{logger: relay.logger},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	relayed, err := client.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = relayed.Close()
		client.Close()
		_ = conn.Close()
	})
	return testAllocation{client: client, relay: relayed}
}

func listen(t *testing.T, relay *Relay) *Server {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := relay.serve(udp, tcp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	return server
}

// outsideRange binds a plain UDP socket on the relay address but outside the
// relay port range: same IP as every allocation, never an allocation itself.
func outsideRange(t *testing.T, relay *Relay) net.PacketConn {
	t.Helper()
	for port := int(relay.maxPort) + 1; port <= int(relay.maxPort)+100; port++ {
		conn, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	t.Fatal("no free port above the relay range")
	return nil
}

// readExpect sends with resend until the receiver observes want or the deadline passes.
func readExpect(t *testing.T, receiver net.PacketConn, send func() error, want []byte) net.Addr {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buffer := make([]byte, 1500)
	for time.Now().Before(deadline) {
		if err := send(); err != nil {
			t.Fatal(err)
		}
		if err := receiver.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, from, err := receiver.ReadFrom(buffer)
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], want) {
			t.Fatalf("received %q, want %q", buffer[:n], want)
		}
		return from
	}
	t.Fatalf("datagram %q was not relayed", want)
	return nil
}

func TestRelayForwardsOnlyBetweenAllocations(t *testing.T) {
	relay := testRelay(t, time.Now)
	server := listen(t, relay)
	session := uuid.New()
	device := allocate(t, relay, server, session, RoleDevice, false)
	// The console uses TURN-over-TCP control, as browsers behind UDP-blocking proxies do.
	console := allocate(t, relay, server, session, RoleConsole, true)
	for _, allocation := range []testAllocation{device, console} {
		if !relay.relayPeer(allocation.relay.LocalAddr()) {
			t.Fatalf("allocation %s is outside the configured relay range", allocation.relay.LocalAddr())
		}
	}
	// The console's write installs its permission for the relay address.
	if _, err := console.relay.WriteTo([]byte("open"), device.relay.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	from := readExpect(t, console.relay, func() error {
		_, err := device.relay.WriteTo([]byte("media"), console.relay.LocalAddr())
		return err
	}, []byte("media"))
	if from.String() != device.relay.LocalAddr().String() {
		t.Fatalf("datagram arrived from %s, want the device allocation", from)
	}

	if err := device.client.CreatePermission(&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 9}); err == nil {
		t.Fatal("permission for a non-relay peer address was granted")
	}

	plain := outsideRange(t, relay)
	if _, err := device.relay.WriteTo([]byte("leak"), plain.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := plain.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := plain.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatalf("relay forwarded %d bytes to a non-relay port on the relay address", n)
	}
	// A non-relay source on the relay address is never delivered to an allocation.
	if _, err := plain.WriteTo([]byte("inject"), console.relay.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	readExpect(t, console.relay, func() error {
		_, err := device.relay.WriteTo([]byte("after"), console.relay.LocalAddr())
		return err
	}, []byte("after"))
}

func TestEndClosesSessionAllocations(t *testing.T) {
	relay := testRelay(t, time.Now)
	server := listen(t, relay)
	session := uuid.New()
	allocate(t, relay, server, session, RoleDevice, false)
	other := uuid.New()
	allocate(t, relay, server, other, RoleConsole, true)
	deadline := time.Now().Add(5 * time.Second)
	for server.turn.AllocationCount() != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("allocations = %d, want 2", server.turn.AllocationCount())
		}
		time.Sleep(10 * time.Millisecond)
	}
	relay.End(session, time.Now().Add(time.Minute))
	for server.turn.AllocationCount() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("ended session kept its allocation: %d", server.turn.AllocationCount())
		}
		time.Sleep(10 * time.Millisecond)
	}
	relay.mu.Lock()
	_, kept := relay.sessions[other]
	_, dropped := relay.sessions[session]
	relay.mu.Unlock()
	if !kept || dropped {
		t.Fatal("End closed the wrong session's allocation")
	}
}
