// SPDX-License-Identifier: Apache-2.0

// Package assistrelay runs the embedded relay-only TURN service used by
// graphical remote assistance and mints per-session TURN REST credentials.
//
// Boundaries: the relay forwards ciphertext only between its own allocations
// (peer IP and port must be one of its relay addresses); it is never an open
// proxy. Credentials are HMACs under a per-process random secret and are never
// stored. The relay does not decide session authorization: the device service
// mints credentials for authorized sessions and reports ended sessions through
// End, which also closes their allocations. Non-goals: TURN-over-TLS, TCP
// relay allocations (RFC 6062), cross-replica credential verification.
package assistrelay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/pion/turn/v4"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

const (
	defaultMaxSessions = 16
	// Each role may hold a few allocations (one per advertised URL plus ICE
	// restarts); the total is bounded by the admission cap.
	maxAllocationsPerCredential = 8
	maxTCPConnections           = 1024
	// TURN-over-TCP control connections never outlive the longest session.
	tcpConnectionLifetime = 31 * time.Minute
	// Ended-session markers outlive the credential expiry they shadow by this
	// margin so clock rounding never reopens a session.
	endedRetention = time.Minute
)

var errPeerRefused = errors.New("assistrelay: peer is not a relay allocation")

// Relay holds the relay configuration, credential secret and allocation
// registry. Listen starts serving; the zero value is not usable.
type Relay struct {
	address        netip.Addr
	minPort        uint16
	maxPort        uint16
	listen         string
	urls           []string
	realm          string
	maxSessions    int
	maxAllocations int
	secret         []byte
	clock          func() time.Time
	logger         *slog.Logger

	mu            sync.Mutex
	ended         map[uuid.UUID]time.Time
	conns         map[string]*relayConn
	sessions      map[uuid.UUID]map[*relayConn]struct{}
	perCredential map[string]int
}

// Validate checks cfg against its protobuf rules and the relay's semantic
// requirements. New calls it; configuration checks may call it without
// generating a secret.
func Validate(cfg *configv1.AssistanceConfig) error {
	if cfg == nil || cfg.GetRelay() == nil {
		return errors.New("assistrelay: relay configuration is required")
	}
	if err := protovalidate.Validate(cfg); err != nil {
		return fmt.Errorf("assistrelay: %w", err)
	}
	relay := cfg.GetRelay()
	address, err := relayAddress(relay.GetRelayAddress())
	if err != nil {
		return err
	}
	listener, err := netip.ParseAddr(relay.GetListener().GetAddress())
	if err != nil {
		return errors.New("assistrelay: listener address is invalid")
	}
	port := relay.GetListener().GetPort()
	if (listener.Unmap() == address || listener.IsUnspecified()) && port >= relay.GetRelayPortMin() && port <= relay.GetRelayPortMax() {
		return errors.New("assistrelay: listener port overlaps the relay port range")
	}
	return nil
}

// New validates cfg and generates the per-process credential secret. It does
// not bind sockets.
func New(cfg *configv1.AssistanceConfig, clock func() time.Time, logger *slog.Logger) (*Relay, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	if clock == nil || logger == nil {
		return nil, errors.New("assistrelay: clock and logger are required")
	}
	relay := cfg.GetRelay()
	address, err := relayAddress(relay.GetRelayAddress())
	if err != nil {
		return nil, err
	}
	maxSessions := int(cfg.GetMaxConcurrentSessions())
	if maxSessions == 0 {
		maxSessions = defaultMaxSessions
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate relay secret: %w", err)
	}
	return &Relay{
		address:        address,
		minPort:        uint16(relay.GetRelayPortMin()),
		maxPort:        uint16(relay.GetRelayPortMax()),
		listen:         net.JoinHostPort(relay.GetListener().GetAddress(), strconv.FormatUint(uint64(relay.GetListener().GetPort()), 10)),
		urls:           append([]string(nil), relay.GetUrls()...),
		realm:          relay.GetRealm(),
		maxSessions:    maxSessions,
		maxAllocations: maxSessions * 2 * maxAllocationsPerCredential,
		secret:         secret,
		clock:          clock,
		logger:         logger,
		ended:          make(map[uuid.UUID]time.Time),
		conns:          make(map[string]*relayConn),
		sessions:       make(map[uuid.UUID]map[*relayConn]struct{}),
		perCredential:  make(map[string]int),
	}, nil
}

// relayAddress admits only a specific IPv4 unicast address: pion allocates
// udp4 relay sockets, and the address is both bound and advertised to peers.
func relayAddress(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, errors.New("assistrelay: relay_address is not an IP address")
	}
	address = address.Unmap()
	if !address.Is4() || address.IsUnspecified() || address.IsMulticast() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, errors.New("assistrelay: relay_address must be a specific IPv4 unicast address")
	}
	return address, nil
}

// MaxSessions is the admission bound for non-ended sessions.
func (r *Relay) MaxSessions() int {
	return r.maxSessions
}

// RelayAddress is the only address relay candidates may carry.
func (r *Relay) RelayAddress() netip.Addr {
	return r.address
}

// ICEServer mints relay credentials for one session role that expire at
// expires (the session's hard end). URLs come only from configuration.
func (r *Relay) ICEServer(session uuid.UUID, role string, expires time.Time) (*agentv1.AssistanceIceServer, error) {
	if session == uuid.Nil || (role != RoleDevice && role != RoleConsole) || expires.Unix() <= 0 {
		return nil, errors.New("assistrelay: invalid credential request")
	}
	name := username(expires, session, role)
	return &agentv1.AssistanceIceServer{Urls: append([]string(nil), r.urls...), Username: name, Credential: password(r.secret, name)}, nil
}

// End marks a session ended until its credentials expire and closes every
// relay allocation authenticated for it. It is idempotent.
func (r *Relay) End(session uuid.UUID, expires time.Time) {
	now := r.clock()
	r.mu.Lock()
	for id, until := range r.ended {
		if now.After(until) {
			delete(r.ended, id)
		}
	}
	r.ended[session] = expires.Add(endedRetention)
	closing := make([]*relayConn, 0, len(r.sessions[session]))
	for conn := range r.sessions[session] {
		closing = append(closing, conn)
	}
	r.mu.Unlock()
	for _, conn := range closing {
		r.closeAllocation(conn)
	}
}

func (r *Relay) closeAllocation(conn *relayConn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		r.logger.Debug("close relay allocation", "error", err)
	}
}

// Ended reports whether the relay refuses session because it was reported ended.
func (r *Relay) Ended(session uuid.UUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.ended[session]
	return ok
}

// authenticate implements turn.AuthHandler for TURN REST credentials.
func (r *Relay) authenticate(name, realm string, _ net.Addr) ([]byte, bool) {
	cred, err := parseUsername(name)
	if err != nil || realm != r.realm || !r.clock().Before(cred.expires) || r.Ended(cred.session) {
		return nil, false
	}
	return turn.GenerateAuthKey(name, realm, password(r.secret, name)), true
}

// quota implements turn.QuotaHandler.
func (r *Relay) quota(name, _ string, _ net.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.perCredential[name] < maxAllocationsPerCredential && len(r.conns) < r.maxAllocations
}

// permit implements turn.PermissionHandler: peers are only this relay.
func (r *Relay) permit(_ net.Addr, peer net.IP) bool {
	address, ok := netip.AddrFromSlice(peer)
	return ok && address.Unmap() == r.address
}

func (r *Relay) relayPeer(addr net.Addr) bool {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return false
	}
	address, ok := netip.AddrFromSlice(udp.IP)
	return ok && address.Unmap() == r.address && udp.Port >= int(r.minPort) && udp.Port <= int(r.maxPort)
}

func (r *Relay) register(key string, conn *relayConn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.conns) >= r.maxAllocations {
		return errors.New("assistrelay: allocation capacity reached")
	}
	r.conns[key] = conn
	return nil
}

// allocated binds a fresh allocation socket to its authenticated session and
// bounds it by the credential expiry.
func (r *Relay) allocated(name string, relayAddr net.Addr) {
	cred, err := parseUsername(name)
	r.mu.Lock()
	conn := r.conns[relayAddr.String()]
	if conn == nil {
		r.mu.Unlock()
		return
	}
	_, ended := r.ended[cred.session]
	if err != nil || ended || conn.bound {
		r.mu.Unlock()
		r.closeAllocation(conn)
		return
	}
	conn.bound, conn.username, conn.session = true, name, cred.session
	r.perCredential[name]++
	if r.sessions[cred.session] == nil {
		r.sessions[cred.session] = make(map[*relayConn]struct{})
	}
	r.sessions[cred.session][conn] = struct{}{}
	conn.timer = time.AfterFunc(cred.expires.Sub(r.clock()), func() { r.closeAllocation(conn) })
	r.mu.Unlock()
}

func (r *Relay) unregister(conn *relayConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns[conn.key] == conn {
		delete(r.conns, conn.key)
	}
	if conn.timer != nil {
		conn.timer.Stop()
	}
	if !conn.bound {
		return
	}
	if r.perCredential[conn.username]--; r.perCredential[conn.username] <= 0 {
		delete(r.perCredential, conn.username)
	}
	if set := r.sessions[conn.session]; set != nil {
		delete(set, conn)
		if len(set) == 0 {
			delete(r.sessions, conn.session)
		}
	}
}

func (r *Relay) closeAll() {
	r.mu.Lock()
	closing := make([]*relayConn, 0, len(r.conns))
	for _, conn := range r.conns {
		closing = append(closing, conn)
	}
	r.mu.Unlock()
	for _, conn := range closing {
		r.closeAllocation(conn)
	}
}

// Server is a running relay. Close stops it.
type Server struct {
	relay    *Relay
	turn     *turn.Server
	udp      net.PacketConn
	tcp      *boundedListener
	closeErr error
	once     sync.Once
}

// Listen binds the UDP and TCP listeners from configuration and starts serving.
func (r *Relay) Listen(ctx context.Context) (*Server, error) {
	config := new(net.ListenConfig)
	udp, err := config.ListenPacket(ctx, "udp", r.listen)
	if err != nil {
		return nil, fmt.Errorf("bind relay UDP listener: %w", err)
	}
	tcp, err := config.Listen(ctx, "tcp", r.listen)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("bind relay TCP listener: %w", err), udp.Close())
	}
	server, err := r.serve(udp, tcp)
	if err != nil {
		return nil, errors.Join(err, udp.Close(), tcp.Close())
	}
	r.logger.Info("assistance relay ready", "listener", r.listen, "relay_address", r.address.String(), "relay_ports", fmt.Sprintf("%d-%d", r.minPort, r.maxPort))
	return server, nil
}

func (r *Relay) serve(udp net.PacketConn, tcp net.Listener) (*Server, error) {
	bounded := &boundedListener{Listener: tcp, conns: make(map[net.Conn]struct{})}
	generator := func() *relayGenerator {
		return &relayGenerator{relay: r, inner: &turn.RelayAddressGeneratorPortRange{
			RelayAddress: net.IP(r.address.AsSlice()),
			Address:      r.address.String(),
			MinPort:      r.minPort,
			MaxPort:      r.maxPort,
			MaxRetries:   64,
		}}
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm:         r.realm,
		AuthHandler:   r.authenticate,
		QuotaHandler:  r.quota,
		LoggerFactory: loggerFactory{logger: r.logger},
		EventHandler: turn.EventHandler{
			OnAllocationCreated: func(_, _ net.Addr, _, name, _ string, relayAddr net.Addr, _ int) {
				r.allocated(name, relayAddr)
			},
		},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: udp, RelayAddressGenerator: generator(), PermissionHandler: r.permit}},
		ListenerConfigs:   []turn.ListenerConfig{{Listener: bounded, RelayAddressGenerator: generator(), PermissionHandler: r.permit}},
	})
	if err != nil {
		return nil, fmt.Errorf("start relay: %w", err)
	}
	return &Server{relay: r, turn: server, udp: udp, tcp: bounded}, nil
}

// UDPAddr and TCPAddr report the bound listener addresses.
func (s *Server) UDPAddr() net.Addr { return s.udp.LocalAddr() }
func (s *Server) TCPAddr() net.Addr { return s.tcp.Addr() }

// Close stops the listeners, TCP control connections and every allocation.
func (s *Server) Close() error {
	s.once.Do(func() {
		s.closeErr = s.turn.Close()
		s.tcp.closeConns()
		s.relay.closeAll()
	})
	return s.closeErr
}

// relayGenerator wraps the port-range generator so every allocation socket is
// registered, peer-filtered and closable by session.
type relayGenerator struct {
	relay *Relay
	inner *turn.RelayAddressGeneratorPortRange
}

func (g *relayGenerator) Validate() error {
	return g.inner.Validate()
}

func (g *relayGenerator) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	if requestedPort != 0 && (requestedPort < int(g.relay.minPort) || requestedPort > int(g.relay.maxPort)) {
		return nil, nil, errors.New("assistrelay: requested port is outside the relay range")
	}
	conn, addr, err := g.inner.AllocatePacketConn(network, requestedPort)
	if err != nil {
		return nil, nil, err
	}
	wrapped := &relayConn{PacketConn: conn, relay: g.relay, key: addr.String()}
	if err := g.relay.register(wrapped.key, wrapped); err != nil {
		return nil, nil, errors.Join(err, conn.Close())
	}
	return wrapped, addr, nil
}

func (g *relayGenerator) AllocateConn(string, int) (net.Conn, net.Addr, error) {
	return nil, nil, errors.New("assistrelay: TCP relay allocations are not supported")
}

// relayConn is one allocation's relay socket. It only exchanges datagrams
// with other relay allocations of this server.
type relayConn struct {
	net.PacketConn
	relay *Relay
	key   string
	once  sync.Once
	err   error

	// Guarded by relay.mu.
	bound    bool
	username string
	session  uuid.UUID
	timer    *time.Timer
}

func (c *relayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil || c.relay.relayPeer(addr) {
			return n, addr, err
		}
	}
}

func (c *relayConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !c.relay.relayPeer(addr) {
		return 0, errPeerRefused
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *relayConn) Close() error {
	c.once.Do(func() {
		c.relay.unregister(c)
		c.err = c.PacketConn.Close()
	})
	return c.err
}

// boundedListener caps concurrent TURN-over-TCP control connections and
// bounds each connection's lifetime.
type boundedListener struct {
	net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		admitted := !l.closed && len(l.conns) < maxTCPConnections
		if admitted {
			l.conns[conn] = struct{}{}
		}
		l.mu.Unlock()
		if !admitted {
			_ = conn.Close()
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(tcpConnectionLifetime)); err != nil {
			l.forget(conn)
			_ = conn.Close()
			continue
		}
		return &trackedConn{Conn: conn, listener: l}, nil
	}
}

func (l *boundedListener) forget(conn net.Conn) {
	l.mu.Lock()
	delete(l.conns, conn)
	l.mu.Unlock()
}

func (l *boundedListener) closeConns() {
	l.mu.Lock()
	l.closed = true
	conns := make([]net.Conn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type trackedConn struct {
	net.Conn
	listener *boundedListener
	once     sync.Once
	err      error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.listener.forget(c.Conn)
		c.err = c.Conn.Close()
	})
	return c.err
}
