// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	testUID       = 1000
	testSessionID = "0b8a3f3e-6c62-4a43-9c52-2f1b2d0f8a10"
	testOffer     = "v=0\r\na=fingerprint:sha-256 AA\r\na=candidate:1 1 udp 1 192.0.2.1 3478 typ relay raddr 0.0.0.0 rport 0\r\n"
	testAnswer    = "v=0\r\na=fingerprint:sha-256 BB\r\na=candidate:1 1 udp 1 192.0.2.2 3478 typ relay raddr 0.0.0.0 rport 0\r\n"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fakeNotice struct {
	notification Notification
	result       chan string
	closed       chan struct{}
	closeOnce    sync.Once
	updates      chan Notification
}

func (n *fakeNotice) Result() <-chan string { return n.result }

func (n *fakeNotice) Close(context.Context) error {
	n.closeOnce.Do(func() { close(n.closed) })
	return nil
}

func (n *fakeNotice) Update(_ context.Context, notification Notification) error {
	n.updates <- notification
	return nil
}

func (n *fakeNotice) isClosed() bool {
	select {
	case <-n.closed:
		return true
	default:
		return false
	}
}

type fakeNotifier struct {
	capabilities []string
	server       string
	err          error
	posted       chan *fakeNotice
}

func newFakeNotifier() *fakeNotifier {
	return &fakeNotifier{capabilities: []string{"actions", "body"}, server: "gnome-shell", posted: make(chan *fakeNotice, 32)}
}

func (n *fakeNotifier) Capabilities(context.Context) ([]string, error) {
	return n.capabilities, n.err
}

func (n *fakeNotifier) ServerName(context.Context) (string, error) {
	return n.server, n.err
}

func (n *fakeNotifier) Notify(_ context.Context, notification Notification) (Notice, error) {
	notice := &fakeNotice{notification: notification, result: make(chan string, 1), closed: make(chan struct{}), updates: make(chan Notification, 8)}
	n.posted <- notice
	return notice, nil
}

// next returns the next posted notification with summary.
func (n *fakeNotifier) next(t *testing.T, summary string) *fakeNotice {
	t.Helper()
	return n.nextWith(t, summary, func(got string) bool { return got == summary })
}

// nextWith returns the next posted notification whose summary matches.
func (n *fakeNotifier) nextWith(t *testing.T, summary string, match func(string) bool) *fakeNotice {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case notice := <-n.posted:
			if match(notice.notification.Summary) {
				return notice
			}
		case <-timeout:
			t.Fatalf("no %q notification", summary)
			return nil
		}
	}
}

type fakeGrant struct {
	control      bool
	closed       chan struct{}
	mu           sync.Mutex
	injected     []InputEvent
	closes       int
	streams      []Stream
	clipboard    bool
	text         string
	writes       int
	selected     string
	cursorHidden bool
	paused       bool
	// restore is the persistent-grant token the desktop returns, if any.
	restore string
}

func (g *fakeGrant) Streams() []Stream {
	if g.streams != nil {
		return g.streams
	}
	return []Stream{{NodeID: 42, ID: "monitor-1", Label: "Monitor 1", Width: 1920, Height: 1080}}
}
func (g *fakeGrant) SelectStream(id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.selected = id
	return nil
}
func (g *fakeGrant) CursorHidden() bool      { return g.cursorHidden }
func (g *fakeGrant) ClipboardGranted() bool  { return g.clipboard }
func (g *fakeGrant) ClipboardReason() string { return "" }
func (g *fakeGrant) KeyboardGranted() bool   { return g.control }
func (g *fakeGrant) PortalVersions() string  { return "screencast_5" }
func (g *fakeGrant) PauseClipboard(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.text, g.paused = "", true
	return nil
}
func (g *fakeGrant) ResumeClipboard() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.paused = false
	return nil
}
func (g *fakeGrant) ClipboardWrite(_ context.Context, text string, _ time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		return errors.New("clipboard_paused")
	}
	g.text, g.writes = text, g.writes+1
	return nil
}
func (g *fakeGrant) ClipboardRead(context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		return "", errors.New("clipboard_paused")
	}
	return g.text, nil
}
func (g *fakeGrant) ControlGranted() bool    { return g.control }
func (g *fakeGrant) RestoreToken() string    { return g.restore }
func (g *fakeGrant) Closed() <-chan struct{} { return g.closed }

func (g *fakeGrant) OpenPipeWire(context.Context) (*os.File, error) {
	return os.Open(os.DevNull)
}

func (g *fakeGrant) Inject(_ context.Context, event InputEvent) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.injected = append(g.injected, event)
	return nil
}

func (g *fakeGrant) Close(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closes++
	return nil
}

func (g *fakeGrant) snapshot() ([]InputEvent, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]InputEvent(nil), g.injected...), g.closes
}

type fakePortal struct {
	grant         *fakeGrant
	grantOverride Grant
	err           error
	block         bool
	mu            sync.Mutex
	modes         []agentv1.AssistanceMode
	opened        chan struct{}
	choose        func(context.Context, string) (*os.File, error)
	// refuse maps a mode to the Check result a desktop's portal produces.
	refuse  map[agentv1.AssistanceMode]error
	checked []PortalRequest
	opens   []PortalRequest
}

func (p *fakePortal) Check(_ context.Context, request PortalRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked = append(p.checked, request)
	return p.refuse[request.Mode]
}

func (p *fakePortal) Open(ctx context.Context, request PortalRequest) (Grant, error) {
	mode := request.Mode
	p.mu.Lock()
	p.modes = append(p.modes, mode)
	p.opens = append(p.opens, request)
	p.mu.Unlock()
	if p.opened != nil {
		p.opened <- struct{}{}
	}
	if p.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.err != nil {
		return nil, p.err
	}
	if p.grantOverride != nil {
		return p.grantOverride, nil
	}
	return p.grant, nil
}

func (p *fakePortal) ChooseFile(ctx context.Context, title string) (*os.File, error) {
	if p.choose == nil {
		return nil, ErrPortalCancelled
	}
	return p.choose(ctx, title)
}

func (p *fakePortal) openCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.modes)
}

type fakeCapture struct {
	packets   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *fakeCapture) ReadPacket(buf []byte) (int, error) {
	select {
	case packet, ok := <-c.packets:
		if !ok {
			return 0, io.EOF
		}
		return copy(buf, packet), nil
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *fakeCapture) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

type fakeCapturer struct {
	capture  *fakeCapture
	err      error
	captures []*fakeCapture
	mu       sync.Mutex
	requests []CaptureRequest
}

func newFakeCapturer() *fakeCapturer {
	packets := make(chan []byte, 4)
	packets <- []byte{0x80, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0xAA}
	return &fakeCapturer{capture: &fakeCapture{packets: packets, closed: make(chan struct{})}}
}

func (c *fakeCapturer) Start(_ context.Context, request CaptureRequest) (Capture, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, request)
	if request.PipeWire == nil {
		return nil, errors.New("missing pipewire")
	}
	if c.err != nil {
		return nil, c.err
	}
	if len(c.captures) > 0 {
		capture := c.captures[0]
		c.captures = c.captures[1:]
		return capture, nil
	}
	return c.capture, nil
}

type fakePeer struct {
	config    PeerConfig
	offer     string
	connected chan struct{}
	failed    chan struct{}
	input     chan []byte
	mu        sync.Mutex
	answers   []string
	written   int
	closes    int
	frames    displayFrames
	files     chan []byte
	sentFiles chan []byte
	inputGate pionPeer
	// annotations feeds the overlay channel; audio counts sound packets.
	annotations chan []byte
	audio       int
}

func (p *fakePeer) Offer(context.Context) (string, error) { return p.offer, nil }

func (p *fakePeer) Answer(sdp string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answers = append(p.answers, sdp)
	return nil
}

func (p *fakePeer) WriteRTP([]byte) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.written++
	return true, nil
}

func (p *fakePeer) BeginDisplay(display string, generation uint32) error {
	return p.frames.begin(display, generation)
}

func (p *fakePeer) PublishDisplayFrame(frame DisplayFrame) error {
	return p.frames.publish(frame)
}

func (p *fakePeer) EndDisplayFrames() { p.frames.close() }

func (p *fakePeer) SetInputState(epoch uint32, paused bool) error {
	p.inputGate.input = p.input
	return p.inputGate.SetInputState(epoch, paused)
}
func (p *fakePeer) Files() <-chan []byte { return p.files }
func (p *fakePeer) Annotations() <-chan []byte {
	if !p.config.Annotation {
		return nil
	}
	return p.annotations
}
func (p *fakePeer) WriteAudioRTP([]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.audio++
	return nil
}
func (p *fakePeer) SendFile(ctx context.Context, frame []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.sentFiles <- append([]byte(nil), frame...):
		return nil
	}
}

func (p *fakePeer) Connected() <-chan struct{} { return p.connected }
func (p *fakePeer) Failed() <-chan struct{}    { return p.failed }

func (p *fakePeer) Input() <-chan []byte {
	if !p.config.Input {
		return nil
	}
	return p.input
}

func (p *fakePeer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	return nil
}

func (p *fakePeer) state() (answers []string, closes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.answers...), p.closes
}

type fakePeers struct {
	peer *fakePeer
	mu   sync.Mutex
	made []PeerConfig
}

func newFakePeers() *fakePeers {
	return &fakePeers{peer: &fakePeer{
		offer:       testOffer,
		connected:   make(chan struct{}),
		failed:      make(chan struct{}),
		input:       make(chan []byte, 16),
		files:       make(chan []byte, 8),
		sentFiles:   make(chan []byte, 8),
		annotations: make(chan []byte, 16),
	}}
}

func (f *fakePeers) NewPeer(config PeerConfig) (Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.made = append(f.made, config)
	f.peer.config = config
	return f.peer, nil
}

// fakeClient is the executor's SessionService.
type fakeClient struct {
	mu           sync.Mutex
	respond      func(*agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error)
	requests     []*agentv1.SyncSessionRequest
	recordings   []*agentv1.PutAssistanceRecordingRequest
	recordingErr error
}

func (c *fakeClient) SyncSession(_ context.Context, request *connect.Request[agentv1.SyncSessionRequest]) (*connect.Response[agentv1.SyncSessionResponse], error) {
	c.mu.Lock()
	c.requests = append(c.requests, request.Msg)
	respond := c.respond
	c.mu.Unlock()
	response, err := respond(request.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (c *fakeClient) PutAssistanceRecording(_ context.Context, request *connect.Request[agentv1.PutAssistanceRecordingRequest]) (*connect.Response[agentv1.PutAssistanceRecordingResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recordingErr != nil {
		return nil, c.recordingErr
	}
	c.recordings = append(c.recordings, proto.CloneOf(request.Msg))
	return connect.NewResponse(&agentv1.PutAssistanceRecordingResponse{}), nil
}

func (c *fakeClient) set(respond func(*agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.respond = respond
}

type harness struct {
	t        *testing.T
	helper   *Helper
	clock    *fakeClock
	client   *fakeClient
	notifier *fakeNotifier
	portal   *fakePortal
	capturer *fakeCapturer
	peers    *fakePeers
	locks    *fakeLocks
	ctx      context.Context
	// local is the executor-bound session the fake executor reports.
	local *agentv1.AssistanceLocalSession
}

// fakeLocks is the LockMonitor boundary: one channel per subscription.
type fakeLocks struct {
	mu         sync.Mutex
	err        error
	subscribed []string
	current    *fakeLockWatch
}

type fakeLockWatch struct {
	locked chan string
	once   sync.Once
	closed bool
}

func (w *fakeLockWatch) Locked() <-chan string { return w.locked }

func (w *fakeLockWatch) Close() error {
	w.once.Do(func() { w.closed = true })
	return nil
}

func (l *fakeLocks) Subscribe(_ context.Context, sessionID string) (LockSubscription, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.subscribed = append(l.subscribed, sessionID)
	if l.err != nil {
		return nil, l.err
	}
	l.current = &fakeLockWatch{locked: make(chan string, 4)}
	return l.current, nil
}

func (l *fakeLocks) watch() *fakeLockWatch {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.current
}

func newHarness(t *testing.T) *harness {
	return newDesktopHarness(t, "ubuntu:GNOME")
}

// newDesktopHarness builds a helper for a session whose XDG_CURRENT_DESKTOP
// is currentDesktop.
func newDesktopHarness(t *testing.T, currentDesktop string) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		clock:    &fakeClock{now: time.Now()},
		client:   &fakeClient{},
		notifier: newFakeNotifier(),
		portal:   &fakePortal{grant: &fakeGrant{closed: make(chan struct{})}},
		capturer: newFakeCapturer(),
		peers:    newFakePeers(),
		locks:    &fakeLocks{},
		ctx:      t.Context(),
		local:    localSession(),
	}
	h.client.set(h.directives())
	helper, err := newHelper(Config{
		Client:         h.client,
		Notifier:       h.notifier,
		Portal:         h.portal,
		Capturer:       h.capturer,
		Peers:          h.peers,
		Locks:          h.locks,
		CurrentDesktop: currentDesktop,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, testUID)
	if err != nil {
		t.Fatal(err)
	}
	helper.deps.clock = h.clock.Now
	helper.deps.repostInterval = 10 * time.Millisecond
	helper.deps.captureGrace = 10 * time.Millisecond
	helper.lastSuccess = h.clock.Now()
	h.helper = helper
	t.Cleanup(func() {
		helper.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "test_done")
		helper.group.Wait()
	})
	return h
}

func localSession() *agentv1.AssistanceLocalSession {
	return &agentv1.AssistanceLocalSession{Username: "alice", Uid: testUID, LogindSessionId: "2", SessionType: "wayland", Desktop: "GNOME"}
}

func invitation(mode agentv1.AssistanceMode, consent, ends time.Duration) *agentv1.AssistanceInvitation {
	now := time.Now()
	policy := &agentv1.AssistancePolicy{Keyboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON}
	return &agentv1.AssistanceInvitation{
		SessionId:             testSessionID,
		Mode:                  mode,
		Reason:                "printer <setup> & drivers",
		OperatorDisplay:       "Olga Operator",
		ConsentDeadline:       timestamppb.New(now.Add(consent)),
		EndsAt:                timestamppb.New(now.Add(ends)),
		IceServers:            []*agentv1.AssistanceIceServer{{Urls: []string{"turn:192.0.2.1:3478?transport=udp"}, Username: "u", Credential: "c"}},
		RequestedCapabilities: policy,
		EffectiveCapabilities: policy,
	}
}

// directives returns a responder handing out the given directives.
func (h *harness) directives(directives ...*agentv1.AssistanceDirective) func(*agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error) {
	return func(*agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error) {
		for _, directive := range directives {
			if directive.AuthorizedUntil == nil {
				directive.AuthorizedUntil = timestamppb.New(h.clock.Now().Add(25 * time.Second))
			}
		}
		return &agentv1.SyncSessionResponse{Directives: directives, LocalSession: proto.CloneOf(h.local)}, nil
	}
}

// sync runs one executor exchange with the given directives.
func (h *harness) sync(directives ...*agentv1.AssistanceDirective) {
	h.t.Helper()
	h.client.set(h.directives(directives...))
	h.helper.syncOnce(h.ctx, context.WithoutCancel(h.ctx))
}

// report returns the helper's current report for the test session.
func (h *harness) report() *agentv1.SessionAssistanceReport {
	s, ok := h.helper.sessions[testSessionID]
	if !ok {
		return nil
	}
	report, _ := s.report()
	return report
}

// waitPhase polls until the test session reaches phase.
func (h *harness) waitPhase(phase agentv1.AssistancePhase) *agentv1.SessionAssistanceReport {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if report := h.report(); report != nil && report.GetPhase() == phase {
			return report
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("session did not reach %s; last report %v", phase, h.report())
	return nil
}

// waitEnded waits for ENDED and for the session goroutine's cleanup.
func (h *harness) waitEnded(cause agentv1.AssistanceEndCause) *agentv1.SessionAssistanceReport {
	h.t.Helper()
	s := h.helper.sessions[testSessionID]
	report := h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED)
	if report.GetEndCause() != cause {
		h.t.Fatalf("end cause = %s (%s), want %s", report.GetEndCause(), report.GetEndDetail(), cause)
	}
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("session cleanup did not finish")
	}
	return report
}

// offered drives a fresh invitation to OFFERED by allowing the prompt.
func (h *harness) offered(directive *agentv1.AssistanceDirective) *agentv1.SessionAssistanceReport {
	h.t.Helper()
	h.sync(directive)
	// Recording disclosure extends the request summary.
	prompt := h.notifier.nextWith(h.t, "Remote assistance request", func(summary string) bool {
		return strings.HasPrefix(summary, "Remote assistance request")
	})
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	prompt.result <- actionAllow
	return h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
}

func (c *fakeClient) last() *agentv1.SyncSessionRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests[len(c.requests)-1]
}

func (c *fakeClient) sawPhase(phase agentv1.AssistancePhase) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, request := range c.requests {
		for _, report := range request.GetReports() {
			if report.GetPhase() == phase {
				return true
			}
		}
	}
	return false
}
