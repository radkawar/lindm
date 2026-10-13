package desktop

import (
	"context"
	"sync"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

type heldCloseCapture struct {
	Capture
	closing       chan struct{}
	continueClose chan struct{}
	once          sync.Once
}

func (c *heldCloseCapture) Close() error {
	c.once.Do(func() { close(c.closing) })
	<-c.continueClose
	return c.Capture.Close()
}

type switchTestCapturer struct {
	first         Capture
	second        Capture
	secondStarted chan struct{}
	started       bool
}

func (c *switchTestCapturer) Start(context.Context, CaptureRequest) (Capture, error) {
	if !c.started {
		c.started = true
		return c.first, nil
	}
	close(c.secondStarted)
	return c.second, nil
}

func sendSwitchBurst(t *testing.T, h *harness) {
	t.Helper()
	// More than the production queue capacity must drain while teardown or
	// first-packet readiness is blocked. A lock held across either phase stalls
	// this loop long before the native call timeout and used to kill the session.
	messages := []string{
		`{"t":"move","x":0.5,"y":0.5,"display":"monitor-1","generation":1}`,
		`{"t":"key","code":"KeyA","down":true,"display":"monitor-2","generation":2}`,
		`{"t":"keysym","keysym":8364,"down":true,"display":"monitor-2","generation":2}`,
		`{"t":"release"}`,
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for i := range inputQueueSize + 32 {
		select {
		case h.peers.peer.input <- []byte(messages[i%len(messages)]):
		case <-deadline.C:
			t.Fatal("input pump blocked during capture switch")
		}
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for len(h.peers.peer.input) != 0 {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("queued input did not drain while switch was paused")
		}
	}
	if h.report().GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		t.Fatal("switch input ended session")
	}
	if events, _ := h.portal.grant.snapshot(); len(events) != 2 {
		t.Fatalf("input crossed paused switch: %+v", events)
	}
}

func TestConcurrentInputDrainsThroughoutCaptureSwitchAndRemainsFenced(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control = true
	h.portal.grant.streams = []Stream{{NodeID: 42, ID: "monitor-1"}, {NodeID: 43, ID: "monitor-2"}}
	old := &heldCloseCapture{Capture: h.capturer.capture, closing: make(chan struct{}), continueClose: make(chan struct{})}
	var resume sync.Once
	unblock := func() { resume.Do(func() { close(old.continueClose) }) }
	t.Cleanup(unblock)
	second := &fakeCapture{packets: make(chan []byte, 1), closed: make(chan struct{})}
	capturer := &switchTestCapturer{first: old, second: second, secondStarted: make(chan struct{})}
	h.helper.deps.capturer = capturer
	inv := tierOneInvitation(modeControl)
	activateTierOne(h, inv)
	h.peers.peer.input <- []byte(`{"t":"key","code":"ControlLeft","down":true,"display":"monitor-1","generation":1}`)
	waitInjected(t, h.portal.grant, 1)
	command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY)
	command.DisplayId = "monitor-2"
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
	select {
	case <-old.closing:
	case <-time.After(time.Second):
		t.Fatal("old capture teardown did not begin")
	}
	sendSwitchBurst(t, h)
	before := h.report()
	if before.GetSelectedDisplayId() != "monitor-1" || before.GetDisplayGeneration() != 1 || before.GetCommandResult() != nil {
		t.Fatal("incomplete switch was published")
	}
	unblock()
	select {
	case <-capturer.secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second capture did not start")
	}
	sendSwitchBurst(t, h)
	// Permit the first new frame only after the input pump has drained while
	// waiting. New source coordinates/keys must remain blocked until publication.
	second.packets <- timelinePacket(500, 700000, 987)
	result := waitCommand(h, command.GetRequestId())
	if result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("switch result = %v", result)
	}
	h.peers.peer.input <- []byte(`{"t":"key","code":"KeyA","down":true,"display":"monitor-1","generation":1}`)
	h.peers.peer.input <- []byte(`{"t":"keysym","keysym":8364,"down":true,"display":"monitor-1","generation":1}`)
	h.peers.peer.input <- []byte(`{"t":"move","x":0.25,"y":0.75,"display":"monitor-2","generation":2}`)
	waitInjected(t, h.portal.grant, 3)
	events, _ := h.portal.grant.snapshot()
	if len(events) != 3 || events[1].Down || events[1].Keycode != 29 || events[2].kind != inputMove || events[2].Display != "monitor-2" {
		t.Fatalf("stale keyboard or coordinates crossed switch: %+v", events)
	}
	if h.report().GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		t.Fatal("concurrent switch terminated consented session")
	}
}
