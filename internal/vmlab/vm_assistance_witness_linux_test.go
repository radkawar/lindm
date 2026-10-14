// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"image"
	"io"
	"math"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestAssistancePointerWitnessRejectsWrongHeadAndScale(t *testing.T) {
	for _, got := range []assistancePointerWitness{
		{Head: 1, X: 0.7, Y: 0.7},
		{Head: 0, X: 0.35, Y: 0.7},
		{Head: 0, X: 0.7, Y: 0.35},
		{Head: 0, X: math.NaN(), Y: 0.7},
		{Head: 0, X: 0.7, Y: math.Inf(1)},
	} {
		if err := verifyAssistancePointer(got, 0, 0.7, 0.7); err == nil {
			t.Fatalf("accepted misrouted pointer: %+v", got)
		}
	}
	if err := verifyAssistancePointer(assistancePointerWitness{Head: 1, X: 0.699, Y: 0.701}, 1, 0.7, 0.7); err != nil {
		t.Fatal(err)
	}
}

func TestAssistanceLocalConsentUsesWholeDesktopCoordinates(t *testing.T) {
	screen := &assistanceScreen{desktopBounds: image.Rect(-1024, 0, 1280, 1024), headOrigin: image.Pt(0, 0)}
	display, point := screen.localPoint(image.Rect(0, 0, 1280, 1024), image.Pt(640, 200))
	if display != screen.desktopBounds || point != image.Pt(640, 200) {
		t.Fatalf("local consent mapping = %v %v", display, point)
	}
	// Head zero can be placed right of a differently sized second monitor;
	// normalizing against its screenshot alone sends the click to the wrong head.
	x := (point.X - display.Min.X) * qmpAbsoluteMax / (display.Dx() - 1)
	if x <= qmpAbsoluteMax/2 {
		t.Fatalf("head-zero click mapped into the left half: %d", x)
	}
}

// Fedora 44 x86 and Ubuntu 24.04 arm64 monitors runs hovered Allow through the
// desktop-mapped move, then clicked against the head-0 screendump: the press
// landed off the banner and the session stayed PROMPTED. Every local click and
// move must send the same desktop-mapped absolute coordinates.
func TestAssistanceLocalClickUsesDesktopMappedCoordinates(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("unix", filepath.Join(dir, "qmp.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	type absEvent struct {
		Type string `json:"type"`
		Data struct {
			Axis  string `json:"axis"`
			Value int    `json:"value"`
		} `json:"data"`
	}
	commands := make(chan []absEvent, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				decoder := json.NewDecoder(conn)
				_, _ = io.WriteString(conn, "{\"QMP\":{}}\n")
				for range 2 {
					var command struct {
						ID        string `json:"id"`
						Arguments struct {
							Events []absEvent `json:"events"`
						} `json:"arguments"`
					}
					if decoder.Decode(&command) != nil {
						return
					}
					if command.ID != "capabilities" {
						commands <- command.Arguments.Events
					}
					reply, _ := json.Marshal(map[string]any{"id": command.ID, "return": map[string]any{}})
					_, _ = conn.Write(append(reply, '\n'))
				}
			}()
		}
	}()
	// Head 0 (1280x800) right of a 1024x768 second head, as GDK reports it.
	screen := &assistanceScreen{
		vm:            &guestVM{dir: dir, done: make(chan struct{}), log: new(vmLog)},
		desktopBounds: image.Rect(-1024, 0, 1280, 800),
		headOrigin:    image.Pt(0, 0),
	}
	head0 := image.Rect(0, 0, 1280, 800)
	allow := image.Pt(511, 250)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := screen.move(ctx, head0, allow); err != nil {
		t.Fatal(err)
	}
	if err := screen.pointerClick(ctx, head0, allow); err != nil {
		t.Fatal(err)
	}
	wantX := (allow.X + 1024) * qmpAbsoluteMax / (2304 - 1)
	wantY := allow.Y * qmpAbsoluteMax / (800 - 1)
	for _, name := range []string{"hover move", "click move"} {
		events := <-commands
		if len(events) != 2 || events[0].Data.Axis != "x" || events[0].Data.Value != wantX || events[1].Data.Axis != "y" || events[1].Data.Value != wantY {
			t.Fatalf("%s = %+v, want desktop-mapped (%d,%d)", name, events, wantX, wantY)
		}
	}
	for _, phase := range []string{"press", "release"} {
		if events := <-commands; len(events) != 1 || events[0].Type != "btn" {
			t.Fatalf("%s = %+v", phase, events)
		}
	}
}

func TestAssistanceClipboardWitnessRequiresBothNativeDirections(t *testing.T) {
	const operator = "111111111111111111111111"
	const guest = "222222222222222222222222"
	scenario := &assistanceScenarioEvidence{Name: "clipboard", SessionID: "session", LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}}
	makeWitness := func() *assistanceCapabilityWitness {
		return &assistanceCapabilityWitness{
			Capability: "clipboard", SessionID: "session", Checks: []string{"roundtrip"},
			OperatorNonce: operator, PastedOperatorNonce: operator,
			Guest: &assistanceFixtureState{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "7", UID: 1000, PID: 123, Pasted: operator, ClipboardSource: guest},
			Commands: []assistanceCommandWitness{
				{RequestID: "11111111-1111-4111-8111-111111111111", Kind: "ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE", Status: "ASSISTANCE_COMMAND_STATUS_SUCCEEDED"},
				{RequestID: "22222222-2222-4222-8222-222222222222", Kind: "ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ", Status: "ASSISTANCE_COMMAND_STATUS_SUCCEEDED", Text: guest},
			},
		}
	}
	if err := verifyAssistanceCapabilityWitness(scenario, makeWitness()); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*assistanceCapabilityWitness){
		"command acceptance only": func(w *assistanceCapabilityWitness) { w.PastedOperatorNonce = "" },
		"echoed operator nonce": func(w *assistanceCapabilityWitness) {
			w.Guest.ClipboardSource = operator
			w.Commands[1].Text = operator
		},
		"browser did not copy": func(w *assistanceCapabilityWitness) { w.Commands[1].Text = "" },
		"wrong session":        func(w *assistanceCapabilityWitness) { w.SessionID = "other" },
		"pending operation":    func(w *assistanceCapabilityWitness) { w.Commands[0].Status = "ASSISTANCE_COMMAND_STATUS_PENDING" },
	} {
		t.Run(name, func(t *testing.T) {
			witness := makeWitness()
			alter(witness)
			if err := verifyAssistanceCapabilityWitness(scenario, witness); err == nil {
				t.Fatal("accepted incomplete clipboard evidence")
			}
		})
	}
}

func TestAssistanceMonitorWitnessRequiresCurrentNativeNonce(t *testing.T) {
	const nonce = "222222222222222222222222"
	scenario := &assistanceScenarioEvidence{Name: "monitors", SessionID: "session", LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}}
	var witness assistanceCapabilityWitness
	if err := json.Unmarshal([]byte(`{
		"capability":"monitors","session_id":"session","checks":["selected-native-heads"],
		"granted_displays":[{},{}],
		"guest":{"backend":"GdkWaylandDisplay","display":"wayland-0","session_type":"wayland",
			"session_id":"7","uid":1000,"pid":123,"clipboard_source":"222222222222222222222222",
			"monitors":[{"head":0},{"head":1}],
			"clicks":[{},{"head":0,"x":0.7,"y":0.7},{"head":1,"x":0.7,"y":0.7}]},
		"monitor_selections":[
			{"label":"Monitor 1","head":0,"nonce":"222222222222222222222222"},
			{"label":"Monitor 2","head":1,"nonce":"222222222222222222222222"}],
		"commands":[{"requestId":"11111111-1111-4111-8111-111111111111",
			"kind":"ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY","status":"ASSISTANCE_COMMAND_STATUS_SUCCEEDED"}]
	}`), &witness); err != nil {
		t.Fatal(err)
	}
	if err := verifyAssistanceCapabilityWitness(scenario, &witness); err != nil {
		t.Fatal(err)
	}
	for head := range witness.MonitorSelections {
		for _, stale := range []string{"", "111111111111111111111111"} {
			witness.MonitorSelections[head].Nonce = stale
			if err := verifyAssistanceCapabilityWitness(scenario, &witness); err == nil {
				t.Fatalf("accepted missing or stale marker for head %d", head)
			}
		}
		witness.MonitorSelections[head].Nonce = nonce
	}
}

func TestAssistanceMessageWitnessRejectsScreenshotExistenceAlone(t *testing.T) {
	const nonce = "111111111111111111111111"
	scenario := &assistanceScenarioEvidence{Name: "message", SessionID: "session", OperatorID: "11111111-1111-4111-8111-111111111111", OperatorDisplay: "Assistance Operator", Screenshots: []string{"guest.png"}, LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}}
	witness := &assistanceCapabilityWitness{
		Capability: "message", SessionID: "session", Checks: []string{"visible"}, Guest: &assistanceFixtureState{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "7", UID: 1000, PID: 123},
		OperatorNonce: nonce, MessageScreenshot: "guest.png", Screenshots: []string{"guest.png"},
		MessageActor: &assistanceActor{ID: scenario.OperatorID, Display: scenario.OperatorDisplay, Role: "owner", Permissions: []string{"remote_assistance.view", "remote_assistance.control"}, ObservedAt: time.Now()},
		Commands:     []assistanceCommandWitness{{RequestID: "11111111-1111-4111-8111-111111111111", Kind: "ASSISTANCE_COMMAND_KIND_MESSAGE", Status: "ASSISTANCE_COMMAND_STATUS_SUCCEEDED"}},
	}
	if err := verifyAssistanceCapabilityWitness(scenario, witness); err == nil {
		t.Fatal("screenshot existence qualified message visibility")
	}
	for _, ocr := range []string{
		nonce,
		"LINDM " + nonce,
		"LINDM Message from your support operator " + nonce,
		"Assistance Operator " + nonce,
		"LINDM Message from your support operator Other Operator " + nonce,
		"LINDM\nMessage from your support operator\nOther Assistance Operator:\n" + nonce,
		"LINDM\nMessage from your support operator\nOther Assistance Operator: " + nonce,
		"LINDM\nMessage from your support operator Assistance Operator: " + nonce,
		"LINDM\nMessage from your support operator\nAssistance Operator: xxxx" + nonce[4:],
		"LINDM\nMessage from your support operator\nAssistance Operator: " + nonce[:20],
	} {
		witness.OCR = ocr
		if err := verifyAssistanceCapabilityWitness(scenario, witness); err == nil {
			t.Fatalf("nonce without matching product and authenticated sender qualified: %q", ocr)
		}
	}
	for _, ocr := range []string{
		"LINDM\nMessage from your support operator\nAssistance Operator:\n" + nonce,
		// GNOME joins the message into the in-progress notice body;
		// tesseract reads 1 as i or l (the nonce is all ones).
		"lindm Just now\nRemote assistance in progress\nand controlling your screen. Message from your support operator\nAssistance Operator: iiiiiillllllIIIIII111111\n\nStop\n",
		// tesseract doubled glyphs of a clear nonce (banner-fix-full-01).
		"lindm\nMessage from your support operator\nAssistance Operator: 111111111111111111O11l11\n",
	} {
		witness.OCR = ocr
		if err := verifyAssistanceCapabilityWitness(scenario, witness); err != nil {
			t.Fatalf("%q: %v", ocr, err)
		}
	}
	witness.MessageActor.ID = "22222222-2222-4222-8222-222222222222"
	if err := verifyAssistanceCapabilityWitness(scenario, witness); err == nil {
		t.Fatal("different authenticated actor qualified sender identity")
	}
	witness.MessageActor.ID = scenario.OperatorID
	witness.MessageScreenshot = "operator-console.png"
	if err := verifyAssistanceCapabilityWitness(scenario, witness); err == nil {
		t.Fatal("unbound console screenshot qualified guest visibility")
	}
}

func TestAssistanceBaselineCannotQualifyCapability(t *testing.T) {
	for _, name := range []string{"clipboard", "clipboard-limited", "clipboard-policy", "clipboard-permission", "keyboard", "display", "message", "monitors"} {
		t.Run(name, func(t *testing.T) {
			result := &VMAssistanceResult{Scenarios: []*assistanceScenarioEvidence{{Name: name, CaptureStopped: true, NonceReceived: true}}}
			if err := verifyAssistanceEvidence(t.TempDir(), result); err == nil {
				t.Fatal("baseline consent, media and typed nonce qualified an unobserved capability")
			}
		})
	}
}

func TestAssistanceWitnessRejectsXWaylandAndWrongUser(t *testing.T) {
	local := &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}
	for _, guest := range []assistanceFixtureState{
		{Backend: "GdkX11Display", Display: ":0", SessionType: "wayland", SessionID: "7", UID: 1000, PID: 123},
		{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "7", UID: 1001, PID: 123},
		{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "8", UID: 1000, PID: 123},
	} {
		if err := verifyAssistanceFixtureIdentity(&guest, local); err == nil {
			t.Fatalf("accepted wrong native identity: %+v", guest)
		}
	}
}

func TestAssistanceKeyboardRequiresCanonicalNativeUnicodeEffects(t *testing.T) {
	scenario := &assistanceScenarioEvidence{Name: "keyboard", SessionID: "session", LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}}
	makeWitness := func() *assistanceCapabilityWitness {
		t.Helper()
		guest := &assistanceFixtureState{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "7", UID: 1000, PID: 123, Closed: []int{0}}
		if err := json.Unmarshal([]byte(`{"keys":[{"symbol":"y"},{"symbol":"z"},{"symbol":"z"},{"symbol":"y"},{"symbol":"z"},{"symbol":"EuroSign","unicode":8364,"layout_z":"y"},{"symbol":"Cyrillic_ya","unicode":1103,"layout_z":"Cyrillic_ya"}]}`), guest); err != nil {
			t.Fatal(err)
		}
		return &assistanceCapabilityWitness{Capability: "keyboard", SessionID: "session", Checks: []string{"native-keys"}, Guest: guest, Commands: []assistanceCommandWitness{{RequestID: "11111111-1111-4111-8111-111111111111", Kind: "ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS", Status: "ASSISTANCE_COMMAND_STATUS_SUCCEEDED"}}}
	}
	if err := verifyAssistanceCapabilityWitness(scenario, makeWitness()); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*assistanceFixtureState){
		"missing Cyrillic":        func(g *assistanceFixtureState) { g.Keys = g.Keys[:6] },
		"noncanonical Euro":       func(g *assistanceFixtureState) { g.Keys[5].Symbol = "U20AC" },
		"wrong character":         func(g *assistanceFixtureState) { g.Keys[6].Unicode = 0 },
		"no native layout change": func(g *assistanceFixtureState) { g.Keys[6].LayoutZ = "y" },
	} {
		t.Run(name, func(t *testing.T) {
			witness := makeWitness()
			alter(witness.Guest)
			if err := verifyAssistanceCapabilityWitness(scenario, witness); err == nil {
				t.Fatal("unobserved canonical Unicode delivery qualified keyboard")
			}
		})
	}
}
