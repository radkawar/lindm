// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"strings"
	"testing"
	"time"
)

func TestParseInputAccepts(t *testing.T) {
	for message, want := range map[string]InputEvent{
		`{"t":"move","x":0,"y":1,"display":"monitor-1","generation":1}`:                 {kind: inputMove, X: 0, Y: 1, Display: "monitor-1", Generation: 1},
		`{"t":"move","x":0.5,"y":0.25,"display":"monitor-1","generation":1}`:            {kind: inputMove, X: 0.5, Y: 0.25, Display: "monitor-1", Generation: 1},
		`{"t":"button","b":"left","down":true,"display":"monitor-1","generation":1}`:    {kind: inputButton, Button: btnLeft, Down: true, Display: "monitor-1", Generation: 1},
		`{"t":"button","b":"middle","down":false,"display":"monitor-1","generation":1}`: {kind: inputButton, Button: btnMiddle, Display: "monitor-1", Generation: 1},
		`{"t":"button","b":"right","down":true,"display":"monitor-1","generation":1}`:   {kind: inputButton, Button: btnRight, Down: true, Display: "monitor-1", Generation: 1},
		`{"t":"wheel","dx":-10,"dy":10,"display":"monitor-1","generation":1}`:           {kind: inputWheel, DX: -10, DY: 10, Display: "monitor-1", Generation: 1},
		`{"t":"wheel","dx":0,"dy":1.0,"display":"monitor-1","generation":1}`:            {kind: inputWheel, DY: 1, Display: "monitor-1", Generation: 1},
		`{"t":"keysym","keysym":121,"down":true,"display":"monitor-1","generation":1}`:  {kind: inputKeysym, Keysym: 121, Down: true, Display: "monitor-1", Generation: 1},
		`{"t":"release"}`: {kind: inputRelease},
		`{"t":"key","code":"KeyA","down":true,"display":"monitor-1","generation":1}`:        {kind: inputKey, Keycode: 30, Down: true, Display: "monitor-1", Generation: 1},
		`{"t":"key","code":"Enter","down":false,"display":"monitor-1","generation":1}`:      {kind: inputKey, Keycode: 28, Display: "monitor-1", Generation: 1},
		`{"t":"key","code":"MetaLeft","down":true,"display":"monitor-1","generation":1}`:    {kind: inputKey, Keycode: 125, Down: true, Display: "monitor-1", Generation: 1},
		`{"t":"key","code":"ArrowDown","down":true,"display":"monitor-1","generation":1}`:   {kind: inputKey, Keycode: 108, Down: true, Display: "monitor-1", Generation: 1},
		`{"t":"key","code":"NumpadEnter","down":true,"display":"monitor-1","generation":1}`: {kind: inputKey, Keycode: 96, Down: true, Display: "monitor-1", Generation: 1},
		`{"t":"key","code":"F24","down":true,"display":"monitor-1","generation":1}`:         {kind: inputKey, Keycode: 194, Down: true, Display: "monitor-1", Generation: 1},
	} {
		got, err := parseInput([]byte(message))
		if err != nil {
			t.Errorf("parseInput(%s) = %v", message, err)
			continue
		}
		if got != want {
			t.Errorf("parseInput(%s) = %+v, want %+v", message, got, want)
		}
	}
}

func TestParseInputRejects(t *testing.T) {
	for _, message := range []string{
		``,
		`{}`,
		`null`,
		`[]`,
		`{"t":"move","x":1.01,"y":0}`,
		`{"t":"move","x":-0.1,"y":0}`,
		`{"t":"move","x":0.5}`,
		`{"t":"move","x":0.5,"y":0.5,"down":true}`,
		`{"t":"move","x":"0.5","y":0.5}`,
		`{"t":"button","b":"back","down":true}`,
		`{"t":"button","b":"left"}`,
		`{"t":"wheel","dx":11,"dy":0}`,
		`{"t":"wheel","dx":0.5,"dy":0}`,
		`{"t":"wheel","dy":1}`,
		`{"t":"key","code":"Power","down":true,"display":"monitor-1","generation":1}`,
		`{"t":"key","code":"Sleep","down":true,"display":"monitor-1","generation":1}`,
		`{"t":"key","code":"KeyA","display":"monitor-1","generation":1}`,
		`{"t":"key","code":"KeyA","down":true,"extra":1,"display":"monitor-1","generation":1}`,
		`{"t":"key","code":"KeyA","down":true,"display":"monitor-1","generation":1}{"t":"key","code":"KeyB","down":true,"display":"monitor-1","generation":1}`,
		`{"t":"type","text":"rm -rf"}`,
		`{"t":"key","code":"` + strings.Repeat("A", 300) + `","down":true}`,
		`{"t":"move","x":0,"y":0}`,
		`{"t":"move","x":0,"y":0,"display":"monitor-1","generation":0}`,
		`{"t":"keysym","keysym":65293,"down":true,"display":"monitor-1","generation":1}`,
		`{"t":"keysym","keysym":65307,"down":true,"display":"monitor-1","generation":1}`,
		`{"t":"keysym","keysym":65535,"down":true,"display":"monitor-1","generation":1}`,
		`{"t":"keysym","keysym":9,"down":true,"display":"monitor-1","generation":1}`,
		`{"t":"keysym","keysym":16777337,"down":true,"display":"monitor-1","generation":1}`,
		`{"t":"keysym","down":true,"display":"monitor-1","generation":1}`,
		`{"t":"key","keysym":121,"code":"KeyY","down":true,"display":"monitor-1","generation":1}`,
		`{"t":"key","code":"KeyA","down":true}`,
		`{"t":"keysym","keysym":121,"down":true}`,
		`{"t":"key","code":"KeyA","down":true,"display":"monitor-1","generation":0}`,
		`{"t":"keysym","keysym":121,"down":true,"display":"","generation":1}`,
		`{"t":"release","display":"monitor-1","generation":1}`,
		`{"t":"release","down":true}`,
	} {
		if event, err := parseInput([]byte(message)); err == nil {
			t.Errorf("parseInput(%q) accepted %+v", message, event)
		}
	}
}

func TestKeycodeTableMatchesEvdev(t *testing.T) {
	// Spot checks against linux/input-event-codes.h across every block.
	for code, want := range map[string]int32{
		"Escape": 1, "Digit0": 11, "Backspace": 14, "KeyQ": 16, "KeyP": 25, "ControlLeft": 29,
		"KeyL": 38, "Backquote": 41, "ShiftLeft": 42, "KeyM": 50, "Slash": 53, "AltLeft": 56,
		"Space": 57, "F10": 68, "Numpad0": 82, "IntlBackslash": 86, "F11": 87, "F12": 88,
		"ControlRight": 97, "PrintScreen": 99, "AltRight": 100, "Home": 102, "Delete": 111,
		"Pause": 119, "MetaRight": 126, "ContextMenu": 127, "F13": 183,
	} {
		if got, ok := evdevKeycodes[code]; !ok || got != want {
			t.Errorf("%s = %d (%t), want %d", code, got, ok, want)
		}
	}
	for code, keycode := range evdevKeycodes {
		if keycode <= 0 || keycode == 116 || keycode == 142 || keycode == 143 || keycode == 161 {
			t.Errorf("%s maps to forbidden keycode %d", code, keycode)
		}
	}
}

func TestInputLimiter(t *testing.T) {
	start := time.Unix(1000, 0)
	limiter := newInputLimiter(start)
	allowed := 0
	for range 1000 {
		if limiter.allow(start) {
			allowed++
		}
	}
	if allowed != maxInputPerSecond {
		t.Fatalf("burst allowed %d, want %d", allowed, maxInputPerSecond)
	}
	if limiter.allow(start.Add(time.Millisecond)) {
		t.Fatal("refilled faster than 240/s")
	}
	if !limiter.allow(start.Add(5 * time.Millisecond)) {
		t.Fatal("no refill after 5 ms")
	}
	// Sustained 1000/s over 10 s admits at most 240/s plus the burst.
	limiter = newInputLimiter(start)
	allowed = 0
	for i := range 10000 {
		if limiter.allow(start.Add(time.Duration(i) * time.Millisecond)) {
			allowed++
		}
	}
	if allowed > 10*maxInputPerSecond+maxInputPerSecond {
		t.Fatalf("sustained allowed %d", allowed)
	}
}

func TestPressedInputReleasesHeld(t *testing.T) {
	pressed := newPressedInput()
	pressed.observe(InputEvent{kind: inputKey, Keycode: 29, Down: true})
	pressed.observe(InputEvent{kind: inputKey, Keycode: 30, Down: true})
	pressed.observe(InputEvent{kind: inputKey, Keycode: 30})
	pressed.observe(InputEvent{kind: inputButton, Button: btnRight, Down: true})
	pressed.observe(InputEvent{kind: inputMove, X: 1, Y: 1})
	releases := pressed.releases()
	if len(releases) != 2 {
		t.Fatalf("releases = %+v", releases)
	}
	if releases[0] != (InputEvent{kind: inputKey, Keycode: 29}) || releases[1] != (InputEvent{kind: inputButton, Button: btnRight}) {
		t.Fatalf("releases = %+v", releases)
	}
	if again := pressed.releases(); len(again) != 0 {
		t.Fatalf("second release = %+v", again)
	}
}
