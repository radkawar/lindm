package desktop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// Input data-channel limits from the assistance contract.
const (
	maxInputMessageBytes = 256
	maxInputPerSecond    = 240
	maxWheelSteps        = 10
)

// Linux evdev button codes (linux/input-event-codes.h).
const (
	btnLeft   int32 = 0x110
	btnRight  int32 = 0x111
	btnMiddle int32 = 0x112
)

// Portal axis identifiers for NotifyPointerAxisDiscrete.
const (
	axisVertical   uint32 = 0
	axisHorizontal uint32 = 1
)

type inputKind uint8

const (
	inputMove inputKind = iota + 1
	inputButton
	inputWheel
	inputKey
)

// InputEvent is one validated operator input already mapped to portal
// arguments. X and Y are normalized [0,1] coordinates; Button and Keycode are
// evdev codes; DX and DY are discrete wheel steps (positive is right/down).
type InputEvent struct {
	kind    inputKind
	X, Y    float64
	Button  int32
	Keycode int32
	DX, DY  int32
	Down    bool
}

var errInvalidInput = errors.New("invalid_input")

type inputWire struct {
	T    string   `json:"t"`
	X    *float64 `json:"x"`
	Y    *float64 `json:"y"`
	B    *string  `json:"b"`
	Down *bool    `json:"down"`
	DX   *float64 `json:"dx"`
	DY   *float64 `json:"dy"`
	Code *string  `json:"code"`
}

// parseInput validates one data-channel message. Messages are single JSON
// objects of at most 256 bytes with exactly the fields of their type:
//
//	{"t":"move","x":0..1,"y":0..1}
//	{"t":"button","b":"left|middle|right","down":bool}
//	{"t":"wheel","dx":-10..10,"dy":-10..10}   (integral steps, positive right/down)
//	{"t":"key","code":"<KeyboardEvent.code>","down":bool}
func parseInput(message []byte) (InputEvent, error) {
	if len(message) == 0 || len(message) > maxInputMessageBytes {
		return InputEvent{}, fmt.Errorf("%w: size", errInvalidInput)
	}
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	var wire inputWire
	if err := decoder.Decode(&wire); err != nil {
		return InputEvent{}, fmt.Errorf("%w: decode: %w", errInvalidInput, err)
	}
	if decoder.More() {
		return InputEvent{}, fmt.Errorf("%w: trailing data", errInvalidInput)
	}
	present := func(fields ...bool) bool {
		for _, field := range fields {
			if !field {
				return false
			}
		}
		return true
	}
	x, y, b, down, dx, dy, code := wire.X != nil, wire.Y != nil, wire.B != nil, wire.Down != nil, wire.DX != nil, wire.DY != nil, wire.Code != nil
	switch wire.T {
	case "move":
		if !present(x, y) || b || down || dx || dy || code {
			return InputEvent{}, fmt.Errorf("%w: move fields", errInvalidInput)
		}
		if !unit(*wire.X) || !unit(*wire.Y) {
			return InputEvent{}, fmt.Errorf("%w: move range", errInvalidInput)
		}
		return InputEvent{kind: inputMove, X: *wire.X, Y: *wire.Y}, nil
	case "button":
		if !present(b, down) || x || y || dx || dy || code {
			return InputEvent{}, fmt.Errorf("%w: button fields", errInvalidInput)
		}
		var button int32
		switch *wire.B {
		case "left":
			button = btnLeft
		case "middle":
			button = btnMiddle
		case "right":
			button = btnRight
		default:
			return InputEvent{}, fmt.Errorf("%w: button name", errInvalidInput)
		}
		return InputEvent{kind: inputButton, Button: button, Down: *wire.Down}, nil
	case "wheel":
		if !present(dx, dy) || x || y || b || down || code {
			return InputEvent{}, fmt.Errorf("%w: wheel fields", errInvalidInput)
		}
		stepsX, okX := wheelSteps(*wire.DX)
		stepsY, okY := wheelSteps(*wire.DY)
		if !okX || !okY {
			return InputEvent{}, fmt.Errorf("%w: wheel range", errInvalidInput)
		}
		return InputEvent{kind: inputWheel, DX: stepsX, DY: stepsY}, nil
	case "key":
		if !present(code, down) || x || y || b || dx || dy {
			return InputEvent{}, fmt.Errorf("%w: key fields", errInvalidInput)
		}
		keycode, ok := evdevKeycodes[*wire.Code]
		if !ok {
			return InputEvent{}, fmt.Errorf("%w: unmapped key", errInvalidInput)
		}
		return InputEvent{kind: inputKey, Keycode: keycode, Down: *wire.Down}, nil
	default:
		return InputEvent{}, fmt.Errorf("%w: type", errInvalidInput)
	}
}

func unit(value float64) bool {
	return !math.IsNaN(value) && value >= 0 && value <= 1
}

func wheelSteps(value float64) (int32, bool) {
	if math.IsNaN(value) || value < -maxWheelSteps || value > maxWheelSteps || math.Trunc(value) != value {
		return 0, false
	}
	return int32(value), true
}

// inputLimiter is a token bucket admitting at most maxInputPerSecond
// messages per second with a one-second burst; excess messages are dropped.
type inputLimiter struct {
	tokens float64
	last   time.Time
}

func newInputLimiter(now time.Time) *inputLimiter {
	return &inputLimiter{tokens: maxInputPerSecond, last: now}
}

func (l *inputLimiter) allow(now time.Time) bool {
	if elapsed := now.Sub(l.last); elapsed > 0 {
		l.tokens = math.Min(maxInputPerSecond, l.tokens+elapsed.Seconds()*maxInputPerSecond)
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// pressedInput tracks keys and buttons the operator holds so that every one
// of them is released when the session ends.
type pressedInput struct {
	buttons map[int32]struct{}
	keys    map[int32]struct{}
}

func newPressedInput() *pressedInput {
	return &pressedInput{buttons: map[int32]struct{}{}, keys: map[int32]struct{}{}}
}

func (p *pressedInput) observe(event InputEvent) {
	var set map[int32]struct{}
	var code int32
	switch event.kind {
	case inputButton:
		set, code = p.buttons, event.Button
	case inputKey:
		set, code = p.keys, event.Keycode
	default:
		return
	}
	if event.Down {
		set[code] = struct{}{}
	} else {
		delete(set, code)
	}
}

// releases returns release events for everything still held, keys first.
func (p *pressedInput) releases() []InputEvent {
	events := make([]InputEvent, 0, len(p.keys)+len(p.buttons))
	for code := range p.keys {
		events = append(events, InputEvent{kind: inputKey, Keycode: code})
	}
	for code := range p.buttons {
		events = append(events, InputEvent{kind: inputButton, Button: code})
	}
	clear(p.keys)
	clear(p.buttons)
	return events
}

// evdevKeycodes maps W3C UI Events KeyboardEvent.code values to Linux evdev
// keycodes (linux/input-event-codes.h). Codes absent here are dropped. Power,
// sleep, wake and eject keys are intentionally not mapped.
var evdevKeycodes = map[string]int32{
	"Escape":             1,
	"Digit1":             2,
	"Digit2":             3,
	"Digit3":             4,
	"Digit4":             5,
	"Digit5":             6,
	"Digit6":             7,
	"Digit7":             8,
	"Digit8":             9,
	"Digit9":             10,
	"Digit0":             11,
	"Minus":              12,
	"Equal":              13,
	"Backspace":          14,
	"Tab":                15,
	"KeyQ":               16,
	"KeyW":               17,
	"KeyE":               18,
	"KeyR":               19,
	"KeyT":               20,
	"KeyY":               21,
	"KeyU":               22,
	"KeyI":               23,
	"KeyO":               24,
	"KeyP":               25,
	"BracketLeft":        26,
	"BracketRight":       27,
	"Enter":              28,
	"ControlLeft":        29,
	"KeyA":               30,
	"KeyS":               31,
	"KeyD":               32,
	"KeyF":               33,
	"KeyG":               34,
	"KeyH":               35,
	"KeyJ":               36,
	"KeyK":               37,
	"KeyL":               38,
	"Semicolon":          39,
	"Quote":              40,
	"Backquote":          41,
	"ShiftLeft":          42,
	"Backslash":          43,
	"KeyZ":               44,
	"KeyX":               45,
	"KeyC":               46,
	"KeyV":               47,
	"KeyB":               48,
	"KeyN":               49,
	"KeyM":               50,
	"Comma":              51,
	"Period":             52,
	"Slash":              53,
	"ShiftRight":         54,
	"NumpadMultiply":     55,
	"AltLeft":            56,
	"Space":              57,
	"CapsLock":           58,
	"F1":                 59,
	"F2":                 60,
	"F3":                 61,
	"F4":                 62,
	"F5":                 63,
	"F6":                 64,
	"F7":                 65,
	"F8":                 66,
	"F9":                 67,
	"F10":                68,
	"NumLock":            69,
	"ScrollLock":         70,
	"Numpad7":            71,
	"Numpad8":            72,
	"Numpad9":            73,
	"NumpadSubtract":     74,
	"Numpad4":            75,
	"Numpad5":            76,
	"Numpad6":            77,
	"NumpadAdd":          78,
	"Numpad1":            79,
	"Numpad2":            80,
	"Numpad3":            81,
	"Numpad0":            82,
	"NumpadDecimal":      83,
	"Lang5":              85,
	"IntlBackslash":      86,
	"F11":                87,
	"F12":                88,
	"IntlRo":             89,
	"Lang3":              90,
	"Lang4":              91,
	"Convert":            92,
	"KanaMode":           93,
	"NonConvert":         94,
	"NumpadEnter":        96,
	"ControlRight":       97,
	"NumpadDivide":       98,
	"PrintScreen":        99,
	"AltRight":           100,
	"Home":               102,
	"ArrowUp":            103,
	"PageUp":             104,
	"ArrowLeft":          105,
	"ArrowRight":         106,
	"End":                107,
	"ArrowDown":          108,
	"PageDown":           109,
	"Insert":             110,
	"Delete":             111,
	"AudioVolumeMute":    113,
	"AudioVolumeDown":    114,
	"AudioVolumeUp":      115,
	"NumpadEqual":        117,
	"Pause":              119,
	"NumpadComma":        121,
	"Lang1":              122,
	"Lang2":              123,
	"IntlYen":            124,
	"MetaLeft":           125,
	"OSLeft":             125,
	"MetaRight":          126,
	"OSRight":            126,
	"ContextMenu":        127,
	"MediaTrackNext":     163,
	"MediaPlayPause":     164,
	"MediaTrackPrevious": 165,
	"MediaStop":          166,
	"F13":                183,
	"F14":                184,
	"F15":                185,
	"F16":                186,
	"F17":                187,
	"F18":                188,
	"F19":                189,
	"F20":                190,
	"F21":                191,
	"F22":                192,
	"F23":                193,
	"F24":                194,
}
