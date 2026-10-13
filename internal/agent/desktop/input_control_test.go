package desktop

import (
	"context"
	"errors"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestLimitedKeyboardRejectsPhysicalAndNonPrintableKeysyms(t *testing.T) {
	grant := &fakeGrant{control: true}
	input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, "monitor-1")
	if err := input.inject(t.Context(), InputEvent{kind: inputKey, Keycode: 29, Down: true, Display: "monitor-1", Generation: 1}); err == nil {
		t.Fatal("LIMITED admitted physical Control")
	}
	for _, symbol := range []int32{0xff1b, 0xffff, 0xff0d, 0xffbe, 0xffe1, 0xfe50, 0xff80, 0xffb1, 0x1008ff12, 0x7f, 0x9f, 0xa0, 0x01000061, 0x0100d800, 0x01110000, -1} {
		if printableKeysym(symbol) {
			t.Fatalf("admitted noncanonical/nonprintable keysym %#x", symbol)
		}
		if err := input.inject(t.Context(), InputEvent{kind: inputKeysym, Keysym: symbol, Down: true, Display: "monitor-1", Generation: 1}); err == nil {
			t.Fatalf("LIMITED injected forbidden keysym %#x", symbol)
		}
	}
	for _, symbol := range []int32{0x20, 0x7e, 0xff, 0x01000100, 0x010065e5, 0x0101f642} {
		if !printableKeysym(symbol) {
			t.Fatalf("rejected printable keysym %#x", symbol)
		}
	}
	semantic, err := parseInput([]byte(`{"t":"keysym","keysym":121,"down":true,"display":"monitor-1","generation":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := input.inject(t.Context(), semantic); err != nil {
		t.Fatal(err)
	}
	if err := input.inject(t.Context(), InputEvent{kind: inputRelease}); err != nil {
		t.Fatal(err)
	}
	events, _ := grant.snapshot()
	if len(events) != 2 || events[0].kind != inputKeysym || events[0].Keysym != 'y' || events[0].Keycode != 0 || events[1].Down {
		t.Fatalf("semantic y confused with physical Y: %+v", events)
	}
	// Physical KeyY is evdev 21 regardless of semantic y/z on the layout.
	physical, err := parseInput([]byte(`{"t":"key","code":"KeyY","down":true,"display":"monitor-1","generation":1}`))
	if err != nil || physical.Keycode != 21 || physical.Keysym != 0 {
		t.Fatalf("physical mapping = %+v, %v", physical, err)
	}
}

func TestLimitedKeyboardAcceptsCanonicalEncodedUnicodeSymbol(t *testing.T) {
	grant := &fakeGrant{control: true}
	input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, "monitor-1")
	event, err := parseInput([]byte(`{"t":"keysym","keysym":16803301,"down":true,"display":"monitor-1","generation":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := input.inject(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if err := input.releaseAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	events, _ := grant.snapshot()
	if len(events) != 2 || events[0].Keysym != 0x010065e5 || events[1].Keysym != 0x010065e5 || events[1].Down {
		t.Fatalf("encoded symbol state = %+v", events)
	}
}

func TestPointerFenceAndReleaseAreIndependentOfKeyboardPolicy(t *testing.T) {
	grant := &fakeGrant{control: true}
	input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, "monitor-2")
	input.generation = 3
	for _, event := range []InputEvent{
		{kind: inputMove, Display: "monitor-1", Generation: 3},
		{kind: inputButton, Display: "monitor-2", Generation: 2, Button: btnLeft, Down: true},
		{kind: inputWheel, Display: "monitor-2", Generation: 0, DY: 1},
	} {
		if err := input.inject(t.Context(), event); err == nil {
			t.Fatal("stale pointer event accepted")
		}
	}
	if err := input.inject(t.Context(), InputEvent{kind: inputButton, Display: "monitor-2", Generation: 3, Button: btnLeft, Down: true}); err != nil {
		t.Fatal(err)
	}
	if err := input.inject(t.Context(), InputEvent{kind: inputRelease}); err != nil {
		t.Fatal(err)
	}
	events, _ := grant.snapshot()
	if len(events) != 2 || events[1].Down || events[1].Button != btnLeft {
		t.Fatalf("pointer/release with keyboard OFF: %+v", events)
	}
}

type failingInputGrant struct {
	*fakeGrant
	failCode int32
}

func (g *failingInputGrant) Inject(ctx context.Context, event InputEvent) error {
	if err := g.fakeGrant.Inject(ctx, event); err != nil {
		return err
	}
	if event.Down && event.Keycode == g.failCode {
		return errors.New("injected failure after uncertain delivery")
	}
	return nil
}

func TestSpecialChordReleasesEveryAttemptedKeyInReverseOrder(t *testing.T) {
	grant := &failingInputGrant{fakeGrant: &fakeGrant{control: true}, failCode: 20}
	input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, "monitor-1")
	if err := input.special(t.Context(), agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_OPEN_TERMINAL); err == nil {
		t.Fatal("uncertain chord reported success")
	}
	events, _ := grant.snapshot()
	if len(events) != 6 {
		t.Fatalf("events = %+v", events)
	}
	for i, code := range []int32{29, 56, 20, 20, 56, 29} {
		if events[i].Keycode != code || events[i].Down != (i < 3) {
			t.Fatalf("event %d = %+v", i, events[i])
		}
	}
	if specialKeyCodes(agentv1.AssistanceSpecialKey(999)) != nil {
		t.Fatal("unknown special chord accepted")
	}
}

func TestLimitedKeyboardAcceptsGraphicalLegacyXKBWithoutActionAliases(t *testing.T) {
	// Independent canonical examples span the table, not just Euro/Cyrillic.
	for _, symbol := range []int32{0x01a1, 0x03c0, 0x04b1, 0x05c7, 0x06d1, 0x07e1, 0x0ce0, 0x0da1, 0x0ea1, 0x13bc, 0x20ac} {
		grant := &fakeGrant{control: true}
		input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, "monitor-1")
		event := InputEvent{kind: inputKeysym, Keysym: symbol, Down: true, Display: "monitor-1", Generation: 1}
		if err := input.inject(t.Context(), event); err != nil {
			t.Fatalf("graphical legacy %#x rejected: %v", symbol, err)
		}
		if err := input.releaseAll(t.Context()); err != nil {
			t.Fatal(err)
		}
		events, _ := grant.snapshot()
		if len(events) != 2 || events[0].Keysym != symbol || events[1].Keysym != symbol || events[1].Down {
			t.Fatalf("legacy symbol changed or stuck: %+v", events)
		}
	}
	// General-purpose keysym-to-Unicode APIs convert keypad/action symbols too.
	// LIMITED must not admit any of those aliases or any dead/modifier symbol.
	for symbol := int32(0xfe00); symbol <= 0xffff; symbol++ {
		if printableKeysym(symbol) {
			t.Fatalf("non-graphical alias admitted: %#x", symbol)
		}
	}
}

func TestAllKeyboardInputRequiresCurrentDisplayFence(t *testing.T) {
	grant := &fakeGrant{control: true}
	input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, "monitor-2")
	input.generation = 2
	for _, event := range []InputEvent{
		{kind: inputKey, Keycode: 30, Down: true},
		{kind: inputKey, Keycode: 30, Down: true, Display: "monitor-1", Generation: 1},
		{kind: inputKeysym, Keysym: 0x06d1, Down: true, Display: "monitor-1", Generation: 2},
		{kind: inputKeysym, Keysym: 0x20ac, Down: true, Display: "monitor-2", Generation: 1},
	} {
		if err := input.inject(t.Context(), event); !errors.Is(err, errInvalidInput) {
			t.Fatalf("stale keyboard admitted: %+v %v", event, err)
		}
	}
	input.paused = true
	for _, event := range []InputEvent{
		{kind: inputKey, Keycode: 30, Down: true, Display: "monitor-2", Generation: 2},
		{kind: inputKeysym, Keysym: 0x20ac, Down: true, Display: "monitor-2", Generation: 2},
		{kind: inputMove, X: 0.5, Y: 0.5, Display: "monitor-2", Generation: 2},
	} {
		if err := input.inject(t.Context(), event); !errors.Is(err, errInvalidInput) {
			t.Fatalf("paused input admitted: %+v %v", event, err)
		}
	}
	if err := input.special(t.Context(), agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_OPEN_TERMINAL); !errors.Is(err, errInvalidInput) {
		t.Fatal("paused special keys admitted")
	}
	if events, _ := grant.snapshot(); len(events) != 0 {
		t.Fatalf("fenced input reached portal: %+v", events)
	}
}
