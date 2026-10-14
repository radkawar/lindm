// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"sync"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// inputControl serializes native input and pauses it across monitor changes.
// All presses carry a source fence; release remains safe across generations.
type inputControl struct {
	mu         sync.Mutex
	grant      Grant
	keyboard   agentv1.AssistancePolicyMode
	pressed    *pressedInput
	display    string
	generation uint32
	paused     bool
}

func newInputControl(grant Grant, keyboard agentv1.AssistancePolicyMode, display string) *inputControl {
	return &inputControl{grant: grant, keyboard: keyboard, pressed: newPressedInput(), display: display, generation: 1}
}

func (c *inputControl) inject(ctx context.Context, event InputEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.paused {
		return errInvalidInput
	}
	if event.kind != inputRelease && (event.Display != c.display || event.Generation != c.generation) {
		return errInvalidInput
	}
	switch event.kind {
	case inputRelease:
		return c.release(ctx)
	case inputKey:
		_, held := c.pressed.keys[event.Keycode]
		if c.keyboard != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON && (event.Down || !held) {
			return errInvalidInput
		}
	case inputKeysym:
		_, held := c.pressed.symbols[event.Keysym]
		if !printableKeysym(event.Keysym) || (!policyEnabled(c.keyboard) && (event.Down || !held)) {
			return errInvalidInput
		}
		if event.Down && !held && len(c.pressed.symbols) >= 32 {
			return errInvalidInput
		}
	}
	// Track attempted presses as well: a timed-out portal call may have acted.
	if event.Down {
		c.pressed.observe(event)
	}
	err := c.grant.Inject(ctx, event)
	if err == nil && !event.Down {
		c.pressed.observe(event)
	}
	return err
}

func (c *inputControl) release(ctx context.Context) error {
	var errs []error
	for _, event := range c.pressed.releases() {
		errs = append(errs, c.grant.Inject(ctx, event))
	}
	return errors.Join(errs...)
}

func (c *inputControl) releaseAll(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.release(ctx)
}

// beginSwitch detaches held inputs and returns the new generation under a short
// lock (zero means unchanged). Native releases, teardown and startup happen
// outside it so the data-channel pump keeps draining.
func (c *inputControl) beginSwitch(display string) ([]InputEvent, uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		return nil, 0, errors.New("display_switch_in_progress")
	}
	if display == c.display {
		return nil, 0, nil
	}
	if c.generation == ^uint32(0) {
		return nil, 0, errors.New("display_generation_exhausted")
	}
	c.paused = true
	c.display, c.generation = display, c.generation+1
	return c.pressed.releases(), c.generation, nil
}

func specialKeyCodes(key agentv1.AssistanceSpecialKey) []int32 {
	switch key {
	case agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_SWITCH_WINDOW:
		return []int32{56, 15}
	case agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_SHOW_APPLICATIONS:
		return []int32{125}
	case agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_OPEN_TERMINAL:
		return []int32{29, 56, 20}
	case agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_CLOSE_WINDOW:
		return []int32{56, 62}
	default:
		return nil
	}
}

func (c *inputControl) special(ctx context.Context, key agentv1.AssistanceSpecialKey) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		return errInvalidInput
	}
	if c.keyboard != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		return errors.New("special_keys_not_granted")
	}
	codes := specialKeyCodes(key)
	if len(codes) == 0 {
		return errors.New("special_key_unsupported")
	}
	if err := c.release(ctx); err != nil {
		return err
	}
	pressed := 0
	defer func() {
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		for i := pressed - 1; i >= 0; i-- {
			err = errors.Join(err, c.grant.Inject(release, InputEvent{kind: inputKey, Keycode: codes[i]}))
		}
	}()
	for _, code := range codes {
		if err := ctx.Err(); err != nil {
			return err
		}
		pressed++
		if err := c.grant.Inject(ctx, InputEvent{kind: inputKey, Keycode: code, Down: true}); err != nil {
			return err
		}
	}
	return nil
}
