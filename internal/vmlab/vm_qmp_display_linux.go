//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"image"
	"io"
	"os"
	"time"
)

// qmpAbsoluteMax is QEMU's INPUT_EVENT_ABS_MAX; the desktop lane's usb-tablet
// maps 0..qmpAbsoluteMax onto the full guest display.
const qmpAbsoluteMax = 0x7fff

// screendump captures QEMU's current display surface through QMP. It observes
// pixels only; it never injects input and never reads guest memory.
func (v *guestVM) screendump(ctx context.Context) (_ *image.RGBA, err error) {
	if !v.hardware.Desktop {
		return nil, errors.New("screendump requires the lab desktop display")
	}
	file, err := os.CreateTemp(v.dir, "screendump-*.ppm")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	defer func() { err = errors.Join(err, os.Remove(path)) }()
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := v.qmpCommand(ctx, map[string]any{"execute": "screendump", "arguments": map[string]any{"filename": path}, "id": "screendump"}); err != nil {
		return nil, fmt.Errorf("capture guest display: %w", err)
	}
	file, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return decodeScreendumpPPM(io.LimitReader(file, maxScreendumpPixels*3+64))
}

// pointerClick moves the guest's absolute pointer to a display pixel and
// clicks. This is local-seat input from the lab, never the product's remote
// input path, and is used only for local-user consent and stop controls.
func (v *guestVM) pointerClick(ctx context.Context, display image.Rectangle, point image.Point, button string) error {
	if err := v.pointerMove(ctx, display, point); err != nil {
		return err
	}
	for _, down := range []bool{true, false} {
		if err := v.qmpCommand(ctx, map[string]any{"execute": "input-send-event", "id": "button", "arguments": map[string]any{"events": []map[string]any{
			{"type": "btn", "data": map[string]any{"down": down, "button": button}},
		}}}); err != nil {
			return fmt.Errorf("guest pointer button: %w", err)
		}
		// GNOME Shell distinguishes press and release events by arrival; a
		// short bounded gap mirrors a physical click without polling state.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(60 * time.Millisecond):
		}
	}
	return nil
}

// pointerMove positions the absolute pointer, e.g. to park it outside the
// regions the locators compare.
func (v *guestVM) pointerMove(ctx context.Context, display image.Rectangle, point image.Point) error {
	if display.Dx() < 2 || display.Dy() < 2 || !point.In(display) {
		return errors.New("guest pointer target is outside the display")
	}
	x := (point.X - display.Min.X) * qmpAbsoluteMax / (display.Dx() - 1)
	y := (point.Y - display.Min.Y) * qmpAbsoluteMax / (display.Dy() - 1)
	if err := v.qmpCommand(ctx, map[string]any{"execute": "input-send-event", "id": "move", "arguments": map[string]any{"events": []map[string]any{
		{"type": "abs", "data": map[string]any{"axis": "x", "value": x}},
		{"type": "abs", "data": map[string]any{"axis": "y", "value": y}},
	}}}); err != nil {
		return fmt.Errorf("guest pointer motion: %w", err)
	}
	return nil
}

// sendKey presses and releases one QEMU key code on the guest's local seat.
func (v *guestVM) sendKey(ctx context.Context, qcode string) error {
	if err := v.qmpCommand(ctx, map[string]any{"execute": "send-key", "id": "key", "arguments": map[string]any{"keys": []map[string]any{{"type": "qcode", "data": qcode}}}}); err != nil {
		return fmt.Errorf("guest key %s: %w", qcode, err)
	}
	return nil
}
