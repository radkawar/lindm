//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"time"
)

// assistanceScreen is the lab's view of the guest's local seat: QMP
// screendumps compared with a clean reference, and QMP pointer input for the
// local user's consent and stop controls. Every capture it reports is saved
// as bound evidence by the caller.
type assistanceScreen struct {
	vm        *guestVM
	evidence  *assistanceEvidence
	result    *VMAssistanceResult
	reference *image.RGBA
}

// screenPollInterval paces screendumps; each is a full-frame QMP capture.
const screenPollInterval = 500 * time.Millisecond

// parkPoint keeps the guest pointer out of the banner and dialog areas the
// locators compare, and off hover-sensitive banners.
func parkPoint(display image.Rectangle) image.Point {
	return image.Pt(display.Min.X+display.Dx()/2, display.Max.Y-30)
}

func (s *assistanceScreen) save(name string, img *image.RGBA) (string, error) {
	var encoded bytes.Buffer
	if err := encodeScreendumpPNG(&encoded, img); err != nil {
		return "", err
	}
	bound, err := s.evidence.write("guest "+name, "guest-"+name+".png", encoded.Bytes())
	if err != nil {
		return "", err
	}
	s.result.Screenshots = append(s.result.Screenshots, bound)
	return bound.Path, nil
}

// captureReference records the clean desktop the banner locator compares
// against. Two captures six seconds apart must agree in the banner area, so a
// transient login notification (GNOME hides normal banners ~5 s after local
// activity; each round nudges the parked pointer) is never mistaken for the
// clean desktop.
func (s *assistanceScreen) captureReference(ctx context.Context) (string, error) {
	first, err := s.vm.screendump(ctx)
	if err != nil {
		return "", err
	}
	for round := range 10 {
		park := parkPoint(first.Bounds()).Add(image.Pt(round%2, 0))
		if err := s.vm.pointerMove(ctx, first.Bounds(), park); err != nil {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(6 * time.Second):
		}
		second, err := s.vm.screendump(ctx)
		if err != nil {
			return "", err
		}
		display := second.Bounds()
		centre := display.Min.X + display.Dx()/2
		if _, count := screenDiffBounds(first, second, image.Rect(centre-420, display.Min.Y+gnomeTopBarHeight, centre+420, display.Min.Y+360), screenDiffThreshold); count < 200 {
			s.reference = second
			return s.save("desktop-reference", second)
		}
		first = second
	}
	return "", errors.New("guest desktop never settled for a clean reference capture")
}

// waitBanner waits for a notification banner whose bounds are identical in
// two consecutive captures, i.e. its slide-in animation has finished.
func (s *assistanceScreen) waitBanner(ctx context.Context, timeout time.Duration) (*image.RGBA, image.Rectangle, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var previous image.Rectangle
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return nil, image.Rectangle{}, err
		}
		banner, found := locateNotificationBanner(s.reference, img)
		if found && banner == previous {
			return img, banner, nil
		}
		previous = banner
		select {
		case <-ctx.Done():
			return img, image.Rectangle{}, fmt.Errorf("guest notification banner did not appear: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// waitNoBanner waits until the banner area matches the clean reference again.
// GNOME keeps an expired normal banner on screen while the seat is idle, so
// each poll nudges the parked pointer by one pixel as local user activity.
// This also re-parks a pointer the operator moved through remote control.
func (s *assistanceScreen) waitNoBanner(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for poll := 0; ; poll++ {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return err
		}
		if _, found := locateNotificationBanner(s.reference, img); !found {
			return nil
		}
		park := parkPoint(img.Bounds()).Add(image.Pt(poll%2, 0))
		if err := s.vm.pointerMove(ctx, img.Bounds(), park); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			if _, saveErr := s.save(fmt.Sprintf("stale-banner-%d", time.Now().Unix()), img); saveErr != nil {
				return errors.Join(saveErr, ctx.Err())
			}
			return fmt.Errorf("a guest notification banner stayed visible: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// waitDialog waits for the portal share dialog with stable bounds.
func (s *assistanceScreen) waitDialog(ctx context.Context, timeout time.Duration) (*image.RGBA, image.Rectangle, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var previous image.Rectangle
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return nil, image.Rectangle{}, err
		}
		dialog, found := locatePortalDialog(img)
		if found && dialog == previous {
			return img, dialog, nil
		}
		previous = dialog
		select {
		case <-ctx.Done():
			return img, image.Rectangle{}, fmt.Errorf("portal share dialog did not appear: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// waitSwitchOn confirms the RemoteDesktop dialog's interaction switch shows
// the accent colour after it was clicked.
func (s *assistanceScreen) waitSwitchOn(ctx context.Context, dialog image.Rectangle, timeout time.Duration) (*image.RGBA, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return nil, err
		}
		if portalSwitchOn(img, dialog) {
			return img, nil
		}
		select {
		case <-ctx.Done():
			return img, fmt.Errorf("portal remote interaction switch did not turn on: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// waitCentreWindow waits for a window covering the display centre.
func (s *assistanceScreen) waitCentreWindow(ctx context.Context, timeout time.Duration) (*image.RGBA, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return nil, err
		}
		if centreChanged(s.reference, img) {
			return img, nil
		}
		select {
		case <-ctx.Done():
			return img, fmt.Errorf("guest window did not appear: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// click performs one local-seat click, records it, and parks the pointer.
func (s *assistanceScreen) click(ctx context.Context, display image.Rectangle, point image.Point, target string, scenario *assistanceScenarioEvidence) error {
	if err := s.vm.pointerClick(ctx, display, point, "left"); err != nil {
		return fmt.Errorf("click %s: %w", target, err)
	}
	scenario.Clicks = append(scenario.Clicks, assistanceClickEvidence{Target: target, X: point.X, Y: point.Y})
	return s.vm.pointerMove(ctx, display, parkPoint(display))
}
