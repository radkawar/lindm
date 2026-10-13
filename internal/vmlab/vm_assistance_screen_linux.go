//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// assistanceScreen is the lab's view of the guest's local seat: QMP
// screendumps compared with a clean reference, and QMP pointer input for the
// local user's consent and stop controls. Every capture it reports is saved
// as bound evidence by the caller.
type assistanceScreen struct {
	vm            *guestVM
	evidence      *assistanceEvidence
	result        *VMAssistanceResult
	reference     *image.RGBA
	desktopBounds image.Rectangle
	headOrigin    image.Point
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
func (s *assistanceScreen) captureReference(ctx context.Context, name string) (string, error) {
	first, err := s.vm.screendump(ctx)
	if err != nil {
		return "", err
	}
	for round := range 10 {
		park := parkPoint(first.Bounds()).Add(image.Pt(round%2, 0))
		if err := s.move(ctx, first.Bounds(), park); err != nil {
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
			// A resident lindm banner also holds still; a reference that
			// contains it hides that banner and every later one from the
			// locator (org demo finance-desktop respond, Fedora 44).
			text, err := s.ocr(ctx, second, image.Rect(centre-420, display.Min.Y+gnomeTopBarHeight, centre+420, display.Min.Y+360))
			if err != nil {
				return "", err
			}
			if !strings.Contains(text, "lindm") && !strings.Contains(text, "remote assistance") {
				s.reference = second
				return s.save(name, second)
			}
		}
		first = second
	}
	return "", errors.New("guest desktop never settled for a clean reference capture")
}

// ocr returns tesseract's normalized lowercase text for region of img, read
// in grayscale upscaled three times. Without host tesseract it returns ""
// (callers that require OCR check for tesseract themselves).
func (s *assistanceScreen) ocr(ctx context.Context, img *image.RGBA, region image.Rectangle) (string, error) {
	if _, err := exec.LookPath("tesseract"); err != nil {
		return "", nil
	}
	path, err := s.save(fmt.Sprintf("ocr-%d", time.Now().UnixNano()), upscaleGray(img, region, 3))
	if err != nil {
		return "", err
	}
	// One OpenMP thread: colocated on a busy dgx host, tesseract's default
	// pool overran the one-minute bound (fedora44arm-tier1-19).
	out, err := hostCommand(ctx, s.evidence.dir, "env", nil, "OMP_THREAD_LIMIT=1", "tesseract", filepath.Join(s.evidence.dir, path), "stdout", "--psm", "6")
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(strings.ToLower(string(out))), " "), nil
}

// waitTitledBanner waits for the banner whose OCR'd title contains title,
// letting any other notice (a stale "ended" banner, a cancelled request's
// leftover) expire first. Without host tesseract it falls back to the
// consent prompt's height test for requests.
func (s *assistanceScreen) waitTitledBanner(ctx context.Context, title string, timeout time.Duration) (*image.RGBA, image.Rectangle, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		img, banner, err := s.waitBanner(ctx, timeout)
		if err != nil {
			return img, banner, err
		}
		text, err := s.ocr(ctx, img, banner)
		if err != nil {
			return img, banner, err
		}
		switch {
		case text == "" && (title != "remote assistance request" || banner.Dy() >= consentPromptMinHeight):
			return img, banner, nil
		case text != "" && strings.Contains(text, title):
			return img, banner, nil
		}
		if err := s.waitNoBanner(ctx, timeout); err != nil {
			return img, image.Rectangle{}, fmt.Errorf("another notice stayed visible instead of %q: %w", title, err)
		}
	}
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
			if _, saveErr := s.save(fmt.Sprintf("missing-banner-%d", time.Now().Unix()), img); saveErr != nil {
				return img, image.Rectangle{}, errors.Join(saveErr, ctx.Err())
			}
			return img, image.Rectangle{}, fmt.Errorf("guest notification banner did not appear: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// consentPromptMinHeight separates the consent prompt (title, a multi-line
// request and an action row: 215 px on GNOME 50) from a previous session's
// action-less "ended" notice (100 px with GNOME 50's header row, about 76 px
// on GNOME 43/46). GNOME can show that notice only after the next request,
// once waitNoBanner already passed: Fedora 44 fedora44-tier1-07 clicked the
// late "ended" notice as the clipboard-policy prompt and the request ended
// prompt_dismissed.
const consentPromptMinHeight = 140

// waitPromptBanner waits for the consent prompt banner, letting any shorter
// notice shown first expire instead of mistaking it for the prompt. Between
// short polls it nudges the parked pointer as local activity, as waitNoBanner
// does: on fedora44arm-tier1-10 GNOME showed no banner for a prompt posted
// right after the fullscreen witness window closed. Each shorter notice is
// kept as evidence: GNOME queues the prompt behind it (pipewire-fix-06).
func (s *assistanceScreen) waitPromptBanner(ctx context.Context, timeout time.Duration) (*image.RGBA, image.Rectangle, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for poll := 0; ; poll++ {
		img, banner, err := s.waitBanner(ctx, 5*time.Second)
		switch {
		case err == nil && banner.Dy() >= consentPromptMinHeight:
			return img, banner, nil
		case err == nil:
			if _, err := s.save(fmt.Sprintf("short-notice-%d", time.Now().UnixNano()), img); err != nil {
				return img, image.Rectangle{}, err
			}
			if err := s.waitNoBanner(ctx, timeout); err != nil {
				return img, image.Rectangle{}, fmt.Errorf("a %d px notice stayed visible instead of the consent prompt: %w", banner.Dy(), err)
			}
		case ctx.Err() != nil || img == nil:
			return img, banner, err
		default:
			if err := s.move(ctx, img.Bounds(), parkPoint(img.Bounds()).Add(image.Pt(poll%2, 0))); err != nil {
				return img, image.Rectangle{}, err
			}
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
		if err := s.move(ctx, img.Bounds(), park); err != nil {
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
			if _, saveErr := s.save(fmt.Sprintf("missing-portal-%d", time.Now().Unix()), img); saveErr != nil {
				return img, image.Rectangle{}, errors.Join(saveErr, ctx.Err())
			}
			return img, image.Rectangle{}, fmt.Errorf("portal share dialog did not appear: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// waitSwitchOn confirms the RemoteDesktop dialog's interaction switch at
// toggle shows the accent colour after it was clicked.
func (s *assistanceScreen) waitSwitchOn(ctx context.Context, toggle image.Point, timeout time.Duration) (*image.RGBA, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return nil, err
		}
		if portalSwitchOn(img, toggle) {
			return img, nil
		}
		select {
		case <-ctx.Done():
			return img, fmt.Errorf("portal remote interaction switch did not turn on: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// enablePortalShare prepares the open share dialog so Share grants what the
// request needs: Allow Remote Interaction for control on GNOME 42 and later,
// or the monitor row and, for control, the keyboard and pointer rows of
// GNOME 41's selection lists. It returns the capture proving the selection
// and its evidence name, or a nil capture when the dialog needed nothing.
func (s *assistanceScreen) enablePortalShare(ctx context.Context, img *image.RGBA, dialog image.Rectangle, control bool, scenario *assistanceScenarioEvidence) (*image.RGBA, string, error) {
	if control {
		if toggle, found := portalControlSwitch(img, dialog); found {
			if err := s.click(ctx, img.Bounds(), toggle, "portal-allow-remote-interaction", scenario); err != nil {
				return nil, "", err
			}
			enabled, err := s.waitSwitchOn(ctx, toggle, 10*time.Second)
			return enabled, "portal-interaction-enabled", err
		}
	}
	rows, gnome41 := gnome41PortalRows(img, dialog, control)
	if !gnome41 || (!control && portalShareSensitive(img, dialog)) {
		if control {
			return nil, "", errors.New("control request opened a portal dialog without a remote interaction switch or device list")
		}
		return nil, "", nil
	}
	selected, err := s.selectPortalRows(ctx, img, dialog, rows, scenario)
	if err != nil {
		return nil, "", err
	}
	if !portalShareSensitive(selected, dialog) {
		return selected, "", errors.New("portal Share stayed insensitive after selecting its rows")
	}
	return selected, "portal-rows-selected", nil
}

// selectPortalRows selects each GNOME 41 list row that is not yet selected,
// confirming every click by the row's selection accent, and returns the final
// capture of the dialog.
func (s *assistanceScreen) selectPortalRows(ctx context.Context, img *image.RGBA, dialog image.Rectangle, rows []portalRow, scenario *assistanceScenarioEvidence) (*image.RGBA, error) {
	for _, row := range rows {
		if portalRowSelected(img, dialog, row.centre) {
			continue
		}
		if err := s.click(ctx, img.Bounds(), row.centre, "portal-select-"+row.name, scenario); err != nil {
			return nil, err
		}
		var err error
		if img, err = s.waitRowSelected(ctx, dialog, row, 10*time.Second); err != nil {
			return nil, err
		}
	}
	return img, nil
}

func (s *assistanceScreen) waitRowSelected(ctx context.Context, dialog image.Rectangle, row portalRow, timeout time.Duration) (*image.RGBA, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return nil, err
		}
		if portalRowSelected(img, dialog, row.centre) {
			return img, nil
		}
		select {
		case <-ctx.Done():
			return img, fmt.Errorf("portal %s row was not selected: %w", row.name, ctx.Err())
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
	if err := s.waitPointerHover(ctx, point, target); err != nil {
		return err
	}
	if err := s.pointerClick(ctx, display, point); err != nil {
		return fmt.Errorf("click %s: %w", target, err)
	}
	scenario.Clicks = append(scenario.Clicks, assistanceClickEvidence{Target: target, X: point.X, Y: point.Y})
	return s.move(ctx, display, parkPoint(display))
}

// QEMU's USB tablet maps the whole desktop, not a single screendump. Once the
// second head is active, local clicks include its observed layout.
func (s *assistanceScreen) localPoint(display image.Rectangle, point image.Point) (image.Rectangle, image.Point) {
	if s.desktopBounds.Empty() {
		return display, point
	}
	return s.desktopBounds, point.Sub(display.Min).Add(s.headOrigin)
}

// move and pointerClick are the only local-seat pointer paths: both take
// head-0 screendump coordinates and send desktop-mapped QMP input. A click
// normalized against the screendump alone lands elsewhere once the second
// head widens the desktop, while the hover (already mapped) still settles.
func (s *assistanceScreen) move(ctx context.Context, display image.Rectangle, point image.Point) error {
	display, point = s.localPoint(display, point)
	return s.vm.pointerMove(ctx, display, point)
}

func (s *assistanceScreen) pointerClick(ctx context.Context, display image.Rectangle, point image.Point) error {
	display, point = s.localPoint(display, point)
	return s.vm.pointerClick(ctx, display, point, "left")
}

func (s *assistanceScreen) selectMonitors(ctx context.Context, dialog image.Rectangle, scenario *assistanceScenarioEvidence) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var borders [2]image.Rectangle
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return err
		}
		var found bool
		borders, found = portalMonitorTiles(img, dialog)
		if found {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("portal did not show two native monitor choices: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
	for i, border := range borders {
		point := image.Pt((border.Min.X+border.Max.X)/2, border.Min.Y+15)
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return err
		}
		if err := s.click(ctx, img.Bounds(), point, fmt.Sprintf("portal-select-monitor-%d", i), scenario); err != nil {
			return err
		}
	}
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return err
		}
		if portalMonitorSelected(img, borders[0]) && portalMonitorSelected(img, borders[1]) {
			path, err := s.save("portal-two-monitors-selected", img)
			if err != nil {
				return err
			}
			scenario.Screenshots = append(scenario.Screenshots, path)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("portal monitor choices did not both become selected: %w", ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// clickNotificationAction clicks action index of a banner declaring actions
// actions once the pointer rests on it. The hovered banner is located again
// first: if GNOME redrew it at other bounds under the pointer, the point
// follows the new bounds until they hold, and the first moved frame is kept
// as evidence. A click computed from stale bounds would land on the banner
// body, which GNOME treats as activation and closes the notification without
// an action (rocky102-arm64-dgx20-assistance-03/-05 ended prompt_dismissed).
func (s *assistanceScreen) clickNotificationAction(ctx context.Context, banner image.Rectangle, actions, index int, target string, scenario *assistanceScenarioEvidence) error {
	point := notificationActionPoint(banner, actions, index)
	if err := s.waitPointerHover(ctx, point, target); err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		hovered, err := s.vm.screendump(ctx)
		if err != nil {
			return err
		}
		current, found := locateNotificationBanner(s.reference, hovered)
		if found && current == banner {
			if err := s.pointerClick(ctx, hovered.Bounds(), point); err != nil {
				return fmt.Errorf("click %s: %w", target, err)
			}
			scenario.Clicks = append(scenario.Clicks, assistanceClickEvidence{Target: target, X: point.X, Y: point.Y})
			return s.move(ctx, hovered.Bounds(), parkPoint(hovered.Bounds()))
		}
		if attempt == 0 {
			if _, err := s.save(fmt.Sprintf("banner-moved-%s-%d", target, time.Now().Unix()), hovered); err != nil {
				return err
			}
		}
		if !found || attempt == 3 {
			return fmt.Errorf("notification banner did not hold still under the pointer for %s (last %v, found %t)", target, current, found)
		}
		banner, point = current, notificationActionPoint(current, actions, index)
		if err := s.move(ctx, hovered.Bounds(), point); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(screenPollInterval):
		}
	}
}

func (s *assistanceScreen) waitPointerHover(ctx context.Context, point image.Point, target string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	before, err := s.vm.screendump(ctx)
	if err != nil {
		return err
	}
	if err := s.move(ctx, before.Bounds(), point); err != nil {
		return err
	}
	previous := before
	for {
		current, err := s.vm.screendump(ctx)
		if err != nil {
			return err
		}
		if pointerHoverSettled(before, previous, current, point) {
			return nil
		}
		previous = current
		select {
		case <-ctx.Done():
			_, saveErr := s.save(fmt.Sprintf("missing-hover-%s-%d", target, time.Now().Unix()), current)
			return errors.Join(fmt.Errorf("guest pointer hover did not settle on %s: %w", target, ctx.Err()), saveErr)
		case <-time.After(screenPollInterval):
		}
	}
}
