// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"time"
)

// OCR-located consent surfaces. Plasma's popups, xdg-desktop-portal-kde's
// QtQuick dialogs and their buttons have no stable pixel geometry across
// themes and font metrics, so desktops marked ocrConsent locate each control
// by its visible label in a QMP screendump (host tesseract, upscaled). The
// click itself stays local-seat QMP pointer input with hover feedback, and a
// server-state oracle follows every click, so a misread label fails the lane.

// ocrUpscale enlarges the crop: tesseract misreads 10-pt UI text at 1x, and
// at 2x it lost a hovered Breeze button's label (kde-fedora44-x86_64-04).
const ocrUpscale = 3

// ocrBinaryLuma binarizes the second OCR pass: Breeze draws the focused
// default button with an accent frame and fill that hides its light label
// from the plain luma pass (kde-fedora44-x86_64-05), but not from a threshold.
const ocrBinaryLuma = 150

// ocrRead returns the words tesseract finds in region of img, with boxes in
// img coordinates. Plain and binary luma passes retain light-on-dark text; an
// additional edge-cleared binary pass exposes dark text inside accent buttons.
// Luma, not colour: on Plasma's wallpaper-tinted popups tesseract reads the
// colour crop as a handful of fragments (kde-fedora44-x86_64-03).
func ocrRead(ctx context.Context, img *image.RGBA, region image.Rectangle) (_ []ocrWord, err error) {
	region = region.Intersect(img.Bounds())
	if region.Empty() {
		return nil, errors.New("empty OCR region")
	}
	dir, err := os.MkdirTemp("", "lindm-ocr-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	var words []ocrWord
	var scaled *image.Gray
	for pass := range 3 {
		if pass == 2 {
			// Reuse the binary mask. Do not invoke OCR again if there was no
			// edge-connected background to remove.
			if !ocrClearDarkBorder(scaled) {
				continue
			}
		} else {
			scaled = image.NewGray(image.Rect(0, 0, region.Dx()*ocrUpscale, region.Dy()*ocrUpscale))
			for y := range scaled.Rect.Dy() {
				for x := range scaled.Rect.Dx() {
					luma := pixelLuma(img, region.Min.X+x/ocrUpscale, region.Min.Y+y/ocrUpscale)
					switch {
					case pass == 1 && luma > ocrBinaryLuma:
						luma = 255
					case pass == 1:
						luma = 0
					}
					scaled.Pix[scaled.PixOffset(x, y)] = uint8(luma)
				}
			}
		}
		path := filepath.Join(dir, fmt.Sprintf("screen-%d.png", pass))
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		if err := errors.Join(png.Encode(file, scaled), file.Close()); err != nil {
			return nil, err
		}
		out, err := hostCommand(ctx, dir, "tesseract", nil, path, "stdout", "--psm", "11", "tsv")
		if err != nil {
			return nil, err
		}
		read := parseTesseractTSV(out, region.Min, ocrUpscale)
		for i := range read {
			read[i].pass = pass
		}
		words = append(words, read...)
	}
	return words, nil
}

// waitText polls the display until region (nil: the whole display) shows
// every label, and returns the capture with each label's box.
func (s *assistanceScreen) waitText(ctx context.Context, region func(image.Rectangle) image.Rectangle, timeout time.Duration, what string, labels ...string) (*image.RGBA, map[string]image.Rectangle, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		img, err := s.vm.screendump(ctx)
		if err != nil {
			return nil, nil, err
		}
		area := img.Bounds()
		if region != nil {
			area = region(area)
		}
		words, err := ocrRead(ctx, img, area)
		if err != nil && ctx.Err() == nil {
			return nil, nil, err
		}
		found := map[string]image.Rectangle{}
		for _, label := range labels {
			if box, ok := ocrLowest(words, label); ok {
				found[label] = box
			}
		}
		if len(found) == len(labels) {
			return img, found, nil
		}
		select {
		case <-ctx.Done():
			if _, saveErr := s.save(fmt.Sprintf("missing-%s-%d", what, time.Now().Unix()), img); saveErr != nil {
				return img, nil, errors.Join(saveErr, ctx.Err())
			}
			return img, nil, fmt.Errorf("guest %s (%q) did not appear: %w", what, labels, ctx.Err())
		case <-time.After(screenPollInterval):
		}
	}
}

// clickText clicks the label's button padding after the label is visible there,
// and re-reads it under the hovering pointer so a popup that moved or restacked
// is never clicked by stale coordinates.
func (s *assistanceScreen) clickText(ctx context.Context, region func(image.Rectangle) image.Rectangle, label, target string, scenario *assistanceScenarioEvidence) error {
	return s.clickLabel(ctx, region, label, target, scenario, true, ocrActionPoint)
}

// focusText clicks inert text (a dialog's description) only to activate its
// window. Inert text draws no hover feedback, so the label's re-read position
// is the only pre-click proof.
func (s *assistanceScreen) focusText(ctx context.Context, region func(image.Rectangle) image.Rectangle, label, target string, scenario *assistanceScenarioEvidence) error {
	return s.clickLabel(ctx, region, label, target, scenario, false, nil)
}

func (s *assistanceScreen) clickLabel(ctx context.Context, region func(image.Rectangle) image.Rectangle, label, target string, scenario *assistanceScenarioEvidence, hover bool, pointForLabel func(image.Rectangle) image.Point) error {
	img, found, err := s.waitText(ctx, region, 30*time.Second, target, label)
	if err != nil {
		return err
	}
	box := found[label]
	labelCentre := image.Pt(box.Min.X+box.Dx()/2, box.Min.Y+box.Dy()/2)
	point := labelCentre
	if pointForLabel != nil {
		point = pointForLabel(box)
	}
	if hover {
		err = s.waitPointerHover(ctx, point, target)
	} else {
		err = s.move(ctx, img.Bounds(), point)
	}
	if err != nil {
		return err
	}
	// Re-read only around the label: the hovered control alone decides.
	near := func(display image.Rectangle) image.Rectangle { return box.Inset(-48).Intersect(display) }
	hovered, again, err := s.waitText(ctx, near, 10*time.Second, target, label)
	if err != nil {
		return err
	}
	if moved := again[label]; !labelCentre.In(moved.Inset(-2)) {
		if _, saveErr := s.save(fmt.Sprintf("label-moved-%s-%d", target, time.Now().Unix()), hovered); saveErr != nil {
			return saveErr
		}
		return fmt.Errorf("%s label moved under the pointer from %v to %v", target, box, moved)
	}
	localDisplay, localPoint := s.localPoint(img.Bounds(), point)
	if err := s.vm.pointerClick(ctx, localDisplay, localPoint, "left"); err != nil {
		return fmt.Errorf("click %s: %w", target, err)
	}
	scenario.Clicks = append(scenario.Clicks, assistanceClickEvidence{Target: target, X: point.X, Y: point.Y})
	return s.move(ctx, img.Bounds(), s.parkPoint(img.Bounds()))
}

// popupRegion is where the desktop's notification popups appear.
func (s *assistanceScreen) popupRegion(display image.Rectangle) image.Rectangle {
	return s.area.region(display)
}

// pressKey sends one local-seat key chord and records it like a click.
func (s *assistanceScreen) pressKey(ctx context.Context, target string, scenario *assistanceScenarioEvidence, qcodes ...string) error {
	if err := s.vm.sendKey(ctx, qcodes...); err != nil {
		return err
	}
	scenario.Clicks = append(scenario.Clicks, assistanceClickEvidence{Target: target})
	return nil
}

// plasmaPortal answers xdg-desktop-portal-kde's dialog on the local seat.
// CONTROL opens its "Remote Control" dialog, whose Approve grants every
// output and input together and whose Deny cancels. VIEW opens its "Share
// screen with" chooser. Plasma 6.6 lists the monitor first, then synthetic
// "Share virtual screen" and "Share region" sources, so its description
// reads "Choose which screen…" even for one monitor; the window title is the
// stable anchor. A single-source request has no buttons: the focused search
// field accepts the first (real) monitor on Enter, and Escape cancels. The
// chooser is first activated through its inert title, so the keys reach it
// whatever window had focus before (kde-fedora44-x86_64-06).
func (r *assistanceRun) plasmaPortal(ctx context.Context, spec assistanceScenarioSpec, control bool, scenario *assistanceScenarioEvidence) error {
	if control {
		portal, _, err := r.screen.waitText(ctx, nil, 45*time.Second, "portal-dialog", "Approve", "Deny")
		if err != nil {
			return err
		}
		if err := r.guestScreenshot(scenario, "portal-dialog", portal); err != nil {
			return err
		}
		if spec.portalCancel {
			return r.screen.clickText(ctx, nil, "Deny", "portal-cancel", scenario)
		}
		return r.screen.clickText(ctx, nil, "Approve", "portal-approve", scenario)
	}
	const chooser = "Share screen with"
	portal, _, err := r.screen.waitText(ctx, nil, 45*time.Second, "portal-dialog", chooser)
	if err != nil {
		return err
	}
	if err := r.guestScreenshot(scenario, "portal-dialog", portal); err != nil {
		return err
	}
	if err := r.screen.focusText(ctx, nil, chooser, "portal-focus", scenario); err != nil {
		return err
	}
	if spec.portalCancel {
		return r.screen.pressKey(ctx, "portal-cancel", scenario, "esc")
	}
	return r.screen.pressKey(ctx, "portal-share", scenario, "ret")
}
