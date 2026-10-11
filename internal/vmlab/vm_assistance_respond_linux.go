//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// heldVMFile names the held VM's private run directory inside the evidence
// directory, so the owner's respond command finds its QMP display socket.
const heldVMFile = "held-vm"

// AssistanceRespondActions are the local user's own controls, in UI order:
// the consent notification, the desktop portal dialog and the in-progress
// indicator, plus a plain screenshot.
var AssistanceRespondActions = []string{"screenshot", "allow", "decline", "share", "share-control", "cancel", "stop"}

// AssistanceRespond lets the owner of a held demo act as the guest's local
// user on a headless host. Each action is what a user at the seat would click,
// located and injected through the held VM's QMP display exactly as the lane
// does; nothing bypasses the prompt or the portal. allow completes the whole
// consent: Allow on the notification, then in the desktop's own dialog Allow
// Remote Interaction when that dialog offers it (a Control request) and Share.
// share, share-control and cancel answer an already open dialog. It returns
// the guest screenshot taken afterwards. allow, decline and stop click
// whichever notification is showing, so take a screenshot first.
func AssistanceRespond(ctx context.Context, evidenceDir, action string) (string, error) {
	evidence, err := newAssistanceEvidence(evidenceDir)
	if err != nil {
		return "", err
	}
	held, err := os.ReadFile(filepath.Join(evidenceDir, heldVMFile))
	if err != nil {
		return "", fmt.Errorf("evidence directory is not a held assistance run: %w", err)
	}
	dir := strings.TrimSpace(string(held))
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return "", errors.New("held VM directory must be a clean absolute path")
	}
	reference, err := readScreenPNG(filepath.Join(evidenceDir, "guest-desktop-reference.png"))
	if err != nil {
		return "", err
	}
	screen := &assistanceScreen{vm: &guestVM{dir: dir, hardware: VMHardwareOptions{Desktop: true}}, evidence: evidence, result: &VMAssistanceResult{}, reference: reference}
	clicks := &assistanceScenarioEvidence{}
	switch action {
	case "screenshot":
	case "allow", "decline", "stop":
		img, banner, err := screen.waitBanner(ctx, 15*time.Second)
		if err != nil {
			return "", err
		}
		// The consent prompt declares allow, decline; the indicator only stop.
		point := notificationActionPoint(banner, 1, 0)
		switch action {
		case "allow":
			point = notificationActionPoint(banner, 2, 0)
		case "decline":
			point = notificationActionPoint(banner, 2, 1)
		}
		if err := screen.click(ctx, img.Bounds(), point, action, clicks); err != nil {
			return "", err
		}
		if action == "allow" {
			img, dialog, err := screen.waitDialog(ctx, 45*time.Second)
			if err != nil {
				return "", err
			}
			if err := sharePortal(ctx, screen, img, dialog, portalHasControlSwitch(img, dialog), clicks); err != nil {
				return "", err
			}
		}
	case "share", "share-control", "cancel":
		img, dialog, err := screen.waitDialog(ctx, 15*time.Second)
		if err != nil {
			return "", err
		}
		if action == "cancel" {
			if err := screen.click(ctx, img.Bounds(), portalCancelButton(dialog), action, clicks); err != nil {
				return "", err
			}
			break
		}
		control := action == "share-control"
		if control && !portalHasControlSwitch(img, dialog) {
			return "", errors.New("the open dialog is a view-only screen share; it offers no remote interaction")
		}
		if err := sharePortal(ctx, screen, img, dialog, control, clicks); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unknown respond action %q; use one of %s", action, strings.Join(AssistanceRespondActions, ", "))
	}
	if action != "screenshot" {
		// Let the desktop finish closing the clicked surface.
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	img, err := screen.vm.screendump(ctx)
	if err != nil {
		return "", err
	}
	saved, err := screen.save(fmt.Sprintf("respond-%s-%s", time.Now().UTC().Format("20060102T150405.000Z"), action), img)
	if err != nil {
		return "", err
	}
	return filepath.Join(evidenceDir, saved), nil
}

// sharePortal clicks Share in the open portal dialog, switching on Allow Remote
// Interaction first when control is granted.
func sharePortal(ctx context.Context, screen *assistanceScreen, img *image.RGBA, dialog image.Rectangle, control bool, clicks *assistanceScenarioEvidence) error {
	if control {
		if err := screen.click(ctx, img.Bounds(), portalControlSwitch(dialog), "allow-remote-interaction", clicks); err != nil {
			return err
		}
		if _, err := screen.waitSwitchOn(ctx, dialog, 10*time.Second); err != nil {
			return err
		}
	}
	return screen.click(ctx, img.Bounds(), portalShareButton(dialog), "share", clicks)
}

// readScreenPNG loads a lossless guest capture the lane saved.
func readScreenPNG(path string) (_ *image.RGBA, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	config, err := png.DecodeConfig(io.LimitReader(file, 1<<20))
	if err != nil {
		return nil, err
	}
	if config.Width <= 0 || config.Height <= 0 || config.Width > maxScreendumpPixels/config.Height {
		return nil, errors.New("guest capture exceeds the screendump bound")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	decoded, err := png.Decode(io.LimitReader(file, 64<<20))
	if err != nil {
		return nil, err
	}
	img := image.NewRGBA(decoded.Bounds())
	draw.Draw(img, img.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
	return img, nil
}
