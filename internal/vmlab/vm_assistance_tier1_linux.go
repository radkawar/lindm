// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"math"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

type assistanceCommandWitness struct {
	RequestID string `json:"requestId"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Text      string `json:"text,omitempty"`
}

type assistanceCapabilityWitness struct {
	Capability          string                          `json:"capability"`
	SessionID           string                          `json:"session_id"`
	Granted             *agentv1.AssistanceCapabilities `json:"granted_capabilities"`
	Displays            []*agentv1.AssistanceDisplay    `json:"granted_displays"`
	Checks              []string                        `json:"checks"`
	PastedOperatorNonce string                          `json:"pasted_operator_nonce,omitempty"`
	Commands            []assistanceCommandWitness      `json:"commands"`
	Guest               *assistanceFixtureState         `json:"guest"`
	OperatorNonce       string                          `json:"operator_nonce,omitempty"`
	Screenshots         []string                        `json:"screenshots"`
	MessageScreenshot   string                          `json:"message_screenshot,omitempty"`
	MessageActor        *assistanceActor                `json:"message_actor,omitempty"`
	MonitorSelections   []assistanceMonitorWitness      `json:"monitor_selections,omitempty"`
	OCR                 string                          `json:"screenshot_ocr,omitempty"`
}
type assistanceMonitorWitness struct {
	Label   string                    `json:"label"`
	Head    int                       `json:"head"`
	Nonce   string                    `json:"nonce"`
	Command *assistanceCommandWitness `json:"command,omitempty"`
}

func assistanceNonce() (string, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

func (r *assistanceRun) tierOne(ctx context.Context, scenario *assistanceScenarioEvidence, session *adminv1.AssistanceSession) (err error) {
	policy := session.GetGrantedCapabilities().GetPolicy()
	granted := policy.GetKeyboard()
	switch scenario.Name {
	case "clipboard", "clipboard-limited":
		granted = policy.GetClipboard()
	case "display", "monitors":
		granted = policy.GetDisplay()
	case "message":
		granted = policy.GetMessages()
	}
	minimum := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	if scenario.Name == "display" || scenario.Name == "clipboard-limited" {
		minimum = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	}
	if granted < minimum {
		return fmt.Errorf("%s was not granted at the requested capability level", scenario.Name)
	}
	heads := 1
	if scenario.Name == "monitors" {
		heads = 2
		if len(session.GetDisplays()) != 2 {
			return fmt.Errorf("portal granted %d displays, require two real monitors", len(session.GetDisplays()))
		}
	}
	if err := r.startFixture(ctx, heads); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "control", nil, nil, time.Minute); err != nil {
		return err
	}
	witness := &assistanceCapabilityWitness{Capability: scenario.Name, SessionID: scenario.SessionID, Granted: session.GetGrantedCapabilities(), Displays: session.GetDisplays()}
	var marker struct {
		Head int `json:"head"`
	}
	if err := r.browser.call(ctx, "marker", nil, &marker, 45*time.Second); err != nil {
		return err
	}
	if marker.Head != 0 && heads == 1 {
		return errors.New("single-head scenario received wrong native marker")
	}
	if _, err := r.pointerWitness(ctx, marker.Head, 0.5, 0.6); err != nil {
		return err
	}
	switch scenario.Name {
	case "clipboard", "clipboard-limited":
		err = r.clipboardWitness(ctx, scenario, witness)
	case "keyboard":
		err = r.keyboardWitness(ctx, scenario, witness)
	case "display":
		err = r.presentationWitness(ctx, witness, marker.Head)
	case "message":
		// GNOME suppresses ordinary banners above fullscreen clients. Return
		// to the real desktop before sending the product notification.
		err = r.stopFixture(ctx)
		if err == nil {
			err = r.messageWitness(ctx, scenario, witness)
		}
	case "monitors":
		err = r.monitorsWitness(ctx, scenario, witness)
	default:
		err = errors.New("unknown Tier1 witness")
	}
	if err != nil {
		return err
	}
	witness.Guest, err = r.waitFixture(ctx, "final native witness", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return err
	}
	if err := verifyAssistanceFixtureIdentity(witness.Guest, scenario.LocalSession); err != nil {
		return err
	}
	if err := r.browserScreenshot(ctx, scenario, "capability"); err != nil {
		return err
	}
	witness.Screenshots = slices.Clone(scenario.Screenshots)
	data, err := json.MarshalIndent(witness, "", "  ")
	if err != nil {
		return err
	}
	bound, err := r.evidence.write(scenario.Name+" native witness", "witness-"+scenario.Name+".json", data)
	if err != nil {
		return err
	}
	r.result.Witnesses = append(r.result.Witnesses, bound)
	scenario.CapabilityWitness = bound.Path
	return nil
}

func (r *assistanceRun) commandWitness(ctx context.Context, witness *assistanceCapabilityWitness, op string, args map[string]any) (*assistanceCommandWitness, error) {
	var result assistanceCommandWitness
	if err := r.browser.call(ctx, op, args, &result, time.Minute); err != nil {
		return nil, err
	}
	var expected string
	switch op {
	case "clipboardSend":
		expected = "ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE"
	case "clipboardRead":
		expected = "ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ"
	case "special":
		expected = "ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS"
	case "message":
		expected = "ASSISTANCE_COMMAND_KIND_MESSAGE"
	}
	if result.Kind != expected {
		return nil, errors.New("capability command completed with the wrong operation kind")
	}
	if result.Status != "ASSISTANCE_COMMAND_STATUS_SUCCEEDED" || !vmValidID(result.RequestID) {
		return nil, errors.New("capability command did not report identified guest completion")
	}
	witness.Commands = append(witness.Commands, result)
	return &result, nil
}

func (r *assistanceRun) clipboardWitness(ctx context.Context, scenario *assistanceScenarioEvidence, witness *assistanceCapabilityWitness) error {
	nonce, err := assistanceNonce()
	if err != nil {
		return err
	}
	witness.OperatorNonce = nonce
	if _, err := r.commandWitness(ctx, witness, "clipboardSend", map[string]any{"text": nonce}); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "keys", map[string]any{"key": "Control+v", "mode": "Physical keys"}, nil, 30*time.Second); err != nil {
		return err
	}
	state, err := r.waitFixture(ctx, "operator nonce pasted by native GTK clipboard", func(state *assistanceFixtureState) bool { return state.Pasted == nonce })
	if err != nil {
		return err
	}
	witness.PastedOperatorNonce = state.Pasted
	if scenario.Name == "clipboard-limited" {
		witness.Checks = []string{"limited-operator-nonce-pasted-in-guest", "reverse-direction-authoritatively-refused"}
		return r.clipboardRefusal(ctx, scenario, "read-denied")
	}
	if state.ClipboardSource == nonce || len(state.ClipboardSource) != 24 {
		return errors.New("guest clipboard source is not an independent nonce")
	}
	if err := r.browser.call(ctx, "keys", map[string]any{"key": "Control+c"}, nil, 30*time.Second); err != nil {
		return err
	}
	// The GTK callback records the key and owns the native clipboard before it
	// writes state. Read only after that independent native event is observed.
	if _, err := r.waitFixture(ctx, "native copy gesture", func(state *assistanceFixtureState) bool {
		return len(state.Keys) > 0 && state.Keys[len(state.Keys)-1].Symbol == "c"
	}); err != nil {
		return err
	}
	result, err := r.commandWitness(ctx, witness, "clipboardRead", nil)
	if err != nil {
		return err
	}
	if result.Text != state.ClipboardSource {
		return errors.New("browser clipboard did not receive the independently generated guest nonce")
	}
	witness.Checks = []string{"operator-nonce-pasted-in-guest", "independent-guest-nonce-copied-to-browser"}
	return r.clipboardRefusal(ctx, scenario, "oversized")
}

func (r *assistanceRun) keyboardWitness(ctx context.Context, scenario *assistanceScenarioEvidence, witness *assistanceCapabilityWitness) (err error) {
	original, err := r.vm.guest.run(ctx, r.desktop.rootScript("as gsettings get org.gnome.desktop.input-sources sources"), nil, 4096, 15*time.Second)
	if err != nil {
		return err
	}
	defer func() {
		_, restoreErr := r.vm.guest.run(context.WithoutCancel(ctx), r.desktop.rootScript("as gsettings set org.gnome.desktop.input-sources sources "+nativeQuote(strings.TrimSpace(string(original)))), nil, 4096, 15*time.Second)
		err = errors.Join(err, restoreErr)
	}()
	if _, err := r.vm.guest.run(ctx, r.desktop.rootScript(`as gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'de')]"`), nil, 4096, 15*time.Second); err != nil {
		return err
	}
	if _, err := r.waitFixture(ctx, "native German keymap active", func(state *assistanceFixtureState) bool { return state.LayoutY == "z" && state.LayoutZ == "y" }); err != nil {
		return err
	}
	for _, mode := range []string{"Text", "Physical keys"} {
		for _, key := range []string{"KeyY", "KeyZ"} {
			if err := r.browser.call(ctx, "keys", map[string]any{"mode": mode, "key": key}, nil, 30*time.Second); err != nil {
				return err
			}
		}
	}
	if _, err := r.waitFixture(ctx, "semantic yz and physical zy in German guest layout", func(state *assistanceFixtureState) bool { return fixtureSymbols(state) == "yzzy" }); err != nil {
		return err
	}
	if err := r.modifierRelease(ctx, scenario); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "control", nil, nil, time.Minute); err != nil {
		return err
	}
	if err := r.unicodeKeyboardWitness(ctx); err != nil {
		return err
	}
	if _, err := r.commandWitness(ctx, witness, "special", nil); err != nil {
		return err
	}
	if _, err := r.waitFixture(ctx, "Close window destroyed native fixture window", func(state *assistanceFixtureState) bool { return slices.Contains(state.Closed, 0) }); err != nil {
		return err
	}
	witness.Checks = []string{"german-layout-semantic-yz", "german-layout-physical-zy", "german-layout-canonical-euro", "russian-layout-canonical-cyrillic", "special-close-window-native-delete-event"}
	return nil
}

func (r *assistanceRun) unicodeKeyboardWitness(ctx context.Context) error {
	if err := r.browser.call(ctx, "unicodeKey", map[string]any{"key": "€"}, nil, 30*time.Second); err != nil {
		return err
	}
	if _, err := r.waitFixture(ctx, "canonical EuroSign in native German keymap", func(state *assistanceFixtureState) bool {
		return fixtureUnicodeKey(state, "EuroSign", 0x20ac, "y")
	}); err != nil {
		return err
	}
	if _, err := r.vm.guest.run(ctx, r.desktop.rootScript(`as gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'ru')]"`), nil, 4096, 15*time.Second); err != nil {
		return err
	}
	if _, err := r.waitFixture(ctx, "native Russian keymap active", func(state *assistanceFixtureState) bool { return state.LayoutZ == "Cyrillic_ya" }); err != nil {
		return err
	}
	if err := r.browser.call(ctx, "unicodeKey", map[string]any{"key": "я"}, nil, 30*time.Second); err != nil {
		return err
	}
	_, err := r.waitFixture(ctx, "canonical Cyrillic_ya in native Russian keymap", func(state *assistanceFixtureState) bool {
		return fixtureUnicodeKey(state, "Cyrillic_ya", 0x44f, "Cyrillic_ya")
	})
	return err
}

func fixtureUnicodeKey(state *assistanceFixtureState, symbol string, unicode uint32, layoutZ string) bool {
	for _, key := range state.Keys {
		if key.Symbol == symbol && key.Unicode == unicode && key.LayoutZ == layoutZ {
			return true
		}
	}
	return false
}

func (r *assistanceRun) presentationWitness(ctx context.Context, witness *assistanceCapabilityWitness, head int) error {
	if err := r.browser.call(ctx, "boundary", map[string]any{"onlyDisplay": true}, nil, 30*time.Second); err != nil {
		return err
	}
	witness.Checks = append(witness.Checks, "limited-display-monitor-selection-disabled")
	for i, label := range []string{"Fit", "Actual size", "Full screen", "Exit full screen", "Fit"} {
		if err := r.browser.call(ctx, "presentation", map[string]any{"label": label}, nil, 30*time.Second); err != nil {
			return err
		}
		x, y := 0.3, 0.7
		if i%2 == 1 {
			x, y = 0.65, 0.4
		}
		if _, err := r.pointerWitness(ctx, head, x, y); err != nil {
			return fmt.Errorf("%s coordinates: %w", label, err)
		}
		witness.Checks = append(witness.Checks, label+"-native-pointer-coordinates")
	}
	return nil
}

func (r *assistanceRun) monitorsWitness(ctx context.Context, scenario *assistanceScenarioEvidence, witness *assistanceCapabilityWitness) error {
	var choices struct {
		Labels []string `json:"labels"`
	}
	if err := r.browser.call(ctx, "displays", nil, &choices, 30*time.Second); err != nil {
		return err
	}
	if len(choices.Labels) != 2 || choices.Labels[0] == choices.Labels[1] {
		return errors.New("console did not expose two distinct granted display choices")
	}
	fixture, err := r.waitFixture(ctx, "current monitor marker nonce", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return err
	}
	seen := map[int]bool{}
	for _, label := range choices.Labels {
		// Selecting the current display can be a no-op, so the driver returns
		// the existing selection without claiming a new command completed.
		var marker assistanceMonitorWitness
		if err := r.browser.call(ctx, "display", map[string]any{"label": label}, &marker, time.Minute); err != nil {
			return err
		}
		marker.Label = label
		witness.MonitorSelections = append(witness.MonitorSelections, marker)
		if marker.Command != nil {
			witness.Commands = append(witness.Commands, *marker.Command)
		}
		if marker.Head < 0 || marker.Head > 1 || marker.Nonce != fixture.ClipboardSource {
			return errors.New("invalid monitor marker")
		}
		if marker.Head == 1 {
			r.headOneLabel = label
		}
		if _, err := r.pointerWitness(ctx, marker.Head, 0.7, 0.7); err != nil {
			return err
		}
		if seen[marker.Head] {
			return errors.New("both monitor choices returned the same native head")
		}
		seen[marker.Head] = true
		img, err := r.vm.guest.screendumpHead(ctx, marker.Head)
		if err != nil {
			return err
		}
		if assistanceHeadMarker(img, fixture.ClipboardSource) != marker.Head {
			return errors.New("QMP scanout marker disagrees with streamed native monitor")
		}
		if err := r.guestScreenshot(scenario, fmt.Sprintf("head-%d", marker.Head), img); err != nil {
			return err
		}
		if err := r.browserScreenshot(ctx, scenario, fmt.Sprintf("head-%d", marker.Head)); err != nil {
			return err
		}
	}
	if !seen[0] || !seen[1] {
		return errors.New("monitor selection did not visit both heads")
	}
	var selected assistanceMonitorWitness
	if err := r.browser.call(ctx, "display", map[string]any{"label": r.headOneLabel}, &selected, time.Minute); err != nil {
		return err
	}
	if selected.Head != 1 || selected.Nonce != fixture.ClipboardSource {
		return errors.New("failed to select native head one for hot-unplug")
	}
	if selected.Command != nil {
		witness.Commands = append(witness.Commands, *selected.Command)
	}
	witness.Checks = []string{"two-active-native-monitors", "distinct-qmp-and-video-head-markers", "head-zero-pointer-routing", "head-one-pointer-routing"}
	return nil
}

func (r *assistanceRun) messageWitness(ctx context.Context, scenario *assistanceScenarioEvidence, witness *assistanceCapabilityWitness) (err error) {
	if _, err := exec.LookPath("tesseract"); err != nil {
		return fmt.Errorf("message pixel witness requires host tesseract: %w", err)
	}
	nonce, err := assistanceNonce()
	if err != nil {
		return err
	}
	witness.OperatorNonce = nonce
	witness.MessageActor = new(assistanceActor)
	if err := r.browser.call(ctx, "identity", nil, witness.MessageActor, 30*time.Second); err != nil {
		return err
	}
	if err := verifyAssistanceActor(scenario, witness.MessageActor); err != nil {
		return err
	}
	// Observe pixels while the command is in flight: a normal GNOME banner
	// can disappear before the next device completion report reaches the UI.
	commandCtx, cancelCommand := context.WithTimeout(ctx, 45*time.Second)
	done := make(chan error, 1)
	go func() {
		_, commandErr := r.commandWitness(commandCtx, witness, "message", map[string]any{"text": nonce})
		done <- commandErr
	}()
	defer func() {
		if err != nil {
			cancelCommand()
		}
		err = errors.Join(err, <-done)
		cancelCommand()
	}()
	ctx, cancel := context.WithTimeout(commandCtx, 35*time.Second)
	defer cancel()
	for attempt := 0; ; attempt++ {
		img, err := r.vm.guest.screendump(ctx)
		if err != nil {
			return err
		}
		// Only the notification region is OCRed, not the fixture's visible
		// copy-source nonce or any operator console DOM.
		bounds := img.Bounds()
		region := image.Rect(bounds.Min.X, bounds.Min.Y, bounds.Max.X, min(bounds.Max.Y, bounds.Min.Y+360))
		crop, ok := img.SubImage(region).(*image.RGBA)
		if !ok {
			return errors.New("invalid notification screenshot crop")
		}
		name := fmt.Sprintf("message-banner-%d", attempt)
		path, err := r.screen.save(name, crop)
		if err != nil {
			return err
		}
		scenario.Screenshots = append(scenario.Screenshots, path)
		// tesseract read nothing of GNOME's light-on-dark banner text in the
		// full-width crop (fedora44arm-tier1-18); it reads the located banner
		// alone, in grayscale, upscaled three times.
		banner, found := locateNotificationBanner(r.screen.reference, img)
		if !found {
			select {
			case <-ctx.Done():
				return fmt.Errorf("authenticated sender, product and message nonce not visible together in guest screenshot: %w", ctx.Err())
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		ocrPath, err := r.screen.save(name+"-ocr", upscaleGray(img, banner, 3))
		if err != nil {
			return err
		}
		scenario.Screenshots = append(scenario.Screenshots, ocrPath)
		out, err := hostCommand(ctx, r.evidence.dir, "env", nil, "OMP_THREAD_LIMIT=1", "tesseract", filepath.Join(r.evidence.dir, ocrPath), "stdout", "--psm", "6")
		if err != nil {
			return err
		}
		if assistanceMessageVisible(string(out), witness.MessageActor.Display, nonce) {
			witness.OCR = string(out)
			witness.MessageScreenshot = path
			witness.Checks = []string{"authenticated-sender-product-and-nonce-visible-in-same-guest-notification"}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("authenticated sender, product and message nonce not visible together in guest screenshot: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// upscaleGray returns region of img as grayscale, bilinearly scaled by
// factor, in an RGBA image for the evidence PNG encoder.
func upscaleGray(img *image.RGBA, region image.Rectangle, factor int) *image.RGBA {
	region = region.Intersect(img.Bounds())
	width, height := region.Dx()*factor, region.Dy()*factor
	out := image.NewRGBA(image.Rect(0, 0, width, height))
	luma := func(x, y int) float64 {
		x = min(max(x, region.Min.X), region.Max.X-1)
		y = min(max(y, region.Min.Y), region.Max.Y-1)
		i := img.PixOffset(x, y)
		return 0.299*float64(img.Pix[i]) + 0.587*float64(img.Pix[i+1]) + 0.114*float64(img.Pix[i+2])
	}
	for y := range height {
		sy := float64(region.Min.Y) + (float64(y)+0.5)/float64(factor) - 0.5
		y0, fy := int(math.Floor(sy)), sy-math.Floor(sy)
		for x := range width {
			sx := float64(region.Min.X) + (float64(x)+0.5)/float64(factor) - 0.5
			x0, fx := int(math.Floor(sx)), sx-math.Floor(sx)
			top := luma(x0, y0)*(1-fx) + luma(x0+1, y0)*fx
			bottom := luma(x0, y0+1)*(1-fx) + luma(x0+1, y0+1)*fx
			v := uint8(math.Round(top*(1-fy) + bottom*fy))
			i := out.PixOffset(x, y)
			out.Pix[i], out.Pix[i+1], out.Pix[i+2], out.Pix[i+3] = v, v, v, 255
		}
	}
	return out
}
