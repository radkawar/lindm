// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"math"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

//go:embed assistance_fixture.py
var assistanceFixtureSource []byte

const assistanceFixturePath = "/home/" + actionDesktopUser + "/lindm-assistance-fixture.py"
const assistanceFixtureStatePath = "/home/" + actionDesktopUser + "/lindm-assistance-fixture.json"

type assistanceFixtureState struct {
	Backend        string `json:"backend"`
	Display        string `json:"display"`
	UID            uint32 `json:"uid"`
	PID            int    `json:"pid"`
	SessionID      string `json:"session_id"`
	SessionType    string `json:"session_type"`
	ActiveMonitors int    `json:"active_monitors"`
	RemovedHeads   []int  `json:"removed_heads"`
	Monitors       []struct {
		Head   int    `json:"head"`
		Model  string `json:"model"`
		X      int    `json:"x"`
		Y      int    `json:"y"`
		Width  int    `json:"width"`
		Height int    `json:"height"`
	} `json:"monitors"`
	ClipboardSource string `json:"clipboard_source"`
	Pasted          string `json:"pasted"`
	PasteSerial     int    `json:"paste_serial"`
	LayoutY         string `json:"layout_y"`
	LayoutZ         string `json:"layout_z"`
	Keys            []struct {
		Head    int    `json:"head"`
		Symbol  string `json:"symbol"`
		Unicode uint32 `json:"unicode"`
		LayoutZ string `json:"layout_z"`
	} `json:"keys"`
	Releases []string                   `json:"releases"`
	Clicks   []assistancePointerWitness `json:"clicks"`
	Closed   []int                      `json:"closed"`
}

type assistancePointerWitness struct {
	Head int     `json:"head"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
}

func assistanceFullPolicy() *agentv1.AssistancePolicy {
	const on = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	return &agentv1.AssistancePolicy{Clipboard: on, Keyboard: on, Display: on, Messages: on}
}

func installAssistanceFixture(ctx context.Context, vm *guestVM, desktop *labDesktop, release *platform.Release, evidence *assistanceEvidence, result *VMAssistanceResult) error {
	command, err := labInstallCommand(release, release.Lab.Session.AssistanceFixtures)
	if err != nil {
		return err
	}
	if err := runAssistanceSetup(ctx, vm, evidence, result, "fixture-prerequisites", "sudo -n env DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), 10*time.Minute); err != nil {
		return fmt.Errorf("install native assistance witness prerequisites: %w", err)
	}
	script := "umask 077; cat > " + nativeQuote(assistanceFixturePath) + "; chown \"$u:$u\" " + nativeQuote(assistanceFixturePath)
	_, err = vm.run(ctx, desktop.rootScript(script), bytes.NewReader(assistanceFixtureSource), 4096, 30*time.Second)
	return err
}

func (r *assistanceRun) startFixture(ctx context.Context, heads int) error {
	script := fmt.Sprintf(`rm -f %s
as systemd-run --user --collect --unit=lindm-assistance-fixture --property=RuntimeMaxSec=600 --setenv=GDK_BACKEND=wayland --setenv=WAYLAND_DISPLAY=wayland-0 /usr/bin/python3 %s %s %d`, nativeQuote(assistanceFixtureStatePath), nativeQuote(assistanceFixturePath), nativeQuote(assistanceFixtureStatePath), heads)
	if err := runAssistanceSetup(ctx, r.vm.guest, r.evidence, r.result, "fixture-start", r.desktop.rootScript(script), 30*time.Second); err != nil {
		return err
	}
	r.fixtureLive = true
	state, err := r.waitFixture(ctx, "active native monitors", func(state *assistanceFixtureState) bool {
		return len(state.Monitors) == heads
	})
	if err != nil {
		return err
	}
	// The state file precedes GTK's event loop: it proves monitor discovery,
	// not visible media. Bind the independently read nonce and require its
	// pixels on the current console stream before any native interaction.
	return r.browser.call(ctx, "fixture", map[string]any{"nonce": state.ClipboardSource}, nil, 45*time.Second)
}

func (r *assistanceRun) stopFixture(ctx context.Context) error {
	if !r.fixtureLive {
		return nil
	}
	// An "ended" notice posted under the fullscreen witness stayed queued and
	// held every later banner unless local keyboard input followed (only
	// clipboard's post-end pastes did; after clipboard-limited the
	// clipboard-policy prompt never appeared: ubuntu24arm-/fedora44arm-tier1-13).
	// A local Shift tap is that activity and types nothing.
	if err := r.vm.guest.sendKey(ctx, "shift"); err != nil {
		return err
	}
	_, err := r.vm.guest.run(ctx, r.desktop.rootScript("as systemctl --user stop lindm-assistance-fixture.service"), nil, 4096, 30*time.Second)
	if err == nil {
		r.fixtureLive = false
	}
	return err
}

func (r *assistanceRun) waitFixture(ctx context.Context, what string, accept func(*assistanceFixtureState) bool) (*assistanceFixtureState, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		out, err := r.vm.guest.run(ctx, "sudo -n cat "+nativeQuote(assistanceFixtureStatePath), nil, 32<<10, 10*time.Second)
		if err == nil {
			state := new(assistanceFixtureState)
			if err := json.Unmarshal(out, state); err != nil {
				return nil, fmt.Errorf("decode native witness: %w", err)
			}
			if accept(state) {
				return state, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("native witness did not observe %s: %w", what, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// assistanceHeadMarker independently decodes the same complementary-cell GTK
// marker as the browser, from real QMP scanout pixels. No background color can
// substitute for the current fixture nonce.
func assistanceHeadMarker(img *image.RGBA, expectedNonce string) int {
	var nonce [12]byte
	if img == nil || len(expectedNonce) != hex.EncodedLen(len(nonce)) {
		return -1
	}
	if _, err := hex.Decode(nonce[:], []byte(expectedNonce)); err != nil {
		return -1
	}
	bounds := img.Bounds()
	width, height := float64(bounds.Dx()), float64(bounds.Dy())
	cellWidth, cellHeight := width*0.8/28, height*0.28/8
	if cellWidth < 8 || cellHeight < 8 {
		return -1
	}
	var payload [14]byte
	for bit := range 112 {
		var first byte
		for half := range 2 {
			x := bounds.Min.X + int(width*0.1+(float64(bit%14*2+half)+0.5)*cellWidth)
			y := bounds.Min.Y + int(height*0.65+(float64(bit/14)+0.5)*cellHeight)
			var red, green, blue int
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					pixel := img.RGBAAt(x+dx, y+dy)
					red += int(pixel.R)
					green += int(pixel.G)
					blue += int(pixel.B)
				}
			}
			var value byte
			switch {
			case red <= 80*9 && green <= 80*9 && blue <= 80*9:
				value = 0
			case red >= 175*9 && green >= 175*9 && blue >= 175*9:
				value = 1
			default:
				return -1
			}
			if half == 0 {
				first = value
			} else if value == first {
				return -1
			}
		}
		payload[bit/8] |= first << (7 - bit%8)
	}
	if payload[0] != 0xa7 || payload[1] > 1 || !bytes.Equal(payload[2:], nonce[:]) {
		return -1
	}
	return int(payload[1])
}

// verifyAssistancePointer rejects wrong-head routing as well as scaling errors.
func verifyAssistancePointer(got assistancePointerWitness, head int, x, y float64) error {
	if got.Head != head || math.IsNaN(got.X) || math.IsNaN(got.Y) || math.Abs(got.X-x) > 0.025 || math.Abs(got.Y-y) > 0.025 {
		return fmt.Errorf("pointer reached head %d (%.3f,%.3f), wanted head %d (%.3f,%.3f)", got.Head, got.X, got.Y, head, x, y)
	}
	return nil
}

func (r *assistanceRun) pointerWitness(ctx context.Context, head int, x, y float64) (*assistanceFixtureState, error) {
	before, err := r.waitFixture(ctx, "pointer baseline", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return nil, err
	}
	if err := r.browser.call(ctx, "click", map[string]any{"x": x, "y": y}, nil, 30*time.Second); err != nil {
		return nil, err
	}
	after, err := r.waitFixture(ctx, "new pointer event", func(state *assistanceFixtureState) bool { return len(state.Clicks) > len(before.Clicks) })
	if err != nil {
		return nil, err
	}
	if len(after.Clicks) != len(before.Clicks)+1 {
		return nil, errors.New("unexpected duplicate guest pointer events")
	}
	return after, verifyAssistancePointer(after.Clicks[len(before.Clicks)], head, x, y)
}

func fixtureSymbols(state *assistanceFixtureState) string {
	var result strings.Builder
	for _, key := range state.Keys {
		if key.Symbol == "y" || key.Symbol == "z" {
			result.WriteString(key.Symbol)
		}
	}
	return result.String()
}

func (r *assistanceRun) observeMonitorLayout(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	const probe = `import gi,json; gi.require_version("Gdk","3.0"); from gi.repository import Gdk; d=Gdk.Display.get_default(); print(json.dumps([[g.x,g.y,g.width,g.height] for g in [d.get_monitor(i).get_geometry() for i in range(d.get_n_monitors())]]))`
	for {
		out, err := r.vm.guest.run(ctx, r.desktop.rootScript("as python3 -c "+nativeQuote(probe)), nil, 4096, 10*time.Second)
		if err != nil {
			return err
		}
		var monitors [][4]int
		if err := json.Unmarshal(out, &monitors); err != nil {
			return err
		}
		if len(monitors) == 2 {
			first, second := monitorRectangle(monitors[0]), monitorRectangle(monitors[1])
			if first.Empty() || second.Empty() || first.Overlaps(second) {
				return errors.New("two-head guest exposes mirrored or invalid monitor geometry")
			}
			r.screen.desktopBounds = first.Union(second)
			r.screen.headOrigin = first.Min
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("RFB resize did not activate two native monitors: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func monitorRectangle(geometry [4]int) image.Rectangle {
	return image.Rect(geometry[0], geometry[1], geometry[0]+geometry[2], geometry[1]+geometry[3])
}

// Native package managers and systemd-run legitimately use stderr for progress.
// Preserve both bounded streams and the exact exit status instead of applying
// the strict empty-stderr contract used for machine-readable guest probes.
func runAssistanceSetup(ctx context.Context, vm *guestVM, evidence *assistanceEvidence, result *VMAssistanceResult, name, command string, timeout time.Duration) error {
	executed, runErr := vm.runResult(ctx, command, nil, 1<<20, timeout)
	return recordAssistanceSetup(evidence, result, name, command, executed, runErr)
}

func recordAssistanceSetup(evidence *assistanceEvidence, result *VMAssistanceResult, name, command string, executed guestCommandResult, runErr error) error {
	record := struct {
		Command  string `json:"command"`
		ExitCode int    `json:"exit_code"`
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		Failure  string `json:"failure,omitempty"`
	}{Command: command, ExitCode: executed.ExitCode, Stdout: string(executed.Stdout), Stderr: string(executed.Stderr)}
	if runErr != nil {
		record.Failure = runErr.Error()
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return errors.Join(runErr, err)
	}
	nonce, err := assistanceNonce()
	if err != nil {
		return errors.Join(runErr, err)
	}
	bound, err := evidence.write("native "+name, name+"-"+nonce+".json", data)
	if err != nil {
		return errors.Join(runErr, err)
	}
	result.Journals = append(result.Journals, bound)
	if runErr != nil {
		return runErr
	}
	if executed.ExitCode != 0 {
		return fmt.Errorf("native %s exited %d; stdout and stderr are retained in %s", name, executed.ExitCode, bound.Path)
	}
	return nil
}
