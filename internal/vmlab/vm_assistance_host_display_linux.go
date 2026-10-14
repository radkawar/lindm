// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

// assistanceHostDisplay is a private, authenticated X server for the operator's
// real native save picker. It never connects to the developer's desktop or bus.
// The guest FileChooser remains the real Wayland portal inside the guest.
type assistanceHostDisplay struct {
	display string
	dir     string
	env     []string
	xserver *labexec.Process
	bus     *labexec.Process
}

func startAssistanceHostDisplay(ctx context.Context, private string) (_ *assistanceHostDisplay, err error) {
	var random [18]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(private, "operator-display-")
	if err != nil {
		return nil, err
	}
	d := &assistanceHostDisplay{display: ":" + strconv.Itoa(1000+int(binary.BigEndian.Uint16(random[:2]))%50000), dir: directory}
	defer func() {
		if err != nil {
			err = errors.Join(err, d.Close())
		}
	}()
	auth := filepath.Join(d.dir, "operator-xauthority")
	if err := os.WriteFile(auth, nil, 0600); err != nil {
		return nil, err
	}
	// Feed the cookie over stdin, never argv, logs or public evidence.
	input := "add " + d.display + " MIT-MAGIC-COOKIE-1 " + hex.EncodeToString(random[2:]) + "\nexit\n"
	if err := labexec.Run(ctx, labexec.Command{Path: "xauth", Args: []string{"-q", "-f", auth, "source", "-"}, Stdin: strings.NewReader(input), Timeout: 10 * time.Second}); err != nil {
		return nil, fmt.Errorf("create isolated browser display authority: %w", err)
	}
	clear(random[:])
	d.env = assistanceHostEnvironment(os.Environ(), d.display, auth)
	d.xserver, err = labexec.Start(context.WithoutCancel(ctx), labexec.Command{
		Path: "Xvfb", Args: []string{d.display, "-screen", "0", "1600x1200x24", "-nolisten", "tcp", "-auth", auth, "-noreset"}, Env: d.env,
	})
	if err != nil {
		return nil, fmt.Errorf("start isolated browser display: %w", err)
	}
	if err := d.waitReady(ctx); err != nil {
		return nil, err
	}
	address, err := d.startBus(ctx, d.dir)
	if err != nil {
		return nil, err
	}
	d.env = append(d.env, "DBUS_SESSION_BUS_ADDRESS="+address)
	return d, nil
}

func assistanceHostEnvironment(inherited []string, display, auth string) []string {
	blocked := []string{"DISPLAY=", "WAYLAND_DISPLAY=", "XAUTHORITY=", "DBUS_SESSION_BUS_ADDRESS=", "DBUS_STARTER_ADDRESS=", "DBUS_STARTER_BUS_TYPE=", "XDG_CURRENT_DESKTOP=", "XDG_SESSION_TYPE=", "GTK_USE_PORTAL=", "GDK_BACKEND=", "LANG=", "LC_ALL="}
	out := make([]string, 0, len(inherited)+7)
	for _, value := range inherited {
		skip := false
		for _, prefix := range blocked {
			if strings.HasPrefix(value, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, value)
		}
	}
	return append(out, "DISPLAY="+display, "XAUTHORITY="+auth, "XDG_SESSION_TYPE=x11", "GTK_USE_PORTAL=0", "GDK_BACKEND=x11", "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
}

func (d *assistanceHostDisplay) waitReady(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := labexec.Run(ctx, labexec.Command{Path: "xwininfo", Args: []string{"-root"}, Env: d.env, Timeout: time.Second}); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("isolated browser display did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (d *assistanceHostDisplay) startBus(ctx context.Context, private string) (_ string, err error) {
	// No activation directories: a browser portal cannot escape onto a physical
	// session. Chromium's real native GTK picker is the supported host fallback.
	var escaped bytes.Buffer
	if err := xml.EscapeText(&escaped, []byte(private)); err != nil {
		return "", err
	}
	config := `<busconfig><type>session</type><listen>unix:tmpdir=` + escaped.String() + `</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy></busconfig>`
	path := filepath.Join(private, "operator-bus.xml")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		return "", err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, reader.Close()) }()
	d.bus, err = labexec.Start(context.WithoutCancel(ctx), labexec.Command{Path: "dbus-daemon", Args: []string{"--nofork", "--config-file=" + path, "--print-address=3"}, Env: d.env, Files: []*os.File{writer}})
	if closeErr := writer.Close(); err != nil || closeErr != nil {
		return "", errors.Join(err, closeErr)
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(wait, func() { _ = reader.Close() })
	defer stop()
	address, err := bufio.NewReader(io.LimitReader(reader, 4096)).ReadString('\n')
	if err != nil {
		return "", errors.Join(fmt.Errorf("read isolated browser bus address: %w", err), wait.Err())
	}
	address = strings.TrimSpace(address)
	if !strings.HasPrefix(address, "unix:path="+private+"/") || strings.ContainsAny(address, "\r\n\x00") {
		return "", errors.New("isolated browser bus returned an unexpected address")
	}
	return address, nil
}

// saveFile drives the actual Chromium/GTK native picker with XTEST, not an
// overridden browser API. The target is a new file inside the lane's private
// evidence directory; the recorded window identity and pixels remain evidence.
func (d *assistanceHostDisplay) saveFile(parent context.Context, target, screenshot string) (string, error) {
	if !filepath.IsAbs(target) || strings.ContainsAny(target, "\r\n\x00") {
		return "", errors.New("native save target must be an absolute private path")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("native save target is not new")
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	id, err := d.waitSavePicker(ctx)
	if err != nil {
		return "", err
	}
	name, err := d.tool(ctx, "xdotool", "getwindowname", id)
	if err != nil {
		return "", err
	}
	if err := d.screenshot(ctx, screenshot); err != nil {
		return "", err
	}
	// The dialog preselects only the suggested name's stem; select the whole
	// entry so the typed absolute path replaces it ("saved.txt.txt" otherwise).
	if _, err := d.tool(ctx, "xdotool", "windowfocus", "--sync", id, "key", "--clearmodifiers", "ctrl+l", "ctrl+a"); err != nil {
		return "", err
	}
	if err := labexec.Run(ctx, labexec.Command{Path: "xdotool", Args: []string{"type", "--clearmodifiers", "--delay", "1", "--file", "-"}, Env: d.env, Stdin: strings.NewReader(target), Timeout: 10 * time.Second}); err != nil {
		return "", err
	}
	if err := d.clickSave(ctx, id); err != nil {
		return "", err
	}
	return strings.TrimSpace(name), nil
}

// clickSave presses the dialog's Save button with the XTEST pointer once the
// typed path has settled. On the lane's window-manager-less display, Return in
// the name entry did not activate Save (reproduced with Chromium 156 and GTK
// 3.24 on Xvfb); the button sits in the dialog's bottom-right corner.
func (d *assistanceHostDisplay) clickSave(ctx context.Context, id string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Second):
	}
	out, err := d.tool(ctx, "xdotool", "getwindowgeometry", "--shell", id)
	if err != nil {
		return err
	}
	geometry := map[string]int{}
	for _, line := range strings.Fields(out) {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		number, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("native save picker geometry is invalid")
		}
		geometry[key] = number
	}
	if geometry["WIDTH"] < 200 || geometry["HEIGHT"] < 100 {
		return errors.New("native save picker geometry is invalid")
	}
	x, y := geometry["X"]+geometry["WIDTH"]-48, geometry["Y"]+geometry["HEIGHT"]-22
	_, err = d.tool(ctx, "xdotool", "mousemove", strconv.Itoa(x), strconv.Itoa(y), "click", "1")
	return err
}

// waitSavePicker returns the one visible top-level window that is not a
// browser window. Chromium titles its GTK save dialog for the File System
// Access API "Warning: this site can see edits you make", not "Save"
// (layers-fedora44-files-05), so the dialog is found by elimination on the
// lane's private display, where nothing else runs.
func (d *assistanceHostDisplay) waitSavePicker(ctx context.Context) (string, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		out, err := d.tool(ctx, "xdotool", "search", "--onlyvisible", "--name", ".")
		if err == nil {
			var pickers []string
			for _, id := range strings.Fields(out) {
				if _, err := strconv.ParseUint(id, 10, 32); err != nil {
					return "", errors.New("native save picker window identity is invalid")
				}
				name, err := d.tool(ctx, "xdotool", "getwindowname", id)
				if err != nil {
					continue // the window closed between search and read
				}
				if !browserWindowTitle(strings.TrimSpace(name)) {
					pickers = append(pickers, id)
				}
			}
			switch len(pickers) {
			case 0:
			case 1:
				return pickers[0], nil
			default:
				return "", errors.New("native save picker window is ambiguous")
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("native browser save picker did not appear: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// browserWindowTitle reports Chromium's own top-level window ("page - Google
// Chrome for Testing", "page - Chromium").
func browserWindowTitle(name string) bool {
	for _, suffix := range []string{" - Google Chrome for Testing", " - Google Chrome", " - Chromium"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func (d *assistanceHostDisplay) tool(ctx context.Context, program string, args ...string) (string, error) {
	bounded := nativeexec.NewBuffer(16 << 10)
	err := labexec.Run(ctx, labexec.Command{Path: program, Args: args, Env: d.env, Stdout: bounded, Timeout: 5 * time.Second})
	if err != nil {
		return "", err
	}
	if bounded.Truncated() {
		return "", errors.New("native picker tool output exceeded its bound")
	}
	return bounded.String(), nil
}

func (d *assistanceHostDisplay) screenshot(ctx context.Context, path string) error {
	return labexec.Run(ctx, labexec.Command{Path: "ffmpeg", Args: []string{"-nostdin", "-v", "error", "-f", "x11grab", "-video_size", "1600x1200", "-i", d.display, "-frames:v", "1", "-n", path}, Env: d.env, Timeout: 15 * time.Second})
}

func (d *assistanceHostDisplay) Close() error {
	var failures []error
	if d.bus != nil {
		failures = append(failures, d.bus.Close())
		d.bus = nil
	}
	if d.xserver != nil {
		failures = append(failures, d.xserver.Close())
		d.xserver = nil
	}
	if d.dir != "" {
		failures = append(failures, os.RemoveAll(d.dir))
		d.dir = ""
	}
	return errors.Join(failures...)
}

// moveOperatorDestination moves what the operator's browser saved into the
// evidence directory, never following a link or replacing a file. A missing
// staged file (a refused or cancelled save) moves nothing.
func moveOperatorDestination(staged, target string) (err error) {
	source, err := os.OpenFile(staged, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	if info, err := source.Stat(); err != nil || !info.Mode().IsRegular() {
		return errors.Join(err, errors.New("operator destination is not a regular file"))
	}
	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(destination, source); err != nil {
		return errors.Join(err, destination.Close())
	}
	if err := destination.Close(); err != nil {
		return err
	}
	return os.Remove(staged)
}
