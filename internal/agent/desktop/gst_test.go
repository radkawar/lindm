// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
)

func TestScaledSize(t *testing.T) {
	for _, tc := range []struct {
		width, height int
		wantW, wantH  int
		ok            bool
	}{
		{1920, 1080, 1920, 1080, true},
		{3840, 2160, 1920, 1080, true},
		{2560, 1440, 1920, 1080, true},
		{2560, 1600, 1920, 1200, true},
		{3440, 1440, 1920, 804, true},  // 803.7 rounds to 804
		{5120, 1440, 1920, 540, true},  // super-ultrawide
		{2736, 1824, 1920, 1280, true}, // 3:2
		{1366, 768, 1366, 768, true},
		{1365, 767, 1364, 766, true}, // odd dims made even
		{1080, 1920, 1080, 1920, true},
		{2000, 3, 1920, 2, true}, // never below 2
		{0, 1080, 0, 0, false},
		{1920, 0, 0, 0, false},
		{-1, -1, 0, 0, false},
	} {
		w, h, ok := scaledSize(tc.width, tc.height)
		if w != tc.wantW || h != tc.wantH || ok != tc.ok {
			t.Errorf("scaledSize(%d, %d) = %d, %d, %t; want %d, %d, %t", tc.width, tc.height, w, h, ok, tc.wantW, tc.wantH, tc.ok)
		}
		if ok && (w%2 != 0 || h%2 != 0 || w > captureMaxWidth) {
			t.Errorf("scaledSize(%d, %d) = %d x %d violates bounds", tc.width, tc.height, w, h)
		}
	}
}

func TestGstArguments(t *testing.T) {
	args := gstArguments(57, 3840, 2160, false)
	want := "-m pipewiresrc fd=3 path=57 ! tee name=lindm-source lindm-source. ! " +
		"imagefreeze is-live=true allow-replace=true ! videoconvert ! videoscale ! " +
		"video/x-raw,framerate=15/1,width=1920,height=1080 ! vp8enc deadline=1 cpu-used=8 end-usage=cbr " +
		"target-bitrate=2500000 keyframe-max-dist=30 error-resilient=default ! rtpvp8pay mtu=1200 pt=96 ! " +
		"rtpstreampay ! fdsink fd=4 lindm-source. ! bin.( name=lindm-source-end message-forward=true " +
		"fakesink sync=false async=false enable-last-sample=false )"
	if got := strings.Join(args, " "); got != want {
		t.Fatalf("gstArguments =\n%s\nwant\n%s", got, want)
	}
	unknown := gstArguments(9, 0, 0, false)
	if !slices.Contains(unknown, "video/x-raw,framerate=15/1") || !slices.Contains(unknown, "path=9") {
		t.Fatalf("unknown-size arguments = %q", unknown)
	}
	// Every pipeline element is preflighted.
	for _, element := range gstElements {
		if !slices.Contains(args, element) && !slices.Contains(args, element+".(") {
			t.Errorf("element %s not in pipeline", element)
		}
	}
	modern := gstArguments(57, 3840, 2160, true)
	if !slices.Equal(modern[:5], []string{"-m", "pipewiresrc", "fd=3", "path=57", "on-disconnect=error"}) ||
		!slices.Equal(modern[5:], args[4:]) || cap(modern) != len(modern) || cap(args) != len(args) {
		t.Fatalf("disconnect policy arguments = %q; older arguments = %q", modern, args)
	}
}

// Rocky/AlmaLinux 9.8 (Mutter 40.9, PipeWire 1.4.11) ended capture_no_frames:
// damage frames shared one PTS, so videorate dropped them, and keepalive
// resends carried the absolute clock, so GstBaseSrc waited far ahead.
// The encoding branch after the zero-copy tee must re-stamp in running time
// at the encoder rate, and nothing may synchronise on source timestamps.
func TestGstArgumentsIgnoreSourceTimestamps(t *testing.T) {
	args := gstArguments(57, 1280, 800, false)
	var elements [][]string
	start := 1 // after -m
	for i := start; i <= len(args); i++ {
		if i == len(args) || args[i] == "!" {
			elements = append(elements, args[start:i])
			start = i + 1
		}
	}
	if len(elements) < 3 || elements[0][0] != "pipewiresrc" {
		t.Fatalf("pipeline elements = %q", elements)
	}
	for _, property := range elements[0][1:] {
		if name, _, _ := strings.Cut(property, "="); name != "fd" && name != "path" {
			t.Errorf("pipewiresrc property %q; its timestamps or keepalive must not be relied on", property)
		}
	}
	if !slices.Equal(elements[1], []string{"tee", "name=lindm-source", "lindm-source."}) {
		t.Errorf("element after source = %q, want zero-copy lifecycle tee", elements[1])
	}
	if !slices.Equal(elements[2], []string{"imagefreeze", "is-live=true", "allow-replace=true"}) {
		t.Errorf("encoding branch = %q, want live replacing imagefreeze", elements[2])
	}
	rate := fmt.Sprintf("video/x-raw,framerate=%d/1,width=1280,height=800", captureFramerate)
	if i := slices.IndexFunc(elements, func(e []string) bool { return slices.Equal(e, []string{rate}) }); i < 3 {
		t.Errorf("encoder rate caps %s at element %d, want after imagefreeze", rate, i)
	}
	for _, element := range elements {
		if element[0] == "videorate" {
			t.Errorf("videorate retimes from source timestamps: %q", element)
		}
	}
}

// debian12-arm64-dgx21-assistance-05 ended gst_element_missing:pipewiresrc with
// gstreamer1.0-pipewire 0.3.65 installed: GStreamer 1.22's --exists alone also
// demands plugin version >= 1.22. Every element is checked for existence only.
func TestGstExistsIgnoresPluginVersion(t *testing.T) {
	for _, element := range gstElements {
		args := gstExistsArguments(element)
		if !slices.Equal(args, []string{"--exists", "--atleast-version=0.0.0", element}) {
			t.Fatalf("gst-inspect arguments for %s = %q", element, args)
		}
	}
}

func TestWaitGstSourceEnd(t *testing.T) {
	const eos = `Got message #60 from element "lindm-source-end" (element): GstBinForwarded, message=(GstMessage)NULL;`
	for _, tc := range []struct {
		name, text string
		want       error
	}{
		{"source-eos", eos + "\n", errGstSourceEOS},
		{"startup-before-eos", "Setting pipeline to PLAYING ...\n" + eos + "\n", errGstSourceEOS},
		{"other-bin", strings.Replace(eos, "lindm-source-end", "other-bin", 1) + "\n", io.EOF},
		{"state-change", strings.Replace(eos, "(element)", "(state-changed)", 1) + "\n", io.EOF},
		{"negative-sequence", strings.Replace(eos, "#60", "#-1", 1) + "\n", io.EOF},
		{"overflow-sequence", strings.Replace(eos, "#60", "#4294967296", 1) + "\n", io.EOF},
		{"prefixed-device-text", "device text " + eos + "\n", io.EOF},
		{"trailing-device-text", eos + " device text\n", io.EOF},
		{"no-source-event", "Pipeline is live\n", io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := waitGstSourceEnd(iotest.OneByteReader(strings.NewReader(tc.text))); !errors.Is(err, tc.want) {
				t.Fatalf("source lifecycle error = %v, want %v", err, tc.want)
			}
		})
	}
	if err := waitGstSourceEnd(strings.NewReader(strings.Repeat("x", gstBusLineLimit+1) + "\n" + eos + "\n")); err == nil || errors.Is(err, errGstSourceEOS) || errors.Is(err, io.EOF) {
		t.Fatalf("oversized lifecycle message did not fail closed: %v", err)
	}
	readErr := errors.New("lifecycle reader failed")
	if err := waitGstSourceEnd(iotest.ErrReader(readErr)); !errors.Is(err, readErr) {
		t.Fatalf("reader error = %v, want %v", err, readErr)
	}
}
