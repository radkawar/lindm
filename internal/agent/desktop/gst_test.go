package desktop

import (
	"slices"
	"strings"
	"testing"
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
	args := gstArguments(57, 3840, 2160)
	want := "-q pipewiresrc fd=3 path=57 keepalive-time=500 ! videorate ! videoconvert ! videoscale ! " +
		"video/x-raw,framerate=15/1,width=1920,height=1080 ! vp8enc deadline=1 cpu-used=8 end-usage=cbr " +
		"target-bitrate=2500000 keyframe-max-dist=30 error-resilient=default ! rtpvp8pay mtu=1200 pt=96 ! " +
		"rtpstreampay ! fdsink fd=1"
	if got := strings.Join(args, " "); got != want {
		t.Fatalf("gstArguments =\n%s\nwant\n%s", got, want)
	}
	unknown := gstArguments(9, 0, 0)
	if !slices.Contains(unknown, "video/x-raw,framerate=15/1") || !slices.Contains(unknown, "path=9") {
		t.Fatalf("unknown-size arguments = %q", unknown)
	}
	// Every pipeline element is preflighted.
	for _, element := range gstElements {
		if !slices.Contains(args, element) {
			t.Errorf("element %s not in pipeline", element)
		}
	}
}

func TestTailBufferKeepsLastBytes(t *testing.T) {
	buffer := &tailBuffer{limit: 8}
	for _, chunk := range []string{"abc", "defgh", "ijk", "0123456789xyz"} {
		if n, err := buffer.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if got := buffer.String(); got != "56789xyz" {
		t.Fatalf("tail = %q, want 56789xyz", got)
	}
	if n, err := buffer.Write([]byte("AB")); err != nil || n != 2 || buffer.String() != "789xyzAB" {
		t.Fatalf("tail after small write = %q", buffer.String())
	}
}
