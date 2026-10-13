//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"os"
	"path/filepath"
	"testing"
)

func TestAssistanceSetupRetainsNativeStreamsAndExit(t *testing.T) {
	for _, test := range []struct {
		name        string
		exit        int
		failure     error
		wantFailure bool
	}{
		{name: "successful package progress on stderr"},
		{name: "package failure", exit: 42, wantFailure: true},
		{name: "transport failure is not zero-exit success", failure: errors.New("transport interrupted"), wantFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence, dir := newTestAssistanceEvidence(t)
			result := new(VMAssistanceResult)
			process := guestCommandResult{ExitCode: test.exit, Stdout: []byte("package output\n"), Stderr: []byte("native progress or diagnostic\n")}
			err := recordAssistanceSetup(evidence, result, "fixture-prerequisites", "native installer", process, test.failure)
			if (err != nil) != test.wantFailure {
				t.Fatalf("setup error = %v", err)
			}
			if test.failure != nil && !errors.Is(err, test.failure) {
				t.Fatalf("transport failure lost: %v", err)
			}
			if len(result.Journals) != 1 {
				t.Fatalf("journals = %d", len(result.Journals))
			}
			if err := verifyAssistanceEvidence(dir, result); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, result.Journals[0].Path))
			if err != nil {
				t.Fatal(err)
			}
			var recorded struct {
				Command string `json:"command"`
				Exit    int    `json:"exit_code"`
				Stdout  string `json:"stdout"`
				Stderr  string `json:"stderr"`
				Failure string `json:"failure"`
			}
			if err := json.Unmarshal(data, &recorded); err != nil {
				t.Fatal(err)
			}
			if recorded.Command != "native installer" || recorded.Exit != test.exit || recorded.Stdout != string(process.Stdout) || recorded.Stderr != string(process.Stderr) {
				t.Fatalf("native evidence changed: %+v", recorded)
			}
			if (recorded.Failure != "") != (test.failure != nil) {
				t.Fatalf("transport evidence = %q", recorded.Failure)
			}
		})
	}
}

func TestAssistanceHeadMarkerRequiresCurrentNoncePixels(t *testing.T) {
	const nonce = "0123456789abcdef10325476"
	for _, head := range []byte{0, 1} {
		img := assistanceMarkerTestImage(head)
		if got := assistanceHeadMarker(img, nonce); got != int(head) {
			t.Fatalf("head %d decoded as %d", head, got)
		}
		if got := assistanceHeadMarker(img, "1123456789abcdef10325476"); got != -1 {
			t.Fatalf("stale head %d accepted as %d", head, got)
		}
		for _, invalid := range []string{"", "0123456789abcdef1032547", "g123456789abcdef10325476"} {
			if got := assistanceHeadMarker(img, invalid); got != -1 {
				t.Fatalf("invalid nonce %q accepted", invalid)
			}
		}
	}
	if got := assistanceHeadMarker(assistanceMarkerTestImage(2), nonce); got != -1 {
		t.Fatalf("invalid head accepted: %d", got)
	}
	for _, background := range []color.RGBA{
		{R: 30, G: 55, B: 180, A: 255},
		{R: 204, G: 13, B: 13, A: 255},
		{A: 255},
		{R: 255, G: 255, B: 255, A: 255},
	} {
		img := image.NewRGBA(image.Rect(0, 0, 1024, 768))
		draw.Draw(img, img.Bounds(), image.NewUniform(background), image.Point{}, draw.Src)
		if got := assistanceHeadMarker(img, nonce); got != -1 {
			t.Fatalf("solid background %+v accepted as %d", background, got)
		}
	}
	for _, img := range []*image.RGBA{nil, image.NewRGBA(image.Rect(0, 0, 100, 100))} {
		if got := assistanceHeadMarker(img, nonce); got != -1 {
			t.Fatalf("insufficient pixels accepted as %d", got)
		}
	}
	img := assistanceMarkerTestImage(0)
	// Cover one cell with ambiguous gray: missing marker pixels must not be
	// inferred from the expected nonce, the neighboring cell or the head.
	draw.Draw(img, image.Rect(110, 510, 125, 526), image.NewUniform(color.RGBA{R: 128, G: 128, B: 128, A: 255}), image.Point{}, draw.Src)
	if got := assistanceHeadMarker(img, nonce); got != -1 {
		t.Fatalf("corrupt marker accepted as %d", got)
	}
}

func assistanceMarkerTestImage(head byte) *image.RGBA {
	// Independent fixed payload and rendered rectangles, not a native witness.
	payload := [...]byte{0xa7, head, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76}
	img := image.NewRGBA(image.Rect(0, 0, 1024, 768))
	for index, b := range payload {
		for bit := range 8 {
			offset := index*8 + bit
			for half := range 2 {
				one := (b>>(7-bit))&1 != 0
				shade := uint8(35)
				if one == (half == 0) {
					shade = 220
				}
				column, row := offset%14*2+half, offset/14
				rect := image.Rect(
					int(1024*(0.1+float64(column)*0.8/28)),
					int(768*(0.65+float64(row)*0.28/8)),
					int(1024*(0.1+float64(column+1)*0.8/28)),
					int(768*(0.65+float64(row+1)*0.28/8)),
				)
				draw.Draw(img, rect, image.NewUniform(color.RGBA{R: shade, G: shade, B: shade, A: 255}), image.Point{}, draw.Src)
			}
		}
	}
	return img
}
