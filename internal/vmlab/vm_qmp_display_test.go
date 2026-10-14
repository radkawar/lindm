// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func TestDecodeScreendumpPPMRoundTripsToPNG(t *testing.T) {
	// QEMU's ppm_save writes "P6\n<w> <h>\n255\n" followed by RGB rows.
	raw := []byte("P6\n3 2\n255\n")
	pixels := [][3]byte{{255, 0, 0}, {0, 255, 0}, {0, 0, 255}, {10, 20, 30}, {200, 100, 50}, {0, 0, 0}}
	for _, p := range pixels {
		raw = append(raw, p[:]...)
	}
	img, err := decodeScreendumpPPM(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds() != image.Rect(0, 0, 3, 2) {
		t.Fatalf("bounds = %v", img.Bounds())
	}
	var encoded bytes.Buffer
	if err := encodeScreendumpPNG(&encoded, img); err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range pixels {
		got, ok := color.RGBAModel.Convert(decoded.At(i%3, i/3)).(color.RGBA)
		if !ok || got != (color.RGBA{p[0], p[1], p[2], 0xff}) {
			t.Fatalf("pixel %d = %v, want %v", i, got, p)
		}
	}
}

func TestDecodeScreendumpPPMAcceptsHeaderComments(t *testing.T) {
	raw := append([]byte("P6\n# qemu\n1 1\n255\n"), 1, 2, 3)
	img, err := decodeScreendumpPPM(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := img.RGBAAt(0, 0); got != (color.RGBA{1, 2, 3, 0xff}) {
		t.Fatalf("pixel = %v", got)
	}
}

func TestDecodeScreendumpPPMRejectsMalformedInput(t *testing.T) {
	for name, raw := range map[string]string{
		"ascii ppm":      "P3\n1 1\n255\n0 0 0\n",
		"16-bit samples": "P6\n1 1\n65535\n" + strings.Repeat("\x00", 6),
		"zero width":     "P6\n0 1\n255\n",
		"oversized":      "P6\n100000 100000\n255\n",
		"short raster":   "P6\n2 2\n255\n" + strings.Repeat("\x00", 11),
		"trailing data":  "P6\n1 1\n255\n" + strings.Repeat("\x00", 4),
		"truncated":      "P6\n1",
		"long token":     "P6\n" + strings.Repeat("9", 20) + " 1\n255\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeScreendumpPPM(strings.NewReader(raw)); err == nil {
				t.Fatal("malformed screendump accepted")
			}
		})
	}
}
