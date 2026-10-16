// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"image"
	"testing"
)

// A Plasma consent popup as tesseract reports it: body text that mentions
// "allow" and "Decline here" above the real Allow/Decline buttons.
const plasmaPopupTSV = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n" +
	"1\t1\t0\t0\t0\t0\t0\t0\t1280\t1000\t-1\t\n" +
	"5\t1\t1\t1\t1\t1\t40\t20\t120\t30\t95\tRemote\n" +
	"5\t1\t1\t1\t1\t2\t170\t20\t200\t30\t95\tassistance\n" +
	"5\t1\t2\t1\t1\t1\t40\t80\t60\t30\t91\tlets\n" +
	"5\t1\t2\t1\t1\t2\t110\t80\t60\t30\t91\tyou\n" +
	"5\t1\t2\t1\t1\t3\t180\t80\t80\t30\t91\tallow\n" +
	"5\t1\t2\t1\t1\t4\t270\t80\t130\t30\t90\tDecline\n" +
	"5\t1\t3\t1\t1\t1\t60\t400\t100\t36\t96\tAllow\n" +
	"5\t1\t4\t1\t1\t1\t300\t400\t140\t36\t96\tDecline\n" +
	"5\t1\t5\t1\t1\t1\t40\t500\t80\t30\tbad\tShare\n" +
	"5\t1\t5\t1\t1\t2\t130\t500\t80\t30\t90\tthis\n" +
	"5\t1\t5\t1\t1\t3\t220\t500\t120\t30\t90\tscreen?\n" +
	"5\t1\t6\t1\t1\t1\tx\t500\t80\t30\t90\tbroken\n"

func TestOCRLocatesLowestCaseExactLabel(t *testing.T) {
	words := parseTesseractTSV([]byte(plasmaPopupTSV), image.Pt(640, 100), 2)
	if len(words) != 11 {
		t.Fatalf("parsed %d words", len(words))
	}
	allow, ok := ocrLowest(words, "Allow")
	if !ok || allow != image.Rect(670, 300, 720, 318) {
		t.Fatalf("Allow = %v %t", allow, ok)
	}
	// The button row, not the body's "Decline here".
	if decline, ok := ocrLowest(words, "Decline"); !ok || decline.Min.Y != 300 {
		t.Fatalf("Decline = %v %t", decline, ok)
	}
	if phrase, ok := ocrLowest(words, "Share this screen"); !ok || phrase != image.Rect(660, 350, 810, 365) {
		t.Fatalf("phrase = %v %t", phrase, ok)
	}
	for _, absent := range []string{"Stop", "allow viewing", "Remote assistance request", ""} {
		if box, ok := ocrLowest(words, absent); ok {
			t.Fatalf("%q matched %v", absent, box)
		}
	}
	// Two preprocessing passes are concatenated; a phrase never spans them.
	plain, binary := parseTesseractTSV([]byte(plasmaPopupTSV), image.Pt(640, 100), 2), parseTesseractTSV([]byte(plasmaPopupTSV), image.Pt(640, 100), 2)
	for i := range binary {
		binary[i].pass = 1
	}
	joined := append(plain[:len(plain)-2], binary[len(binary)-2:]...)
	if box, ok := ocrLowest(joined, "Share this screen"); ok {
		t.Fatalf("phrase joined two passes at %v", box)
	}
}

func TestOCRActionPointLeavesVisibleGlyphsUnobscured(t *testing.T) {
	// Native COSMIC's Allow label sits above the button's lower padding.
	label := image.Rect(1003, 261, 1040, 274)
	point := ocrActionPoint(label)
	if point.In(label) || !point.In(image.Rect(987, 251, 1056, 285)) {
		t.Fatalf("hover point %v obscures %v or leaves its button", point, label)
	}
	if point.X != label.Min.X+label.Dx()/2 || point.Y != label.Max.Y+4 {
		t.Fatalf("hover point is not derived from the observed label: %v", point)
	}
}

func TestOCRSourcePointStaysInsideBottomLabelledThumbnail(t *testing.T) {
	// The source label overlays the thumbnail's bottom, unlike action buttons.
	label := image.Rect(606, 598, 670, 619)
	thumbnail := image.Rect(387, 305, 893, 620)
	point := ocrSourcePoint(label)
	if point.In(label) || !point.In(thumbnail) || point.Y >= label.Min.Y {
		t.Fatalf("source point %v obscures glyphs or leaves native thumbnail", point)
	}
	// Native QMP captures contain the entire hand cursor, not only its hotspot.
	cursor := image.Rect(0, 0, 24, 32).Add(point)
	if cursor.Overlaps(label) {
		t.Fatalf("source hover cursor %v obscures native label %v", cursor, label)
	}
	if ocrActionPoint(label).In(thumbnail) {
		t.Fatal("regression fixture does not expose below-thumbnail action padding")
	}
}

func TestOCRClearDarkBorderPreservesEnclosedGlyphsAndCropBounds(t *testing.T) {
	// A strided, nonzero-origin crop of a bright button in dark background.
	backing := image.NewGray(image.Rect(0, 0, 14, 9))
	for i := range backing.Pix {
		backing.Pix[i] = 73
	}
	mask, ok := backing.SubImage(image.Rect(2, 1, 12, 8)).(*image.Gray)
	if !ok {
		t.Fatal("grayscale crop changed image type")
	}
	pattern := []string{
		"##########",
		"##......##",
		"#........#",
		"#..##....#",
		"#...#....#",
		"##......##",
		"##########",
	}
	for y, row := range pattern {
		for x, pixel := range row {
			value := uint8(255)
			if pixel == '#' {
				value = 0
			}
			mask.Pix[y*mask.Stride+x] = value
		}
	}
	pixels := &mask.Pix[0]
	if !ocrClearDarkBorder(mask) || pixels != &mask.Pix[0] {
		t.Fatal("background was not cleared in place")
	}
	for y := range backing.Rect.Dy() {
		for x := range backing.Rect.Dx() {
			want := uint8(73)
			if image.Pt(x, y).In(mask.Rect) {
				want = 255
				if (y == 4 && (x == 5 || x == 6)) || (y == 5 && x == 6) {
					want = 0
				}
			}
			if got := backing.Pix[backing.PixOffset(x, y)]; got != want {
				t.Fatalf("pixel (%d,%d)=%d, want %d: lost enclosed glyph or escaped crop", x, y, got, want)
			}
		}
	}
	if ocrClearDarkBorder(mask) {
		t.Fatal("unchanged mask would schedule redundant OCR")
	}
}

func TestOCRClearDarkBorderHandlesEmptyAndSingleRowOrColumn(t *testing.T) {
	for _, bounds := range []image.Rectangle{
		image.Rect(0, 0, 0, 0), image.Rect(0, 0, 1, 1),
		image.Rect(0, 0, 9, 1), image.Rect(0, 0, 1, 9),
	} {
		mask := image.NewGray(bounds)
		if changed := ocrClearDarkBorder(mask); changed == bounds.Empty() {
			t.Errorf("bounds %v: changed=%t", bounds, changed)
		}
		for _, pixel := range mask.Pix {
			if pixel != 255 {
				t.Fatalf("bounds %v retained edge-connected black pixel", bounds)
			}
		}
	}
}

func TestOCRLowContrastMaskPreservesFaintGlyphsAndStridedCropBounds(t *testing.T) {
	sourceBacking := image.NewGray(image.Rect(0, 0, 9, 6))
	for i := range sourceBacking.Pix {
		sourceBacking.Pix[i] = 211
	}
	source, ok := sourceBacking.SubImage(image.Rect(2, 1, 6, 3)).(*image.Gray)
	if !ok {
		t.Fatal("source crop did not retain gray storage")
	}
	levels := []uint8{72, 120, 180, 255, 0, 100, 150, 151}
	for y := range source.Rect.Dy() {
		for x := range source.Rect.Dx() {
			source.Pix[y*source.Stride+x] = levels[y*source.Rect.Dx()+x]
		}
	}
	maskBacking := image.NewGray(image.Rect(0, 0, 10, 7))
	for i := range maskBacking.Pix {
		maskBacking.Pix[i] = 73
	}
	mask, ok := maskBacking.SubImage(image.Rect(3, 2, 7, 4)).(*image.Gray)
	if !ok {
		t.Fatal("mask crop did not retain gray storage")
	}
	if !ocrLowContrastMask(mask, source, 100, 150) {
		t.Fatal("faint glyph 120 over fill 72 did not schedule contrast OCR")
	}
	for y := range maskBacking.Rect.Dy() {
		for x := range maskBacking.Rect.Dx() {
			want := uint8(73)
			if image.Pt(x, y).In(mask.Rect) {
				value := levels[(y-mask.Rect.Min.Y)*mask.Rect.Dx()+x-mask.Rect.Min.X]
				want = 0
				if value > 100 {
					want = 255
				}
			}
			if got := maskBacking.Pix[maskBacking.PixOffset(x, y)]; got != want {
				t.Fatalf("mask (%d,%d)=%d, want %d: lost faint glyph or escaped crop", x, y, got, want)
			}
		}
	}
	for y := range sourceBacking.Rect.Dy() {
		for x := range sourceBacking.Rect.Dx() {
			want := uint8(211)
			if image.Pt(x, y).In(source.Rect) {
				want = levels[(y-source.Rect.Min.Y)*source.Rect.Dx()+x-source.Rect.Min.X]
			}
			if got := sourceBacking.Pix[sourceBacking.PixOffset(x, y)]; got != want {
				t.Fatalf("retained plain crop changed at (%d,%d)", x, y)
			}
		}
	}
}

func TestOCRLowContrastMaskSkipsUniformOrUnchangedClasses(t *testing.T) {
	for _, levels := range [][]uint8{nil, {0}, {72}, {120}, {200}, {72, 200}, {120, 140}, {0, 255}} {
		source := image.NewGray(image.Rect(0, 0, len(levels), 1))
		copy(source.Pix, levels)
		mask := image.NewGray(source.Rect)
		if ocrLowContrastMask(mask, source, 100, 150) {
			t.Errorf("uniform/unchanged levels %v would schedule redundant OCR", levels)
		}
	}
}
