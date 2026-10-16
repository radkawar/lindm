// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"bytes"
	"image"
	"strconv"
	"strings"
	"unicode"
)

// ocrWord is one tesseract word with its box in screendump coordinates.
type ocrWord struct {
	text string
	// line identifies tesseract's block, paragraph and line within one pass.
	line [3]int
	// pass is the preprocessing pass that read the word.
	pass int
	box  image.Rectangle
}

// parseTesseractTSV reads tesseract's tsv output for an image that is the
// screendump region at origin enlarged by scale. Only word rows with text
// are kept; malformed rows are skipped rather than guessed.
func parseTesseractTSV(out []byte, origin image.Point, scale int) []ocrWord {
	var words []ocrWord
	for row := range bytes.SplitSeq(out, []byte("\n")) {
		fields := strings.Split(strings.TrimRight(string(row), "\r"), "\t")
		if len(fields) != 12 || fields[0] != "5" {
			continue
		}
		numbers := make([]int, 9)
		valid := true
		for i := range numbers {
			n, err := strconv.Atoi(fields[i+1])
			if err != nil || n < 0 {
				valid = false
				break
			}
			numbers[i] = n
		}
		text := strings.TrimSpace(fields[11])
		if !valid || text == "" || scale <= 0 {
			continue
		}
		left, top, width, height := numbers[5], numbers[6], numbers[7], numbers[8]
		box := image.Rect(left/scale, top/scale, (left+width+scale-1)/scale, (top+height+scale-1)/scale).Add(origin)
		words = append(words, ocrWord{text: text, line: [3]int{numbers[1], numbers[2], numbers[3]}, box: box})
	}
	return words
}

// ocrToken drops surrounding punctuation tesseract attaches to UI labels
// (button mnemonics, ellipses, question marks); case is kept, so body text
// such as "allow the operator" never matches the "Allow" button.
func ocrToken(text string) string {
	return strings.TrimFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

// ocrLowest finds label (one or more words on one tesseract line) and
// returns the box of its lowest, then rightmost, occurrence: action buttons
// sit at the bottom of popups and dialogs, below any body text.
func ocrLowest(words []ocrWord, label string) (image.Rectangle, bool) {
	want := strings.Fields(label)
	if len(want) == 0 {
		return image.Rectangle{}, false
	}
	var best image.Rectangle
	found := false
	for i := range words {
		if i+len(want) > len(words) {
			break
		}
		box := words[i].box
		match := true
		for j, token := range want {
			word := words[i+j]
			if ocrToken(word.text) != token || word.line != words[i].line || word.pass != words[i].pass {
				match = false
				break
			}
			box = box.Union(word.box)
		}
		if !match {
			continue
		}
		if !found || box.Min.Y > best.Min.Y || (box.Min.Y == best.Min.Y && box.Min.X > best.Min.X) {
			best, found = box, true
		}
	}
	return best, found
}

// ocrActionPoint rests in a button's padding below its visible label. COSMIC
// includes the pointer in QMP captures; hovering the glyph centre obscured
// "Allow" and made the mandatory hovered-label re-read fail (cell-04).
func ocrActionPoint(label image.Rectangle) image.Point {
	return image.Pt(label.Min.X+label.Dx()/2, label.Max.Y+4)
}

// The COSMIC output picker overlays its connector label at the bottom of the
// thumbnail. Its clickable image is above that label, not in button padding
// below it. Three observed glyph heights leave room for the native hand cursor
// extending below its hotspot, so the mandatory hovered-label re-read stays clear.
func ocrSourcePoint(label image.Rectangle) image.Point {
	return image.Pt(label.Min.X+label.Dx()/2, label.Min.Y-3*label.Dy())
}

// ocrClearDarkBorder removes only black components joined to the edge of a
// binary crop. It lets OCR see dark glyphs enclosed by a bright accent button
// without mistaking that whole filled control for an image. Existing OCR passes
// retain light-on-dark labels. Scanline traversal reuses the mask in place and
// queues spans rather than every background pixel.
func ocrClearDarkBorder(mask *image.Gray) bool {
	width, height := mask.Rect.Dx(), mask.Rect.Dy()
	if width == 0 || height == 0 {
		return false
	}
	stack := make([]image.Point, 0, 32)
	changed := false
	clear := func(x, y int) {
		stack = append(stack, image.Pt(x, y))
		for len(stack) != 0 {
			point := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			row := mask.Pix[point.Y*mask.Stride : point.Y*mask.Stride+width]
			if row[point.X] != 0 {
				continue
			}
			left, right := point.X, point.X+1
			for left > 0 && row[left-1] == 0 {
				left--
			}
			for right < width && row[right] == 0 {
				right++
			}
			for x := left; x < right; x++ {
				row[x] = 255
			}
			changed = true
			for _, y := range [2]int{point.Y - 1, point.Y + 1} {
				if y < 0 || y >= height {
					continue
				}
				adjacent := mask.Pix[y*mask.Stride : y*mask.Stride+width]
				for x := left; x < right; {
					if adjacent[x] != 0 {
						x++
						continue
					}
					stack = append(stack, image.Pt(x, y))
					for x < right && adjacent[x] == 0 {
						x++
					}
				}
			}
		}
	}
	for x := range width {
		if mask.Pix[x] == 0 {
			clear(x, 0)
		}
		if mask.Pix[(height-1)*mask.Stride+x] == 0 {
			clear(x, height-1)
		}
	}
	for y := 1; y < height-1; y++ {
		if mask.Pix[y*mask.Stride] == 0 {
			clear(0, y)
		}
		if mask.Pix[y*mask.Stride+width-1] == 0 {
			clear(width-1, y)
		}
	}
	return changed
}

// ocrLowContrastMask rebinarizes a retained luma crop into the existing mask,
// with matching dimensions but independently strided/originated storage.
// It schedules OCR only when a lower threshold changes pixel classes and leaves
// both foreground and background; uniform or identical masks add no evidence.
func ocrLowContrastMask(mask, luma *image.Gray, threshold, previous uint8) bool {
	reclassified, dark, light := false, false, false
	width := luma.Rect.Dx()
	for y := range luma.Rect.Dy() {
		source := luma.Pix[y*luma.Stride : y*luma.Stride+width]
		target := mask.Pix[y*mask.Stride : y*mask.Stride+width]
		for x, value := range source {
			if value > threshold {
				target[x] = 255
				light = true
				reclassified = reclassified || value <= previous
			} else {
				target[x] = 0
				dark = true
			}
		}
	}
	return reclassified && dark && light
}
