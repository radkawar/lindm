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
