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
