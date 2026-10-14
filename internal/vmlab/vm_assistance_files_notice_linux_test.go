// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import "testing"

// GNOME wraps a long file name at its hyphen (layers-fedora44-files-04).
func TestFileNoticeVisibleReadsAWrappedFileName(t *testing.T) {
	const name = "lindm-file-f3fc076d537ca77acc4bb648.txt"
	wrapped := "lindm Just now\nReceive a file from your support operator\nassistance-operator offers lindm-file-\nf3fc076d537ca77acc4bb648.txt (32768 bytes, text/plain). Save this\nfile in your Downloads folder? Remote input and clipboard access\nare paused.\nSave to Downloads Decline Stop\n"
	if !fileNoticeVisible(wrapped, "assistance-operator", name, false) {
		t.Fatal("wrapped consent was not read")
	}
	for _, ocr := range []string{
		"Receive a file from your support operator assistance-operator offers lindm-file-0000.txt Downloads",
		"Receive a file from your support operator other-operator offers " + name + " Downloads",
		"assistance-operator offers " + name + " Downloads",
	} {
		if fileNoticeVisible(ocr, "assistance-operator", name, false) {
			t.Fatalf("%q qualified", ocr)
		}
	}
}

// Tesseract misreads the hex name of a clearly shown notice: 1/l and 0/O
// confusions (layers-fedora44-files-07), a 1 split into "1l" (-11), a stray
// "/" (-15), and inserted "O" and "7" (-17). A different random name never
// qualifies.
func TestFileNoticeVisibleToleratesOCRNameErrors(t *testing.T) {
	other := "lindm-file-9d0b6c2e5f7a8b1c3d4e6f70.txt"
	for _, c := range []struct {
		name, ocr string
		completed bool
	}{
		{"lindm-file-fe6e1ffc079dc2b1b8a90b0c.txt", "lindm Just now\nReceive a file from your support operator\nassistance-operator offers lindm-file-fe6elffcO79dc2b1b8a90b0c.txt\n(32768 bytes, text/plain). Save this file in your Downloads folder?\n", false},
		{"lindm-file-30ff20cc1dd66addd417a652.txt", "lindm Just now\nReceive a file from your support operator\nassistance-operator offers lindm-\nfile-30ff20cc1ldd66addd417a652.txt (32768 bytes, text/plain). Save\nthis file in your Downloads folder?\n", false},
		{"lindm-file-3af5d212baf136da753e80a4.txt", "Remote assistance in progress\nassistance-operator is viewing\nand controlling your screen. lindm file received assistance-\noperator sent lindm-file-3af5d212baf1l36da/753e80a4.txt. The file\nwas Saved in your Downloads folder.\n", true},
		{"lindm-file-28b34c80acc0e75cdd92c892.txt", "Remote assistance in progress\nassistance-operator is viewing and controlling your screen. lindm\nfile received assistance-operator sent lindm-\nfile-28b34c80accO0e75cdd92c8972.txt. The file was saved in your\nDownloads folder.\n", true},
	} {
		if !fileNoticeVisible(c.ocr, "assistance-operator", c.name, c.completed) {
			t.Errorf("%s was not read from %q", c.name, c.ocr)
		}
		if fileNoticeVisible(c.ocr, "assistance-operator", other, c.completed) {
			t.Errorf("a different file name qualified against %q", c.ocr)
		}
	}
}

func TestOCRContainsApproxBoundsEdits(t *testing.T) {
	for _, c := range []struct {
		text, needle string
		edits        int
		want         bool
	}{
		{"xxabcdefyy", "abcdef", 0, true},
		{"xxabXcdefyy", "abcdef", 1, true},
		{"xxabXcdefyy", "abcdef", 0, false},
		{"xxacdefyy", "abcdef", 1, true},
		{"xxaXcYeZyy", "abcdef", 2, false},
		{"", "abc", 3, true},
		{"", "abc", 2, false},
	} {
		if got := ocrContainsApprox(c.text, c.needle, c.edits); got != c.want {
			t.Errorf("ocrContainsApprox(%q, %q, %d) = %t", c.text, c.needle, c.edits, got)
		}
	}
}
