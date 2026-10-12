package gendoc

import (
	"strings"
	"testing"
)

func TestBlankEmptiesEveryGeneratedBlock(t *testing.T) {
	doc := []byte("# Title\n\n<!-- BEGIN GENERATED a -->\n\n| x |\n\n<!-- END GENERATED a -->\n\nprose\n<!-- BEGIN GENERATED b -->\nold\n<!-- END GENERATED b -->\ntail\n")
	want := "# Title\n\n<!-- BEGIN GENERATED a -->\n\n\n\n<!-- END GENERATED a -->\n\nprose\n<!-- BEGIN GENERATED b -->\n\n\n\n<!-- END GENERATED b -->\ntail\n"
	if got := string(Blank(doc, "a", "b")); got != want {
		t.Fatalf("Blank = %q, want %q", got, want)
	}
	if got := Blank(Blank(doc, "a", "b"), "a", "b"); string(got) != want {
		t.Fatalf("Blank is not idempotent: %q", got)
	}
	// Whatever the generated content, the blanked documents agree.
	other, err := Replace(doc, "a", "| y |\n| z |")
	if err != nil {
		t.Fatal(err)
	}
	if string(Blank(other, "a", "b")) != want {
		t.Fatal("blanked documents differ by generated content")
	}
	// Only named blocks: a marker quoted elsewhere (an example in prose or
	// code) is not generated content.
	if got := string(Blank(doc, "a")); !strings.Contains(got, "old") {
		t.Fatalf("Blank emptied an unnamed block: %q", got)
	}
	for _, plain := range []string{"no markers\n", "<!-- BEGIN GENERATED c -->\nunterminated\n"} {
		if got := string(Blank([]byte(plain), "c")); got != plain {
			t.Fatalf("Blank changed %q to %q", plain, got)
		}
	}
}
