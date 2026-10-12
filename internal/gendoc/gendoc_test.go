package gendoc

import "testing"

func TestBlankEmptiesEveryGeneratedBlock(t *testing.T) {
	doc := []byte("# Title\n\n<!-- BEGIN GENERATED a -->\n\n| x |\n\n<!-- END GENERATED a -->\n\nprose\n<!-- BEGIN GENERATED b -->\nold\n<!-- END GENERATED b -->\ntail\n")
	want := "# Title\n\n<!-- BEGIN GENERATED a -->\n\n<!-- END GENERATED a -->\n\nprose\n<!-- BEGIN GENERATED b -->\n\n<!-- END GENERATED b -->\ntail\n"
	if got := string(Blank(doc)); got != want {
		t.Fatalf("Blank = %q, want %q", got, want)
	}
	if got := Blank(Blank(doc)); string(got) != want {
		t.Fatalf("Blank is not idempotent: %q", got)
	}
	// Whatever the generated content, the blanked documents agree.
	other, err := Replace(doc, "a", "| y |\n| z |")
	if err != nil {
		t.Fatal(err)
	}
	if string(Blank(other)) != want {
		t.Fatal("blanked documents differ by generated content")
	}
	// A marker quoted inside a line is prose, not a block.
	quoted := "Write `<!-- BEGIN GENERATED x -->` and\n`<!-- END GENERATED x -->` around it.\n<!-- END GENERATED x -->\n"
	for _, plain := range []string{"no markers\n", "<!-- BEGIN GENERATED c -->\nunterminated\n", quoted} {
		if got := string(Blank([]byte(plain))); got != plain {
			t.Fatalf("Blank changed %q to %q", plain, got)
		}
	}
}
