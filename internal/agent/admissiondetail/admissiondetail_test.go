package admissiondetail

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

var errSentinel = errors.New("sentinel")

func TestWrapPreservesClassificationAndDetail(t *testing.T) {
	err := fmt.Errorf("outer: %w", Wrap(fmt.Errorf("inner: %w", errSentinel), "existing_file"))
	if !errors.Is(err, errSentinel) {
		t.Fatal("errors.Is lost the sentinel")
	}
	if got := Of(err); got != "existing_file" {
		t.Fatalf("Of = %q", got)
	}
	if err.Error() != "outer: inner: sentinel" {
		t.Fatalf("Error = %q", err.Error())
	}
}

func TestWrapAsTransparent(t *testing.T) {
	err := Wrap(&fs.PathError{Op: "open", Path: "/x", Err: fs.ErrNotExist}, "native_tool_missing")
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("errors.As/Is not transparent")
	}
}

func TestOfReturnsOutermostDetail(t *testing.T) {
	err := Wrap(Wrap(errSentinel, "inner_detail"), "outer_detail")
	if got := Of(err); got != "outer_detail" {
		t.Fatalf("Of = %q", got)
	}
	if got := Of(errSentinel); got != "" {
		t.Fatalf("Of(plain) = %q", got)
	}
	if got := Of(nil); got != "" {
		t.Fatalf("Of(nil) = %q", got)
	}
}

func TestWrapRejectsInvalidDetail(t *testing.T) {
	for _, detail := range []string{"", "Upper", "1abc", "has-dash", "has space", "a" + strings.Repeat("b", 64)} {
		if got := Wrap(errSentinel, detail); got != errSentinel {
			t.Fatalf("Wrap(%q) changed err", detail)
		}
	}
	if Wrap(nil, "ok") != nil {
		t.Fatal("Wrap(nil) not nil")
	}
	if got := Of(Wrap(errSentinel, "a"+strings.Repeat("b", 63))); len(got) != 64 {
		t.Fatalf("64-byte detail rejected: %q", got)
	}
}
