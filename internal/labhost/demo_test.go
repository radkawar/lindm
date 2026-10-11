package labhost

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDemoDirectoryConfinement(t *testing.T) {
	work := t.TempDir()
	for _, name := range []string{"org", "Org_12-demo", "1"} {
		path, err := DemoDirectory(work, name)
		if err != nil || path != filepath.Join(work, "demos", name) {
			t.Fatalf("valid name %q: %s %v", name, path, err)
		}
	}
	for _, name := range []string{"", ".", "..", "../org", "/org", "org/name", "org name", "-org", "org\n", strings.Repeat("a", 33)} {
		if _, err := DemoDirectory(work, name); err == nil {
			t.Fatalf("accepted unsafe name %q", name)
		}
	}
	if _, err := DemoDirectory("relative", "org"); err == nil {
		t.Fatal("accepted ambiguous work directory")
	}
}
