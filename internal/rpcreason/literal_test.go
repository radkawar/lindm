package rpcreason

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestHeaderLiteralOnlyHere keeps the reason header behind Header, Error, Set
// and Get so servers, agents and the lab cannot drift to their own spelling.
func TestHeaderLiteralOnlyHere(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	literal := strconv.Quote(Header)
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path == self {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(body), literal) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s spells %s; use rpcreason", rel, literal)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
