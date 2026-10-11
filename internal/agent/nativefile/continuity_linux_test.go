//go:build linux

package nativefile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestNativeContinuityAllowsOnlySameGenerationContentDrift(t *testing.T) {
	path, template := nativeFixture(t)
	if err := os.WriteFile(path, []byte("before"), 0644); err != nil {
		t.Fatal(err)
	}
	before, identity, err := CaptureWithContinuity(path, template)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("in-place edit"), 0644); err != nil {
		t.Fatal(err)
	}
	after, edited, err := CaptureWithContinuity(path, template)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(identity, edited) || bytes.Equal(before.GetManagedFileContent(), after.GetManagedFileContent()) {
		t.Fatal("content drift lost native generation continuity")
	}
	old := path + ".old"
	if err := os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("in-place edit"), 0644); err != nil {
		t.Fatal(err)
	}
	_, replaced, err := CaptureWithContinuity(path, template)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(edited.GetInodeGenerationSha256(), replaced.GetInodeGenerationSha256()) {
		t.Fatal("new file generation inherited custody")
	}
	parent := filepath.Dir(path)
	oldParent := parent + ".old"
	if err := os.Rename(parent, oldParent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(oldParent); err != nil {
			t.Error(err)
		}
	})
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(oldParent, filepath.Base(path)), path); err != nil {
		t.Fatal(err)
	}
	_, moved, err := CaptureWithContinuity(path, template)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replaced.GetInodeGenerationSha256(), moved.GetInodeGenerationSha256()) || bytes.Equal(replaced.GetAncestryGenerationSha256(), moved.GetAncestryGenerationSha256()) {
		t.Fatal("same file under a replacement ancestor inherited ancestry custody")
	}
}
