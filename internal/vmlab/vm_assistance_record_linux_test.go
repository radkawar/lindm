//go:build linux

package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newTestAssistanceEvidence(t *testing.T) (*assistanceEvidence, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	evidence, err := newAssistanceEvidence(dir)
	if err != nil {
		t.Fatal(err)
	}
	return evidence, dir
}

func TestAssistanceEvidenceBindsEveryArtifact(t *testing.T) {
	evidence, dir := newTestAssistanceEvidence(t)
	shot, err := evidence.write("guest control consent", "guest-control-consent-prompt.png", []byte("png bytes"))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("png bytes"))
	if shot.SHA256 != hex.EncodeToString(want[:]) || shot.Bytes != 9 || shot.Path != "guest-control-consent-prompt.png" {
		t.Fatalf("binding = %+v", shot)
	}
	info, err := os.Stat(filepath.Join(dir, shot.Path))
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("evidence file mode = %v, %v", info, err)
	}
	// The browser runner writes its own screenshots; bind adopts them.
	if err := os.WriteFile(filepath.Join(dir, "console-control-live.png"), []byte("console"), 0o600); err != nil {
		t.Fatal(err)
	}
	console, err := evidence.bind("console control live", "console-control-live.png")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := evidence.write("executor journal", "journal-executor.txt", []byte("line\n"))
	if err != nil {
		t.Fatal(err)
	}
	result := &VMAssistanceResult{
		Screenshots: []assistanceEvidenceFile{shot, console},
		Journals:    []assistanceEvidenceFile{journal},
		Scenarios:   []*assistanceScenarioEvidence{{Name: "control", Screenshots: []string{shot.Path, console.Path}}},
	}
	if err := verifyAssistanceEvidence(dir, result); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"scenarios", "screenshots", "journals", "audit", "relay", "passed", "boundaries"} {
		if _, ok := shape[key]; !ok {
			t.Fatalf("record lacks %q", key)
		}
	}
	var files []map[string]any
	if err := json.Unmarshal(shape["screenshots"], &files); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		digest, ok := file["sha256"].(string)
		if !ok || len(digest) != 64 || file["path"] == "" {
			t.Fatalf("screenshot binding incomplete: %v", file)
		}
	}
}

func TestVerifyAssistanceEvidenceRejectsTamperingAndDanglingReferences(t *testing.T) {
	evidence, dir := newTestAssistanceEvidence(t)
	shot, err := evidence.write("guest", "guest-view-sharing.png", []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	result := &VMAssistanceResult{Screenshots: []assistanceEvidenceFile{shot}, Scenarios: []*assistanceScenarioEvidence{{Name: "view", Screenshots: []string{"guest-view-missing.png"}}}}
	if err := verifyAssistanceEvidence(dir, result); err == nil {
		t.Fatal("dangling scenario screenshot accepted")
	}
	result.Scenarios[0].Screenshots = []string{shot.Path}
	path := filepath.Join(dir, shot.Path)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAssistanceEvidence(dir, result); err == nil {
		t.Fatal("tampered screenshot accepted")
	}
	result.Screenshots[0].Path = "../escape.png"
	if err := verifyAssistanceEvidence(dir, result); err == nil {
		t.Fatal("non-local evidence path accepted")
	}
}

func TestAssistanceEvidenceRejectsUnsafeNames(t *testing.T) {
	evidence, _ := newTestAssistanceEvidence(t)
	for _, name := range []string{"", "../x.png", "a/b.png", "/abs.png"} {
		if _, err := evidence.write("bad", name, nil); err == nil {
			t.Fatalf("write accepted %q", name)
		}
		if _, err := evidence.bind("bad", name); err == nil {
			t.Fatalf("bind accepted %q", name)
		}
	}
	if _, err := evidence.write("once", "once.txt", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.write("twice", "once.txt", nil); err == nil {
		t.Fatal("duplicate evidence name accepted")
	}
	if _, err := newAssistanceEvidence("relative"); err == nil {
		t.Fatal("relative evidence directory accepted")
	}
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newAssistanceEvidence(shared); err == nil {
		t.Fatal("group-readable evidence directory accepted")
	}
}
