package main

import (
	"strings"
	"testing"
)

func TestMergeLedgerComposesConcurrentChanges(t *testing.T) {
	entry := func(platform, cell string) string {
		return `{"platform":"` + platform + `","cell":"` + cell + `","architecture":"x86_64","verdict":"MATRIX_VERDICT_PASS"}`
	}
	ledger := func(entries ...string) []byte {
		return []byte(`{"entries": [` + strings.Join(entries, ", ") + "]}\n")
	}
	old, shared := entry("ubuntu-24.04", "lifecycle"), entry("debian-12", "inventory")
	mine, other := entry("debian-12", "lifecycle"), entry("fedora-43", "lifecycle")
	base := ledger(old, shared)
	// Main gained another landing's entry while this worktree appended its
	// own and dropped a superseded one; formatting differs on each side.
	current := []byte(strings.ReplaceAll(string(ledger(old, shared, other)), ",", ",\n "))
	theirs := ledger(shared, mine)
	merged, err := mergeLedger(current, base, theirs)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"entries\": [\n" + strings.Join([]string{indent(shared), indent(other), indent(mine)}, ",\n") + "\n  ]\n}\n"
	if string(merged) != want {
		t.Fatalf("merged\n%s\nwant\n%s", merged, want)
	}
	if again, err := mergeLedger(merged, base, theirs); err != nil || string(again) != string(merged) {
		t.Fatalf("merge not idempotent: %s, %v", again, err)
	}
	if created, err := mergeLedger(nil, nil, ledger(mine)); err != nil || !strings.Contains(string(created), `"cell": "lifecycle"`) {
		t.Fatalf("new ledger %s: %v", created, err)
	}
	for _, bad := range []string{"{not json", `{"entries":[],"extra":1}`} {
		if _, err := mergeLedger(current, base, []byte(bad)); err == nil {
			t.Fatalf("merged unreadable ledger %q", bad)
		}
	}
}

// indent renders a flat test entry as the merged ledger lays it out.
func indent(entry string) string {
	fields := strings.Split(strings.Trim(entry, "{}"), ",")
	for i, field := range fields {
		key, value, _ := strings.Cut(field, ":")
		fields[i] = "      " + key + ": " + value
	}
	return "    {\n" + strings.Join(fields, ",\n") + "\n    }"
}
