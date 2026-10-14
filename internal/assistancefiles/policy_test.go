// SPDX-License-Identifier: Apache-2.0

package assistancefiles

import (
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestIntersectionNeverExpandsLimitsOrTypeAuthority(t *testing.T) {
	a := &agentv1.AssistanceFilePolicy{MaxFileBytes: MaxFileBytes, MaxSessionBytes: MaxSessionBytes, AllowedMimeTypes: []string{"text/plain", "application/pdf"}, AllowedExtensions: []string{".txt", ".pdf"}}
	b := &agentv1.AssistanceFilePolicy{MaxFileBytes: 32, MaxSessionBytes: 64, AllowedMimeTypes: []string{"text/plain", "application/x-executable"}, AllowedExtensions: []string{".txt", ".exe"}}
	want := &agentv1.AssistanceFilePolicy{MaxFileBytes: 32, MaxSessionBytes: 64, AllowedMimeTypes: []string{"text/plain"}, AllowedExtensions: []string{".txt"}}
	if got := Intersect(a, b); !proto.Equal(got, want) {
		t.Fatalf("intersection = %v", got)
	}
	if Intersect(nil, a) != nil || Intersect(a, nil) != nil {
		t.Fatal("absent policy enabled files")
	}
	b.AllowedExtensions = []string{".exe"}
	if Intersect(a, b) != nil {
		t.Fatal("empty type intersection enabled files")
	}
	file := &agentv1.AssistanceFileMetadata{Name: "note.txt", Size: 32, MimeType: "text/plain", Sha256: make([]byte, 32)}
	if !MetadataAllowed(want, file, true) {
		t.Fatal("exact boundary refused")
	}
	file.Size++
	if MetadataAllowed(want, file, true) {
		t.Fatal("size ceiling expanded")
	}
	file.Size = 1
	file.Name = "note.pdf"
	if MetadataAllowed(want, file, true) {
		t.Fatal("MIME bypassed extension restriction")
	}
	file.Name, file.MimeType = "note.txt", "application/pdf"
	if MetadataAllowed(want, file, true) {
		t.Fatal("extension bypassed MIME restriction")
	}
	for _, name := range []string{"../file.txt", ".bashrc", "file.txt ", "file.txt.", "a/b.txt", "a\\b.txt", "x\u202etxt.exe", "a\x00.txt"} {
		if SafeName(name) {
			t.Fatalf("unsafe basename accepted: %q", name)
		}
	}
	limited := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	if !DirectionAllowed(limited, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER) || DirectionAllowed(limited, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER) {
		t.Fatal("directional grant expanded")
	}
}
