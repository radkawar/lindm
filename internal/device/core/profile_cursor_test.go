// SPDX-License-Identifier: Apache-2.0

package core

import (
	"testing"

	"github.com/google/uuid"
)

// A page token continues only the search it was issued for, so a changed search
// can never silently resume at another search's position.
func TestProfileSearchCursorBindsTheSearch(t *testing.T) {
	id := uuid.New()
	for _, search := range []string{"", "lab", "Lab racks"} {
		token := EncodeProfileSearchCursor(id, search)
		got, err := DecodeProfileSearchCursor(token, search)
		if err != nil || got != id {
			t.Fatalf("search %q: round trip = %v, %v", search, got, err)
		}
	}
	if EncodeProfileSearchCursor(id, "") != EncodeProfileCursor(id) {
		t.Fatal("an unsearched token changed format")
	}
	for name, decode := range map[string]func() (uuid.UUID, error){
		"other search": func() (uuid.UUID, error) {
			return DecodeProfileSearchCursor(EncodeProfileSearchCursor(id, "lab"), "Lab")
		},
		"searched, now none":     func() (uuid.UUID, error) { return DecodeProfileSearchCursor(EncodeProfileSearchCursor(id, "lab"), "") },
		"unsearched, now search": func() (uuid.UUID, error) { return DecodeProfileSearchCursor(EncodeProfileCursor(id), "lab") },
	} {
		if _, err := decode(); err == nil {
			t.Fatalf("%s: token accepted", name)
		}
	}
}
