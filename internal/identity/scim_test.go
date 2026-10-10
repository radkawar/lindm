package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSCIMBodyLimitIncludesTrailingWhitespace(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{}`+strings.Repeat(" ", scimMaxBody)))
	request.Header.Set("Content-Type", "application/scim+json")
	_, err := readSCIMDocument(request)
	var failure *scimFailure
	if !errors.As(err, &failure) || failure.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized whitespace body accepted: %v", err)
	}
}

func TestSCIMPatchComplexAndFilteredAttributes(t *testing.T) {
	document := scimDocument{
		"schemas": []any{scimCore + "User"}, "userName": "original", "externalId": "immutable", "active": true,
		"name":   map[string]any{"givenName": "Original", "familyName": "Retained"},
		"emails": []any{map[string]any{"value": "old@example.test", "type": "work"}, map[string]any{"value": "personal@example.test", "type": "home"}},
	}
	body, err := json.Marshal(scimDocument{"schemas": []any{scimMessages + "PatchOp"}, "Operations": []any{
		map[string]any{"op": "replace", "path": "Name.GivenName", "value": "Renamed"},
		map[string]any{"op": "replace", "path": `emails[type eq "work"].value`, "value": "new@example.test"},
		map[string]any{"op": "replace", "value": map[string]any{"active": false}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/id", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/scim+json")
	if err := patchSCIM(request, document); err != nil {
		t.Fatal(err)
	}
	name, ok := document["name"].(map[string]any)
	if !ok {
		t.Fatal("PATCH discarded the structured name")
	}
	emails, ok := document["emails"].([]any)
	if !ok || len(emails) != 2 {
		t.Fatal("PATCH discarded email entries")
	}
	work, workOK := emails[0].(map[string]any)
	personal, personalOK := emails[1].(map[string]any)
	if !workOK || !personalOK {
		t.Fatal("PATCH discarded structured email values")
	}
	if name["givenName"] != "Renamed" || name["familyName"] != "Retained" || document["active"] != false || work["value"] != "new@example.test" || personal["value"] != "personal@example.test" {
		t.Fatalf("PATCH changed unrelated attributes or lost false: %+v", document)
	}
}

func TestSCIMPatchReadOnlyAndMissingTargets(t *testing.T) {
	for _, path := range []string{"id", "meta.version", "schemas", "groups"} {
		document := scimDocument{"id": "preserved", "schemas": []any{scimCore + "User"}}
		err := scimPatchPath(document, "replace", path, "untrusted")
		var failure *scimFailure
		if !errors.As(err, &failure) || failure.kind != "mutability" || document["id"] != "preserved" {
			t.Fatalf("read-only path %s writable: %v", path, err)
		}
	}
	document := scimDocument{"members": []any{map[string]any{"value": "existing"}}}
	err := scimPatchPath(document, "remove", `members[value eq "absent"]`, nil)
	var failure *scimFailure
	members, ok := document["members"].([]any)
	if !errors.As(err, &failure) || failure.kind != "noTarget" || !ok || len(members) != 1 {
		t.Fatalf("unmatched value path removed a member: %v", err)
	}
}

func TestSCIMEqualityFilters(t *testing.T) {
	for _, test := range []struct{ filter, attribute, value string }{
		{`USERNAME EQ "Mixed Case"`, "userName", "Mixed Case"},
		{`externalid eq "Exact-ID"`, "externalId", "Exact-ID"},
		{`userName eq "escaped\"quote"`, "userName", "escaped\"quote"},
	} {
		attribute, value, err := scimFilter(test.filter)
		if err != nil || attribute != test.attribute || value != test.value {
			t.Fatalf("filter %s: %s %s %v", test.filter, attribute, value, err)
		}
	}
	for _, filter := range []string{`email eq "x"`, `userName co "x"`, `userName eq "x" or active eq true`, `userName eq true`} {
		if _, _, err := scimFilter(filter); err == nil {
			t.Fatalf("unsupported filter accepted: %s", filter)
		}
	}
}
