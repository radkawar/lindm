// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The console plays a recording it decrypted in the page from a blob: URL;
// the policy admits exactly that media source and nothing else by default.
func TestGuardPolicyAdmitsOnlyBlobMedia(t *testing.T) {
	recorder := httptest.NewRecorder()
	guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	directives := map[string]string{}
	for _, directive := range strings.Split(recorder.Header().Get("Content-Security-Policy"), ";") {
		name, value, _ := strings.Cut(strings.TrimSpace(directive), " ")
		directives[name] = value
	}
	if directives["media-src"] != "blob:" || directives["default-src"] != "'none'" || directives["connect-src"] != "'self'" {
		t.Fatalf("policy = %v", directives)
	}
}
