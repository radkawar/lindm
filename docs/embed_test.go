// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/text"
	"golang.org/x/net/html"
)

func TestBundledHelpNavigation(t *testing.T) {
	handler, err := Handler()
	if err != nil {
		t.Fatal(err)
	}
	index := helpRequest(t, handler, http.MethodGet, "/help", http.StatusOK)
	if !strings.Contains(index.Body.String(), "These documents describe this server build.") {
		t.Fatal("help index does not identify its build-local scope")
	}
	links := helpAttributes(t, index.Body.Bytes(), "href")
	var count int
	for _, link := range links {
		if !strings.HasSuffix(link, ".md") {
			continue
		}
		count++
		response := helpRequest(t, handler, http.MethodGet, link, http.StatusOK)
		if !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") || !strings.Contains(response.Body.String(), "<article>") {
			t.Fatalf("%s did not render a documentation page", link)
		}
		for _, attribute := range []string{"href", "src"} {
			for _, destination := range helpAttributes(t, response.Body.Bytes(), attribute) {
				parsed, err := url.Parse(destination)
				if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(destination, "/") && !strings.HasPrefix(destination, "#") {
					t.Fatalf("%s contains outbound or relative %s %q", link, attribute, destination)
				}
				if strings.HasPrefix(parsed.Path, "/help/") {
					helpRequest(t, handler, http.MethodGet, parsed.Path, http.StatusOK)
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("help index has no bundled documents")
	}
	page := helpRequest(t, handler, http.MethodGet, "/help/security-and-operations.md", http.StatusOK)
	if !strings.Contains(page.Body.String(), `id="enrollment-installation-from-your-server"`) {
		t.Fatal("enrollment help anchor is missing")
	}
	page = helpRequest(t, handler, http.MethodGet, "/help/platforms/README.md", http.StatusOK)
	if !strings.Contains(page.Body.String(), "/help/platforms/") {
		t.Fatal("nested platform documentation lost local navigation")
	}
}

func TestHelpBoundariesAndMethods(t *testing.T) {
	handler, err := Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/help/", http.StatusOK},
		{http.MethodGet, "/help/help.css", http.StatusOK},
		{http.MethodGet, "/help/design-concepts/evidence-fork.svg", http.StatusOK},
		{http.MethodGet, "/help/missing.md", http.StatusNotFound},
		{http.MethodGet, "/help/platforms/", http.StatusNotFound},
		{http.MethodGet, "/help/embed.go", http.StatusNotFound},
		{http.MethodGet, "/help/platforms/README.md/extra", http.StatusNotFound},
		{http.MethodGet, "/help/%2e%2e/go.mod", http.StatusNotFound},
		{http.MethodPost, "/help", http.StatusMethodNotAllowed},
		{http.MethodPost, "/help/architecture.md", http.StatusMethodNotAllowed},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			helpRequest(t, handler, test.method, test.path, test.status)
		})
	}
	get := helpRequest(t, handler, http.MethodGet, "/help/architecture.md", http.StatusOK)
	head := helpRequest(t, handler, http.MethodHead, "/help/architecture.md", http.StatusOK)
	if head.Body.Len() != 0 || head.Header().Get("Content-Length") != get.Header().Get("Content-Length") {
		t.Fatal("HEAD must retain the document length without returning its body")
	}
	if !strings.Contains(get.Header().Get("Content-Security-Policy"), "default-src 'none'") || get.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("help omitted its content security boundary")
	}
}

func TestHelpRemovesOutboundLinksAndUnsafeHTML(t *testing.T) {
	source := []byte("# Native `device_state`\n\n# Native `device_state`\n\n" +
		"[Local reference](security-and-operations.md#enrollment-installation-from-your-server)\n\n" +
		"[Public reference](https://public.example/help) [Foreign origin](//public.example/help) " +
		"[Script](javascript:alert(1)) [Source](../go.mod)\n\n" +
		"<https://public.example/reference>\n\n" +
		"![External image](https://public.example/pixel.png)\n\n" +
		"<a href=\"https://public.example/raw\">Raw link</a><script>alert(1)</script>\n")
	markdown := goldmark.New()
	root := markdown.Parser().Parse(text.NewReader(source))
	prepareDocument(root, source, "architecture.md", make(map[string]int))
	var output bytes.Buffer
	if err := markdown.Renderer().Render(&output, source, root); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`id="native-device_state"`, `id="native-device_state-1"`, "Public reference", "External image"} {
		if !strings.Contains(output.String(), value) {
			t.Fatalf("rendered help lost %q", value)
		}
	}
	links := helpAttributes(t, output.Bytes(), "href")
	if len(links) != 1 || links[0] != "/help/security-and-operations.md#enrollment-installation-from-your-server" {
		t.Fatalf("rendered help links = %v", links)
	}
	if len(helpAttributes(t, output.Bytes(), "src")) != 0 || strings.Contains(output.String(), "<script>") {
		t.Fatal("rendered help contains executable or remotely loaded content")
	}
}

func helpRequest(t *testing.T, handler http.Handler, method, path string, status int) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "https://console.example"+path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != status {
		t.Fatalf("%s %s = %d, want %d", method, path, response.Code, status)
	}
	return response
}

func helpAttributes(t *testing.T, body []byte, name string) []string {
	t.Helper()
	var values []string
	tokens := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch tokens.Next() {
		case html.ErrorToken:
			if tokens.Err() != io.EOF {
				t.Fatal(tokens.Err())
			}
			return values
		case html.StartTagToken, html.SelfClosingTagToken:
			for _, attribute := range tokens.Token().Attr {
				if attribute.Key == name {
					values = append(values, attribute.Val)
				}
			}
		}
	}
}
