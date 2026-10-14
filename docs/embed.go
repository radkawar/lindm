// SPDX-License-Identifier: Apache-2.0

// Package docs serves bundled reference documents, not deployment files or live evidence.
package docs

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"
)

//go:embed *.md platforms/*.md design-concepts/*.md design-concepts/*.svg help.css
var documents embed.FS

type documentLink struct {
	Title string
	URL   string
}

type helpPage struct {
	Title     string
	Body      template.HTML
	Documents []documentLink
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · lindm help</title>
<link rel="stylesheet" href="/help/help.css">
</head>
<body>
<a class="skip" href="#content">Skip to documentation</a>
<header><nav aria-label="Documentation"><a href="/">Back to console</a><a href="/help">Help</a></nav></header>
<main id="content" tabindex="-1">
{{if .Documents}}<h1>Help</h1><p>These documents describe this server build.</p><ul>{{range .Documents}}<li><a href="{{.URL}}">{{.Title}}</a></li>{{end}}</ul>{{else}}<article>{{.Body}}</article>{{end}}
</main>
</body>
</html>
`

// Handler renders the embedded documentation once. Navigation stays on this
// origin; external references retain their text without active links. Raw HTML
// in Markdown is not enabled. No session or filesystem access is required.
func Handler() (http.Handler, error) {
	page, err := template.New("help").Parse(pageTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse help page: %w", err)
	}
	markdown := goldmark.New(goldmark.WithExtensions(extension.Table, extension.Strikethrough))
	pages := make(map[string][]byte)
	var links []documentLink
	err = fs.WalkDir(documents, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".md") {
			return nil
		}
		source, err := documents.ReadFile(name)
		if err != nil {
			return err
		}
		root := markdown.Parser().Parse(text.NewReader(source))
		prepareDocument(root, source, name, make(map[string]int))
		var body bytes.Buffer
		if err := markdown.Renderer().Render(&body, source, root); err != nil {
			return fmt.Errorf("render %s: %w", name, err)
		}
		firstLine, _, _ := strings.Cut(string(source), "\n")
		title := strings.TrimSpace(strings.TrimPrefix(firstLine, "# "))
		var output bytes.Buffer
		// Goldmark escapes document text and omits raw HTML. prepareDocument
		// admits only bundled destinations before this trusted HTML boundary.
		if err := page.Execute(&output, helpPage{Title: title, Body: template.HTML(body.String())}); err != nil {
			return fmt.Errorf("render help page %s: %w", name, err)
		}
		pages["/help/"+name] = output.Bytes()
		links = append(links, documentLink{Title: title, URL: "/help/" + name})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("initialize bundled help: %w", err)
	}
	var index bytes.Buffer
	if err := page.Execute(&index, helpPage{Title: "Help", Documents: links}); err != nil {
		return nil, fmt.Errorf("render help index: %w", err)
	}
	pages["/help"] = index.Bytes()
	pages["/help/"] = index.Bytes()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /help", func(w http.ResponseWriter, r *http.Request) {
		serveHelp(w, r, pages)
	})
	mux.HandleFunc("GET /help/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/help/help.css" || strings.HasPrefix(r.URL.Path, "/help/design-concepts/") && strings.HasSuffix(r.URL.Path, ".svg") {
			name := strings.TrimPrefix(r.URL.Path, "/help/")
			info, err := fs.Stat(documents, name)
			if err != nil || info.IsDir() {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFileFS(w, r, documents, name)
			return
		}
		serveHelp(w, r, pages)
	})
	return mux, nil
}

func serveHelp(w http.ResponseWriter, r *http.Request, pages map[string][]byte) {
	body, ok := pages[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// prepareDocument rewrites links before rendering and creates GitHub-style
// heading IDs, including duplicate suffixes, for existing documentation anchors.
func prepareDocument(parent ast.Node, source []byte, name string, ids map[string]int) {
	for node := parent.FirstChild(); node != nil; {
		next := node.NextSibling()
		prepareDocument(node, source, name, ids)
		switch node := node.(type) {
		case *ast.Heading:
			var label bytes.Buffer
			inlineText(&label, node, source)
			var id strings.Builder
			for _, character := range strings.ToLower(label.String()) {
				switch {
				case unicode.IsLetter(character), unicode.IsNumber(character), character == '-', character == '_':
					id.WriteRune(character)
				case unicode.IsSpace(character):
					id.WriteByte('-')
				}
			}
			base := id.String()
			value := base
			if count := ids[base]; count != 0 {
				value = fmt.Sprintf("%s-%d", base, count)
			}
			ids[base]++
			node.SetAttributeString("id", []byte(value))
		case *ast.Link:
			if destination, ok := helpDestination(name, node.Destination); ok {
				node.Destination = []byte(destination)
			} else {
				unwrap(parent, node)
			}
		case *ast.Image:
			if destination, ok := helpDestination(name, node.Destination); ok {
				node.Destination = []byte(destination)
			} else {
				unwrap(parent, node)
			}
		case *ast.AutoLink:
			parent.ReplaceChild(parent, node, ast.NewString(node.Label(source)))
		}
		node = next
	}
}

func unwrap(parent, node ast.Node) {
	for child := node.FirstChild(); child != nil; child = node.FirstChild() {
		node.RemoveChild(node, child)
		parent.InsertBefore(parent, node, child)
	}
	parent.RemoveChild(parent, node)
}

func inlineText(output *bytes.Buffer, parent ast.Node, source []byte) {
	for node := parent.FirstChild(); node != nil; node = node.NextSibling() {
		switch node := node.(type) {
		case *ast.Text:
			output.Write(node.Value(source))
		case *ast.String:
			output.Write(node.Value)
		default:
			inlineText(output, node, source)
		}
	}
}

func helpDestination(name string, destination []byte) (string, bool) {
	link, err := url.Parse(string(destination))
	if err != nil || link.IsAbs() || link.Host != "" || link.User != nil || link.RawQuery != "" || strings.Contains(link.Path, "\\") {
		return "", false
	}
	if link.Path == "" {
		return link.String(), true
	}
	if strings.HasPrefix(link.Path, "/") {
		return "", false
	}
	target := path.Join(path.Dir(name), link.Path)
	info, err := fs.Stat(documents, target)
	if err != nil || info.IsDir() {
		return "", false
	}
	link.Path = "/help/" + target
	return link.String(), true
}
