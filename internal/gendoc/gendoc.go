// SPDX-License-Identifier: Apache-2.0

// Package gendoc renders Markdown blocks generated from declarative registries
// and keeps them in sync between explicit markers in hand-written documents.
// Rendered tables are already in Prettier's canonical form so the formatter and
// the drift check agree. It does not parse Markdown beyond the markers and
// never creates or reorders sections.
package gendoc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Block is one generated region of a document.
type Block struct {
	File string // path relative to the repository root
	Name string // marker name, unique within File
	Body string // Markdown without the markers
}

func begin(name string) string { return "<!-- BEGIN GENERATED " + name + " -->" }
func end(name string) string   { return "<!-- END GENERATED " + name + " -->" }

// Replace returns doc with the named block's content replaced by body. The
// markers must already exist exactly once.
func Replace(doc []byte, name, body string) ([]byte, error) {
	open, closing := []byte(begin(name)), []byte(end(name))
	if bytes.Count(doc, open) != 1 || bytes.Count(doc, closing) != 1 {
		return nil, fmt.Errorf("gendoc: block %q needs exactly one begin and end marker", name)
	}
	start := bytes.Index(doc, open) + len(open)
	stop := bytes.Index(doc, closing)
	if stop < start {
		return nil, fmt.Errorf("gendoc: block %q end marker precedes begin", name)
	}
	out := make([]byte, 0, len(doc)+len(body))
	out = append(out, doc[:start]...)
	out = append(out, "\n\n"...)
	out = append(out, strings.TrimSpace(body)...)
	out = append(out, "\n\n"...)
	return append(out, doc[stop:]...), nil
}

// Sync renders blocks into their files under root. With write false it only
// reports files whose generated content differs; with write true it rewrites
// them. It returns the stale (or rewritten) files.
func Sync(root string, blocks []Block, write bool) ([]string, error) {
	files := make(map[string][]Block)
	var order []string
	for _, b := range blocks {
		if _, ok := files[b.File]; !ok {
			order = append(order, b.File)
		}
		files[b.File] = append(files[b.File], b)
	}
	var stale []string
	for _, file := range order {
		path := filepath.Join(root, file)
		doc, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		next := doc
		for _, b := range files[file] {
			if next, err = Replace(next, b.Name, b.Body); err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
		}
		if bytes.Equal(doc, next) {
			continue
		}
		stale = append(stale, file)
		if write {
			if err := os.WriteFile(path, next, 0o644); err != nil {
				return nil, err
			}
		}
	}
	return stale, nil
}

// Table renders a Markdown table in Prettier's canonical layout: every column
// padded to its widest cell and a dash rule of the same width.
func Table(header []string, rows [][]string) (string, error) {
	widths := make([]int, len(header))
	measure := func(row []string) error {
		if len(row) != len(header) {
			return errors.New("gendoc: table row width differs from header")
		}
		for i, cell := range row {
			widths[i] = max(widths[i], 3, utf8.RuneCountInString(cell))
		}
		return nil
	}
	if err := measure(header); err != nil {
		return "", err
	}
	for _, row := range rows {
		if err := measure(row); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	line := func(row []string) {
		for i, cell := range row {
			b.WriteString("| ")
			b.WriteString(cell)
			b.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell)))
			b.WriteByte(' ')
		}
		b.WriteString("|\n")
	}
	line(header)
	for i := range header {
		b.WriteString("| ")
		b.WriteString(strings.Repeat("-", widths[i]))
		b.WriteByte(' ')
	}
	b.WriteString("|\n")
	for _, row := range rows {
		line(row)
	}
	return b.String(), nil
}

// Escape makes plain text safe inside a table cell: pipes are escaped, and an
// underscore or asterisk that could open emphasis is escaped as Prettier does.
func Escape(s string) string {
	var b strings.Builder
	var prev rune
	for _, r := range s {
		switch {
		case r == '|':
			b.WriteString(`\|`)
		case (r == '_' || r == '*') && !unicode.IsLetter(prev) && !unicode.IsDigit(prev):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
		prev = r
	}
	return b.String()
}

// Blank returns doc with the content of every generated block emptied, the
// markers kept: the hand-written part of a document, against which a change
// can be compared or applied whatever the generated content is. A block is a
// begin marker on a line of its own through the next end marker of the same
// name on a line of its own; a marker quoted inside prose or code is not one.
// It needs no registry, so it works on any revision of any document.
func Blank(doc []byte) []byte {
	out := make([]byte, 0, len(doc))
	rest := doc
	for {
		start, name := nextBegin(rest)
		if start < 0 {
			return append(out, rest...)
		}
		open := start + len(begin(name))
		closing := bytes.Index(rest[open:], []byte("\n"+end(name)+"\n"))
		if closing < 0 {
			return append(out, rest...)
		}
		out = append(out, rest[:open]...)
		out = append(out, "\n\n"...)
		rest = rest[open+closing+1:]
	}
}

// nextBegin finds the next begin marker that is a whole line, returning its
// offset and block name, or -1.
func nextBegin(doc []byte) (int, string) {
	const prefix, suffix = "<!-- BEGIN GENERATED ", " -->"
	for offset := 0; ; {
		i := bytes.Index(doc[offset:], []byte(prefix))
		if i < 0 {
			return -1, ""
		}
		start := offset + i
		lineEnd := bytes.IndexByte(doc[start:], '\n')
		if lineEnd < 0 {
			return -1, ""
		}
		line := string(doc[start : start+lineEnd])
		name, ok := strings.CutSuffix(strings.TrimPrefix(line, prefix), suffix)
		if (start == 0 || doc[start-1] == '\n') && ok && name != "" && !strings.ContainsAny(name, " \t") {
			return start, name
		}
		offset = start + len(prefix)
	}
}
