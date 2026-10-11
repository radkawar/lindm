package feed

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	ovalNS            = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
	ovalLinuxNS       = ovalNS + "#linux"
	ovalCommonNS      = "http://oval.mitre.org/XMLSchema/oval-common-5"
	ovalExpandedLimit = 512 << 20
	ovalEntryLimit    = 4 << 20
	ovalIndexLimit    = 200000
)

// Nodes are retained for one bounded entry only, never a complete XML section.
type ovalNode struct {
	name     xml.Name
	attrs    []xml.Attr
	text     string
	children []ovalNode
}

func (n ovalNode) attr(name string) string {
	for _, a := range n.attrs {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n ovalNode) child(name string) ovalNode {
	var child ovalNode
	for _, c := range n.children {
		if c.name.Local == name {
			if child.name.Local != "" {
				return ovalNode{}
			}
			child = c
		}
	}
	return child
}

func (n ovalNode) attributes(names ...string) bool {
	for i, a := range n.attrs {
		for _, earlier := range n.attrs[:i] {
			if earlier.Name == a.Name {
				return false
			}
		}
		if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
			continue
		}
		found := false
		for _, name := range names {
			if a.Name.Space == "" && a.Name.Local == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func readOVALNode(d *xml.Decoder, start xml.StartElement, offset int64, depth int) (ovalNode, error) {
	n := ovalNode{name: start.Name, attrs: start.Attr}
	if depth > 16 {
		return n, errors.New("feed: OVAL nesting limit")
	}
	var text strings.Builder
	for {
		token, err := d.Token()
		if err != nil {
			return n, err
		}
		if d.InputOffset()-offset > ovalEntryLimit {
			return n, errors.New("feed: OVAL entry byte limit")
		}
		switch t := token.(type) {
		case xml.StartElement:
			child, err := readOVALNode(d, t, offset, depth+1)
			if err != nil {
				return n, err
			}
			n.children = append(n.children, child)
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			n.text = strings.TrimSpace(text.String())
			return n, nil
		case xml.Directive:
			return n, errors.New("feed: OVAL XML directives unsupported")
		}
	}
}

// A decoder token may itself contain megabytes of text. Bound reads before
// asking encoding/xml to allocate the token, not only after Decode returns.
type ovalTokenReader struct {
	input     io.Reader
	remaining int64
}

func (r *ovalTokenReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("feed: OVAL token/entry byte limit")
	}
	n, err := r.input.Read(p[:min(int64(len(p)), r.remaining)])
	r.remaining -= int64(n)
	return n, err
}

// Two passes over a bounded private compressed file index native tests first,
// then emit definitions individually. Forward references do not require keeping
// the 132 MiB vendor document or all normalized claims in memory.
func walkOVAL(ctx context.Context, file *os.File, definitions bool, consume func(string, ovalNode) error) (err error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	z, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("feed: open OVAL gzip: %w", err)
	}
	defer func() { err = errors.Join(err, z.Close()) }()
	limited := &io.LimitedReader{R: contextFeedReader{ctx, z}, N: ovalExpandedLimit + 1}
	tokenReader := &ovalTokenReader{input: limited}
	d := xml.NewDecoder(tokenReader)
	rootSeen, rootClosed := false, false
	section := ""
	seen := make(map[string]bool)
	count := 0
	for {
		tokenReader.remaining = ovalEntryLimit
		token, err := d.Token()
		if err == io.EOF {
			if !rootClosed || limited.N == 0 || len(seen) != 5 {
				return errors.New("feed: incomplete or oversized OVAL document")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("feed: decode OVAL: %w", err)
		}
		switch t := token.(type) {
		case xml.StartElement:
			if rootClosed {
				return errors.New("feed: trailing OVAL document")
			}
			if !rootSeen {
				if t.Name.Space != ovalNS || t.Name.Local != "oval_definitions" {
					return errors.New("feed: OVAL definitions root required")
				}
				rootSeen = true
				continue
			}
			if section == "" {
				if t.Name.Space != ovalNS || seen[t.Name.Local] {
					return errors.New("feed: duplicate or foreign OVAL section")
				}
				switch t.Name.Local {
				case "generator", "definitions", "tests", "objects", "states":
				default:
					return errors.New("feed: unsupported OVAL section")
				}
				seen[t.Name.Local] = true
				if t.Name.Local == "generator" {
					n, err := readOVALNode(d, t, d.InputOffset(), 0)
					if err != nil {
						return err
					}
					if err := consume("generator", n); err != nil {
						return err
					}
					continue
				}
				section = t.Name.Local
				continue
			}
			count++
			if count > ovalIndexLimit*4 {
				return errors.New("feed: OVAL entry count limit")
			}
			if (section == "definitions") != definitions {
				if err := d.Skip(); err != nil {
					return err
				}
				continue
			}
			n, err := readOVALNode(d, t, d.InputOffset(), 0)
			if err != nil {
				return err
			}
			if err := consume(section, n); err != nil {
				return err
			}
		case xml.EndElement:
			if section != "" {
				section = ""
			} else {
				rootClosed = true
			}
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return errors.New("feed: unexpected OVAL text")
			}
		case xml.Directive:
			return errors.New("feed: OVAL XML directives unsupported")
		}
	}
}
