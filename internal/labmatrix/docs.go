// SPDX-License-Identifier: Apache-2.0

package labmatrix

import (
	"fmt"
	"slices"
	"strings"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/gendoc"
)

// DocBlock renders the verification ledger's Tier capability matrix from the
// matrix, manifests and ledger under root.
func DocBlock(root string) (gendoc.Block, error) {
	specs, cells, err := docPlan(root)
	if err != nil {
		return gendoc.Block{}, err
	}
	body, err := Render(specs, cells)
	if err != nil {
		return gendoc.Block{}, err
	}
	return gendoc.Block{File: "docs/verification.md", Name: "lab-matrix", Body: body}, nil
}

// DocBlocks renders both the detailed verification table and public support
// summary from the same loaded inputs and planned states.
func DocBlocks(root string) ([]gendoc.Block, error) {
	in, err := Load(root)
	if err != nil {
		return nil, err
	}
	releases, err := Platforms(nil)
	if err != nil {
		return nil, err
	}
	specs := in.Matrix.GetCells()
	cells := in.Plan(releases, specs)
	matrix, err := Render(specs, cells)
	if err != nil {
		return nil, err
	}
	support, err := RenderSupport(in.supportHistory(cells))
	if err != nil {
		return nil, err
	}
	return []gendoc.Block{
		{File: "docs/verification.md", Name: "lab-matrix", Body: matrix},
		{File: "README.md", Name: "readme-support", Body: support},
	}, nil
}

func docPlan(root string) ([]*labv1.MatrixCell, []*Cell, error) {
	in, err := Load(root)
	if err != nil {
		return nil, nil, err
	}
	releases, err := Platforms(nil)
	if err != nil {
		return nil, nil, err
	}
	specs := in.Matrix.GetCells()
	return specs, in.Plan(releases, specs), nil
}

// Render tables planned cells: one row per release, one column per matrix
// cell. A column shows one state when every architecture agrees and
// "architecture state" pairs otherwise. Evidence sections are reference links
// defined below the table, which keeps cells narrow.
func Render(specs []*labv1.MatrixCell, cells []*Cell) (string, error) {
	header := []string{"Release"}
	for _, spec := range specs {
		header = append(header, gendoc.Escape(spec.GetTitle()))
	}
	type arch struct{ name, text string }
	var refs []string
	label := func(ref string) string {
		i := slices.Index(refs, ref)
		if i < 0 {
			i, refs = len(refs), append(refs, ref)
		}
		return fmt.Sprintf("r%d", i+1)
	}
	var keys []string
	names := map[string]string{}
	columns := map[string][][]arch{}
	for _, c := range cells {
		if _, ok := columns[c.Release.Key]; !ok {
			keys = append(keys, c.Release.Key)
			names[c.Release.Key] = c.Release.Name
			columns[c.Release.Key] = make([][]arch, len(specs))
		}
		i := slices.IndexFunc(specs, func(s *labv1.MatrixCell) bool { return s.GetName() == c.Spec.GetName() })
		columns[c.Release.Key][i] = append(columns[c.Release.Key][i], arch{c.Architecture, cellText(c, label)})
	}
	rows := make([][]string, 0, len(keys))
	for _, key := range keys {
		row := []string{gendoc.Escape(names[key])}
		for _, archs := range columns[key] {
			same := !slices.ContainsFunc(archs, func(a arch) bool { return a.text != archs[0].text })
			if same {
				row = append(row, archs[0].text)
				continue
			}
			pairs := make([]string, len(archs))
			for i, a := range archs {
				pairs[i] = a.name + " " + a.text
			}
			row = append(row, strings.Join(pairs, "; "))
		}
		rows = append(rows, row)
	}
	table, err := gendoc.Table(header, rows)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(table)
	if len(refs) > 0 {
		b.WriteByte('\n')
	}
	for i, ref := range refs {
		fmt.Fprintf(&b, "[r%d]: %s\n", i+1, ref)
	}
	return b.String(), nil
}

func cellText(c *Cell, label func(ref string) string) string {
	switch c.State {
	case NotRun:
		if c.Reason != "" {
			return gendoc.Escape(c.Reason)
		}
		return "—"
	case Pass, Fail:
		text := string(c.State)
		if scope := c.Entry.GetScope(); scope != "" {
			text += " (" + gendoc.Escape(scope) + ")"
		}
		if ref := c.Entry.GetReference(); ref != "" {
			text = "[" + text + "][" + label(ref) + "]"
		}
		return text
	default:
		return string(c.State)
	}
}
