package platform

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"lindm/internal/gendoc"
)

// Pages lists every docs/platforms page that carries a generated capability
// table; each must hold at least one registry row.
func pages() []string {
	var out []string
	for _, r := range registry {
		if !slices.Contains(out, r.Page) {
			out = append(out, r.Page)
		}
	}
	return out
}

// DocBlocks renders every documentation block generated from the registry.
func DocBlocks() ([]gendoc.Block, error) {
	tiers, err := tierTable()
	if err != nil {
		return nil, err
	}
	support, err := supportTable()
	if err != nil {
		return nil, err
	}
	blocks := []gendoc.Block{
		{File: "docs/product-specification.md", Name: "platform-tiers", Body: tiers},
		{File: "docs/verification.md", Name: "platform-tiers", Body: tiers},
		{File: "docs/platforms/README.md", Name: "platform-support", Body: support},
	}
	for _, page := range pages() {
		body, err := capabilityTable(page)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, gendoc.Block{File: "docs/platforms/" + page, Name: "platform-capabilities", Body: body})
	}
	return blocks, nil
}

func label(r *Release) string {
	if short, ok := strings.CutPrefix(r.Name, r.Distribution+" "); ok {
		return short
	}
	switch r.Version.Rule {
	case VersionAbsent:
		return "rolling"
	case VersionSnapshot:
		return "pinned snapshot"
	default:
		return r.Version.String()
	}
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return gendoc.Escape(s)
}

func appendUnique(list []string, values ...string) []string {
	for _, v := range values {
		if v != "" && !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	return list
}

// tierTable groups tiered releases by distribution.
func tierTable() (string, error) {
	type group struct {
		tier                      Tier
		distribution, page        string
		releases, desktops, archs []string
	}
	var groups []*group
	for _, tier := range []Tier{Tier1, Tier2, TierFuture} {
		for _, r := range registry {
			if r.Tier != tier {
				continue
			}
			i := slices.IndexFunc(groups, func(g *group) bool { return g.tier == tier && g.distribution == r.Distribution })
			if i < 0 {
				groups = append(groups, &group{tier: tier, distribution: r.Distribution, page: r.Page})
				i = len(groups) - 1
			}
			g := groups[i]
			g.releases = appendUnique(g.releases, label(r))
			g.desktops = appendUnique(g.desktops, r.Desktop.Name)
			g.archs = appendUnique(g.archs, r.Architectures...)
		}
	}
	rows := make([][]string, 0, len(groups))
	for _, g := range groups {
		rows = append(rows, []string{
			g.tier.String(), gendoc.Escape(g.distribution), gendoc.Escape(strings.Join(g.releases, ", ")),
			dash(strings.Join(g.desktops, "; ")), dash(strings.Join(g.archs, ", ")),
			fmt.Sprintf("[%s](platforms/%s)", strings.TrimSuffix(g.page, ".md"), g.page),
		})
	}
	return gendoc.Table([]string{"Tier", "Distribution", "Releases", "Desktop edition", "Architectures", "Platform page"}, rows)
}

func match(r *Release) string {
	s := "ID=" + r.ID
	switch r.Version.Rule {
	case VersionExact:
		s += " VERSION_ID=" + r.Version.Value
	case VersionMajor:
		s += " VERSION_ID=" + r.Version.Value + "[.N]"
	case VersionAbsent:
		s += ", no VERSION_ID"
	case VersionSnapshot:
		s += " VERSION_ID=YYYYMMDD"
	}
	if r.Variants != nil {
		variants := slices.Clone(r.Variants)
		for i, v := range variants {
			if v == "" {
				variants[i] = "unset"
			}
		}
		s += " VARIANT_ID=" + strings.Join(variants, "/")
	}
	return s
}

func supportTable() (string, error) {
	var rows [][]string
	for _, tier := range []Tier{Tier1, Tier2, TierFuture, TierOutside} {
		for _, r := range registry {
			if r.Tier != tier {
				continue
			}
			n := r.Native()
			packages := string(n.Packages.Backend)
			if n.Packages.Minimum != "" {
				packages += " ≥ " + n.Packages.Minimum
			}
			if r.base != nil {
				packages += " (" + n.Name + " base)"
			}
			systemd := ""
			if n.Systemd > 0 {
				systemd = strconv.Itoa(n.Systemd)
			}
			feedRow := r
			if b := r.BaseCoverage(); b != nil {
				feedRow = b
			}
			feeds := make([]string, 0, len(feedRow.Advisory.Feeds)+1)
			for _, f := range feedRow.Advisory.Feeds {
				feeds = append(feeds, string(f))
			}
			advisory := strings.TrimSpace(strings.Join(feeds, ", ") + " " + feedRow.Advisory.Ecosystem)
			if feedRow != r {
				advisory += " (verified " + feedRow.Advisory.ArchiveOrigin + "-archive packages only)"
			}
			rows = append(rows, []string{
				tier.String(), gendoc.Escape(r.Name), gendoc.Escape(match(r)), dash(strings.Join(r.Architectures, ", ")),
				dash(packages), dash(systemd), dash(n.Firewall), dash(r.FDE), dash(desktop(r.Desktop)), dash(advisory),
				fmt.Sprintf("[%s](%s)", strings.TrimSuffix(r.Page, ".md"), r.Page),
			})
		}
	}
	return gendoc.Table([]string{"Tier", "Release", "os-release match", "Architectures", "Packages", "systemd", "Firewall (native)", "FDE", "Desktop", "Advisory feed", "Guide"}, rows)
}

func desktop(d Desktop) string {
	parts := appendUnique(nil, d.Name)
	if d.Version != "" {
		parts = []string{d.Name + " (" + d.Version + ")"}
	}
	if d.DisplayManager != "" {
		parts = append(parts, "DM "+d.DisplayManager)
	}
	if d.Lock != "" {
		parts = append(parts, "lock "+d.Lock)
	}
	if d.SessionLockUnsupported != "" {
		parts = append(parts, "session lock unsupported: "+d.SessionLockUnsupported)
	}
	return strings.Join(parts, "; ")
}

func capabilityTable(page string) (string, error) {
	var releases []*Release
	for _, r := range registry {
		if r.Page == page {
			releases = append(releases, r)
		}
	}
	header := []string{"Capability"}
	for _, r := range releases {
		header = append(header, gendoc.Escape(r.Name))
	}
	rows := make([][]string, 0, len(Capabilities))
	for _, c := range Capabilities {
		row := []string{string(c)}
		for _, r := range releases {
			cell := "implemented"
			if reason := r.GateReason(c); reason != "" {
				cell = "gated: " + gendoc.Escape(reason)
			} else if c == Advisories && r.BaseCoverage() != nil {
				cell = "partial: " + gendoc.Escape(r.Advisory.Partial)
			}
			row = append(row, cell)
		}
		rows = append(rows, row)
	}
	table, err := gendoc.Table(header, rows)
	if err != nil {
		return "", err
	}
	return "Generated from `internal/platform`; “implemented” is not qualification (see the\n[verification ledger](../verification.md#tier-capability-matrix)).\n\n" + table, nil
}
