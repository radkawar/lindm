// SPDX-License-Identifier: Apache-2.0

// Static contact sheet for `lab console review`: one row per route and variant,
// with light/dark desktop/mobile captures side by side. Reads only the sanitized report.

const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character],
  );

const columns = [
  ["light", "desktop"],
  ["dark", "desktop"],
  ["light", "mobile"],
  ["dark", "mobile"],
];

function findingList(entry) {
  const items = [];
  for (const [name, check] of Object.entries(entry.checks ?? {})) {
    for (const finding of check.findings ?? []) {
      items.push(
        `<li><b>${escape(name)}</b> ${escape(finding.message ?? finding.rule)}${finding.excerpt ? ` <q>${escape(finding.excerpt)}</q>` : ""}${(finding.elements ?? []).length ? `<br><small>${escape(finding.elements.slice(0, 3).join(" | "))}</small>` : ""}</li>`,
      );
    }
  }
  return items.join("");
}

export function contactSheet(report) {
  const rows = new Map();
  for (const entry of report.results) {
    const id = `${entry.route} ${entry.variant ?? ""}`.trim();
    if (!rows.has(id)) rows.set(id, { id, url: entry.url, cells: {} });
    rows.get(id).cells[`${entry.theme}-${entry.viewport}`] = entry;
  }
  const body = [...rows.values()]
    .map((row) => {
      const cells = columns
        .map(([theme, viewport]) => {
          const entry = row.cells[`${theme}-${viewport}`];
          if (!entry) return `<td class="missing">Not captured</td>`;
          const findings = findingList(entry);
          const dialogs = (entry.screenshots.dialogs ?? [])
            .map((path, index) => `<a href="${escape(path)}">dialog ${index + 1}</a>`)
            .join(" ");
          const preview = entry.screenshots.viewport ?? entry.screenshots.failure;
          const primary = entry.screenshots.full ?? preview;
          const details = entry.screenshots.details
            ? `<a href="${escape(entry.screenshots.details)}">details</a>`
            : "";
          return `<td class="${entry.passed ? "pass" : "fail"}"><a href="${escape(primary)}"><img loading="lazy" src="${escape(preview)}" alt="${escape(`${row.id} ${theme} ${viewport}`)}"></a><div>${entry.passed ? "Pass" : "Fail"} · <a href="${escape(primary)}">${entry.screenshots.full ? "full page" : "viewport"}</a> ${dialogs} ${details}</div>${findings ? `<details><summary>${entry.passed ? "" : "Findings"}</summary><ul>${findings}</ul></details>` : ""}</td>`;
        })
        .join("");
      return `<tr><th scope="row">${escape(row.id)}<br><small>${escape(row.url)}</small></th>${cells}</tr>`;
    })
    .join("\n");
  const sessions = (report.sessions ?? [])
    .map(
      (session) =>
        `<li>${escape(session.theme)} ${escape(session.viewport)}: ${Object.entries(session.checks)
          .map(([name, check]) => `${escape(name)} ${check.findings.length ? "fail" : "pass"}`)
          .join(
            ", ",
          )}${session.screenshots?.toast ? ` · <a href="${escape(session.screenshots.toast)}">toast</a>` : ""}</li>`,
    )
    .join("");
  const failures = report.failures.map((line) => `<li>${escape(line)}</li>`).join("");
  const ownerEdits = (report.ownerEdits ?? [])
    .map(
      (edit) =>
        `<li>${edit.passed ? "Pass" : "Fail"} · <b>${escape(edit.route)}</b> ${escape(edit.name)}: ${escape(edit.acceptance)} ${edit.screenshots.map((path, index) => `<a href="${escape(path)}">screenshot ${index + 1}</a>`).join(" ")}${edit.findings.length ? `<ul>${edit.findings.map((finding) => `<li>${escape(finding)}</li>`).join("")}</ul>` : ""}</li>`,
    )
    .join("");
  const help = (report.helpScreenshots ?? [])
    .map(
      (capture) =>
        `<li>${escape(capture.path)} ${escape(capture.theme)} ${escape(capture.viewport)} · <a href="${escape(capture.viewportScreenshot)}">viewport</a> · Complete document (${escape(capture.dimensions.height)} px): ${capture.fullScreenshots.map((part, index) => `<a href="${escape(part.screenshot)}">part ${index + 1}</a>`).join(" ")}</li>`,
    )
    .join("");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>lindm console UI review</title>
<style>
body{font:14px system-ui,sans-serif;margin:16px}
table{border-collapse:collapse}
th,td{border:1px solid #ccc;padding:6px;vertical-align:top}
th[scope=row]{text-align:left;max-width:220px;word-break:break-all}
td{width:260px}
td img{width:250px;display:block;border:1px solid #ddd}
td.fail{background:#fde8e8}
td.pass{background:#e8f6ea}
td ul{padding-left:16px;margin:4px 0;font-size:12px;word-break:break-word}
</style></head><body>
<h1>Console UI machine checks: ${report.passed ? "passed" : "failed"}</h1>
<p>Started ${escape(report.startedAt)}, finished ${escape(report.finishedAt)}. axe-core ${escape(report.axeVersion)}. ${report.results.length} captures.</p>
<p><a href="edit-sheet.html">Owner editing pass</a> · <a href="edit-sheet.json">Screen manifest</a>. No owner review or approval is inferred. Semantic markers check presence, not truth or good choices; generic controls count only as structural action coverage. Unmarked metrics, unopened dialogs and unvisited states still need human review.</p>
${report.walkthroughs ? '<p><a href="task-audit.html">Seven administrator task walkthroughs</a> · <a href="task-audit.json">Task evidence and blockers</a>. Route green does not mean every administrator job is complete.</p>' : ""}
<h2>Session checks</h2><ul>${sessions}</ul>
${ownerEdits ? `<h2>Owner edit acceptance</h2><p>Each imported owner task's acceptance criterion against the seeded fleet. A pass is not owner approval.</p><ul>${ownerEdits}</ul>` : ""}
${failures ? `<h2>Failures (${report.failures.length})</h2><details><summary>Show all</summary><ul>${failures}</ul></details>` : ""}
<h2>Routes</h2>
<table><thead><tr><th>Route</th><th>Light 1440x900</th><th>Dark 1440x900</th><th>Light 390x844</th><th>Dark 390x844</th></tr></thead>
<tbody>
${body}
</tbody></table>
${help ? `<h2>Bundled help</h2><p>Consecutive parts cover each complete document without a single oversized image.</p><ul>${help}</ul>` : ""}
</body></html>
`;
}
