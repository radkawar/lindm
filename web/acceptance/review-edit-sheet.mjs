import { createHash, randomUUID } from "node:crypto";

const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character],
  );

export const annotationFields = {
  whatChanged: "What changed? Which evidence supports that, or is change unknown?",
  needsMe: "What needs me now? Is the proposed next action the right one?",
  consequences: "What will acting do? Are targets, count, reversibility and approval truthful?",
  redundancy: "What should be removed, combined or made quieter?",
  action: "Requested edit (one actionable task for this screen)",
  acceptance: "Observable acceptance criterion for the edit",
  assignee: "Responsible person or team (assigned by you)",
};

export function editManifest(report) {
  const screens = new Map();
  const taskScreens = (report.walkthroughs?.results ?? []).flatMap((job) =>
    job.steps.map((step) => ({
      route: step.url,
      url: step.url,
      variant: `Task: ${job.id}, ${step.name}`,
      theme: "light",
      viewport: "desktop",
      screenshots: step.screenshots,
      passed: false,
      checks: {},
    })),
  );
  for (const entry of [...report.results, ...taskScreens]) {
    const key = JSON.stringify([entry.route, entry.url, entry.variant ?? ""]);
    const id = createHash("sha256").update(key).digest("hex").slice(0, 24);
    if (!screens.has(id))
      screens.set(id, {
        id,
        route: entry.route,
        url: entry.url,
        variant: entry.variant ?? "",
        captures: [],
      });
    screens.get(id).captures.push({
      theme: entry.theme,
      viewport: entry.viewport,
      screenshot: entry.screenshots.full,
      dialogs: entry.screenshots.dialogs ?? [],
      machinePassed: entry.passed,
      coverage: entry.checks.pov?.mode ?? "unavailable",
    });
  }
  return {
    version: 1,
    runId: randomUUID(),
    startedAt: report.startedAt,
    contactSheet: "index.html",
    screens: [...screens.values()],
  };
}

export function annotationTemplate(manifest) {
  return { version: 1, runId: manifest.runId, author: "", annotations: [] };
}

export function editSheet(manifest) {
  const sections = manifest.screens
    .map((screen) => {
      const links = screen.captures
        .map(
          (capture) =>
            `<li><a href="${escape(capture.screenshot)}">${escape(`${capture.theme} ${capture.viewport}`)}</a>: machine ${capture.coverage === "unavailable" ? "not run for this task step" : capture.machinePassed ? "pass" : "fail"}; ${escape(capture.coverage)} coverage ${capture.dialogs.map((path, index) => `<a href="${escape(path)}">dialog ${index + 1}</a>`).join(" ")}</li>`,
        )
        .join("");
      const fields = Object.entries(annotationFields)
        .map(
          ([key, label]) =>
            `<label>${escape(label)}<textarea name="${key}" maxlength="${key === "assignee" ? 120 : 2000}" rows="2"></textarea></label>`,
        )
        .join("");
      return `<section data-screen="${screen.id}"><h2>${escape(screen.route)} ${escape(screen.variant)}</h2><p>${escape(screen.url)}</p><ul>${links}</ul>${fields}<label>Priority<select name="priority"><option value="">Choose when requesting an edit</option><option>low</option><option>normal</option><option>high</option><option>urgent</option></select></label></section>`;
    })
    .join("\n");
  const data = JSON.stringify({ manifest, fields: Object.keys(annotationFields) }).replace(
    /</g,
    "\\u003c",
  );
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>lindm owner editing pass</title>
<style>body{font:14px system-ui,sans-serif;max-width:960px;margin:24px auto;padding:0 16px}h1{font-size:24px}h2{font-size:20px}section{border-top:1px solid #999;margin-top:24px;padding-top:12px}label{display:block;margin:12px 0}textarea{display:block;width:100%;box-sizing:border-box;font:inherit}input,select,button{font:inherit;padding:6px}a{color:inherit}button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid #1670d2;outline-offset:3px}@media(prefers-color-scheme:dark){body{background:#191919;color:#eee}textarea,input,select,button{background:#222;color:#eee}}</style></head><body>
<h1>Owner editing pass — not approval</h1>
<p><a href="index.html">Contact sheet and machine findings</a> · <a href="edit-sheet.json">Run manifest</a> · <a href="annotations-template.json" download>Blank annotation JSON</a></p>
<p>Machine results establish only the listed structural checks. Review all four appearances and every destructive workflow; unmarked metrics, unvisited states and unopened dialogs are not covered. No owner annotations or approval have been supplied. Leave unreviewed screens blank. To request an edit, complete every field for that screen. A blank screen is not accepted or approved.</p>
<p>This local sheet sends nothing to a server and does not autosave. Download annotations before closing. Keep downloads private (chmod 600) and import them with the documented command to create task records. Downloads can contain sensitive owner observations; do not enter passwords or secrets.</p>
<label>Your name or team<input id="author" maxlength="120" autocomplete="off"></label>
<label>Resume saved annotations<input id="resume" type="file" accept="application/json,.json"></label>
<button id="save" type="button">Download annotations</button><p id="status" role="status"></p>
${sections}
<script type="application/json" id="review-data">${data}</script>
<script>
const {manifest, fields} = JSON.parse(document.getElementById("review-data").textContent);
const sections = [...document.querySelectorAll("[data-screen]")];
const status = document.getElementById("status");
const author = document.getElementById("author");
const names = [...fields, "priority"];
document.getElementById("save").addEventListener("click", () => {
  const annotations = sections.map(section => Object.fromEntries([
    ["screenId", section.dataset.screen],
    ...names.map(name => [name, section.querySelector('[name="' + name + '"]').value.trim()]),
  ])).filter(item => names.some(name => item[name]));
  if (!author.value.trim() || !annotations.length || annotations.some(item => names.some(name => !item[name]))) {
    status.textContent = "Supply your name and complete every field on each requested edit; leave other screens entirely blank.";
    return;
  }
  const value = JSON.stringify({version: 1, runId: manifest.runId, author: author.value.trim(), annotations}, null, 2);
  const blob = new Blob([value + "\\n"], {type: "application/json"});
  if (blob.size > 1024 * 1024) { status.textContent = "Annotations exceed the 1 MiB import limit."; return; }
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = "owner-annotations.json"; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  status.textContent = "Download requested. Preserve the file, chmod 600, then run the annotation importer. No review approval is inferred.";
});
document.getElementById("resume").addEventListener("change", async event => {
  try {
    const file = event.target.files[0];
    if (!file || file.size > 1024 * 1024) throw new Error();
    const value = JSON.parse(await file.text());
    if (value.version !== 1 || value.runId !== manifest.runId || typeof value.author !== "string" || value.author.length > 120 || !Array.isArray(value.annotations) || value.annotations.length > 500) throw new Error();
    const known = new Map(sections.map(section => [section.dataset.screen, section]));
    const seen = new Set();
    for (const item of value.annotations) {
      if (!item || !known.has(item.screenId) || seen.has(item.screenId) || names.some(name => typeof item[name] !== "string" || item[name].length > (name === "assignee" ? 120 : 2000)) || !["low", "normal", "high", "urgent"].includes(item.priority)) throw new Error();
      seen.add(item.screenId);
    }
    author.value = value.author;
    for (const section of sections) for (const name of names) section.querySelector('[name="' + name + '"]').value = "";
    for (const item of value.annotations) for (const name of names) known.get(item.screenId).querySelector('[name="' + name + '"]').value = item[name];
    status.textContent = "Saved annotations loaded locally. CLI import still performs authoritative validation.";
  } catch { status.textContent = "Cannot load annotations: wrong run, invalid fields, duplicate screens or file over 1 MiB."; }
});
</script></body></html>\n`;
}
