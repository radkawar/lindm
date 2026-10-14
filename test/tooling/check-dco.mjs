// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

function git(repository, args, input) {
  return execFileSync("git", args, { cwd: repository, input, encoding: "utf8" }).trim();
}

export function missingSignoffs(repository, commit) {
  const [name, author, message] = git(repository, [
    "show",
    "-s",
    "--format=%an%x00%ae%x00%B",
    commit,
  ]).split("\0");
  const trailers = git(repository, ["interpret-trailers", "--parse"], message).split("\n");
  const signed = new Set();
  const authors = new Set([author.toLowerCase()]);
  // Exempt only Dependabot's canonical commit author, never its human coauthors
  // or other commits in the same pull request.
  if (
    name === "dependabot[bot]" &&
    author === "49699333+dependabot[bot]@users.noreply.github.com"
  ) {
    authors.delete(author);
  }
  for (const trailer of trailers) {
    const match = /^(Signed-off-by|Co-authored-by):\s+.+\s+<([^<>\s]+)>$/i.exec(trailer);
    if (!match) continue;
    const email = match[2].toLowerCase();
    if (match[1].toLowerCase() === "signed-off-by") signed.add(email);
    else authors.add(email);
  }
  return [...authors].filter((email) => !signed.has(email));
}

export function eventCommits(repository, event, head) {
  const base = event.pull_request?.base.sha ?? event.before;
  const tip = event.pull_request?.head.sha ?? event.after ?? head;
  for (const value of [base, tip].filter(Boolean)) {
    if (!/^[a-f0-9]{40,64}$/i.test(value)) throw new Error("DCO: invalid event commit ID");
  }
  if (!tip) throw new Error("DCO: missing event commit ID");
  if (!base || /^0+$/.test(base)) return [tip];
  return git(repository, ["rev-list", "--reverse", `${base}..${tip}`])
    .split("\n")
    .filter(Boolean);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));
  const commits = eventCommits(process.cwd(), event, process.env.GITHUB_SHA);
  let failed = false;
  for (const commit of commits) {
    const missing = missingSignoffs(process.cwd(), commit);
    if (missing.length === 0) continue;
    failed = true;
    console.error(`DCO: ${commit} needs Signed-off-by trailers for ${missing.join(", ")}`);
  }
  if (failed) process.exitCode = 1;
  else console.log(`DCO: ${commits.length} commits satisfy author and coauthor sign-off policy.`);
}
