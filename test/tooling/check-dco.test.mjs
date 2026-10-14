// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { eventCommits, missingSignoffs } from "./check-dco.mjs";

function fixture(t) {
  const repository = mkdtempSync(join(tmpdir(), "dco-"));
  t.after(() => rmSync(repository, { recursive: true, force: true }));
  const git = (args, input) =>
    execFileSync("git", args, {
      cwd: repository,
      input,
      encoding: "utf8",
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
    }).trim();
  git(["init", "--quiet", "--initial-branch=main"]);
  const commit = (message) => {
    git(
      [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=Author",
        "-c",
        "user.email=author@example.invalid",
        "commit",
        "--quiet",
        "--allow-empty",
        "--author=Author <author@example.invalid>",
        "--file=-",
      ],
      message,
    );
    return git(["rev-parse", "HEAD"]);
  };
  return { repository, commit };
}

test("DCO checks real author trailers and rejects unsigned or unrelated signers", (t) => {
  const { repository, commit } = fixture(t);
  assert.deepEqual(missingSignoffs(repository, commit("Unsigned\n")), ["author@example.invalid"]);
  assert.deepEqual(
    missingSignoffs(
      repository,
      commit("Signed\n\nSigned-off-by: Author <AUTHOR@example.invalid>\n"),
    ),
    [],
  );
  assert.deepEqual(
    missingSignoffs(
      repository,
      commit("Other signer\n\nSigned-off-by: Other <other@example.invalid>\n"),
    ),
    ["author@example.invalid"],
  );
  assert.deepEqual(
    missingSignoffs(
      repository,
      commit(
        "Body text\n\nSigned-off-by: Author <author@example.invalid>\n\nThis is message prose, not a trailer.\n",
      ),
    ),
    ["author@example.invalid"],
  );
});

test("DCO requires each recorded coauthor's own trailer", (t) => {
  const { repository, commit } = fixture(t);
  const body =
    "Coauthored\n\nCo-authored-by: Other <other@example.invalid>\nSigned-off-by: Author <author@example.invalid>\n";
  assert.deepEqual(missingSignoffs(repository, commit(body)), ["other@example.invalid"]);
  assert.deepEqual(
    missingSignoffs(repository, commit(body + "Signed-off-by: Other <other@example.invalid>\n")),
    [],
  );
});

test("DCO selects only the pushed or proposed range, and the manual head", (t) => {
  const { repository, commit } = fixture(t);
  const base = commit("Historical unsigned commit\n");
  const first = commit("First\n\nSigned-off-by: Author <author@example.invalid>\n");
  const head = commit("Second\n\nSigned-off-by: Author <author@example.invalid>\n");
  assert.deepEqual(eventCommits(repository, { before: base, after: head }), [first, head]);
  assert.deepEqual(
    eventCommits(repository, { pull_request: { base: { sha: base }, head: { sha: head } } }),
    [first, head],
  );
  assert.deepEqual(eventCommits(repository, {}, head), [head]);
  assert.deepEqual(eventCommits(repository, { before: "0".repeat(40), after: head }), [head]);
  assert.throws(
    () => eventCommits(repository, { before: "--all", after: head }),
    /invalid event commit ID/,
  );
  assert.throws(() => eventCommits(repository, {}), /missing event commit ID/);
});
