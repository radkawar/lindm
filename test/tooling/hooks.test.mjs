import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("../../", import.meta.url));

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), "lindm-hooks-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const name of [
    "package.json",
    ".prettierrc.json",
    ".markdownlint.json",
    ".gitignore",
    ".prettierignore",
    ".githooks",
  ]) {
    cpSync(join(repository, name), join(directory, name), { recursive: true });
  }
  symlinkSync(join(repository, "node_modules"), join(directory, "node_modules"), "dir");
  return directory;
}

function command(directory, executable, args, expectSuccess = true) {
  const result = spawnSync(executable, args, {
    cwd: directory,
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `Command terminated by ${result.signal}`);
  if (expectSuccess) {
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  }
  return result;
}

test("pre-commit validates the index and preserves a partially staged working tree", (t) => {
  const directory = fixture(t);
  const git = (...args) => command(directory, "git", args);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Hook regression fixture");
  git("config", "user.email", "hook-test@example.invalid");
  git("config", "commit.gpgsign", "false");
  command(directory, "npm", ["run", "hooks:install"]);

  const document = join(directory, "README.md");
  const valid = "# Hook regression\n\nValid content.\n";
  const invalid = "# Hook regression\n\n# Duplicate title\n";
  writeFileSync(document, valid);
  git("add", ".");
  git("commit", "-m", "Accept valid initial snapshot");

  writeFileSync(document, invalid);
  git("add", "README.md");
  writeFileSync(document, valid);
  const rejected = command(directory, "git", ["commit", "-m", "Reject invalid index"], false);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stdout + rejected.stderr, /MD025/);
  assert.equal(readFileSync(document, "utf8"), valid);
  assert.equal(git("show", ":README.md").stdout, invalid);

  writeFileSync(document, "# Hook regression\n\nCorrected content.\n");
  git("add", "README.md");
  git("commit", "-m", "Accept corrected index");
});

test("pre-push checks project documents, excludes dependencies, and rejects invalid content", (t) => {
  const directory = fixture(t);
  const document = join(directory, "README.md");
  writeFileSync(document, "# Push regression\n\nValid content.\n");
  command(directory, join(directory, ".githooks/pre-push"), []);

  writeFileSync(document, "# Push regression\n\n# Duplicate title\n");
  const rejected = command(directory, join(directory, ".githooks/pre-push"), [], false);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stdout + rejected.stderr, /MD025/);
});
