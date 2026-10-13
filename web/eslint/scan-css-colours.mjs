#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  colourProperty,
  cssUnescape,
  rawColour,
  rawSelectorColour,
  rawTailwindColour,
} from "./colour-values.mjs";

// Split only at CSS statement boundaries: strings, comments, functions and
// attribute selectors can contain semicolons, colons and braces. Nesting and
// @layer/@media blocks need no special cases. This is a policy scanner, not a
// second stylesheet parser; syntax validation remains the build's job.
export function scanCSSColours(source) {
  const findings = [];
  let start = 0;
  let quote = "";
  let comment = false;
  let parentheses = 0;
  let brackets = 0;
  const inspect = (end, selector) => {
    const fragment = source.slice(start, end);
    const text = fragment.replace(/\/\*[\s\S]*?\*\//g, " ").trim();
    let colour;
    if (selector || /^@custom-(?:variant|selector)\b/i.test(text)) {
      colour = rawSelectorColour(text) ?? rawTailwindColour(text);
      // @supports queries are style declarations too, not colour selectors.
      if (!colour && /^@supports\b/i.test(text)) {
        for (const match of text.matchAll(/\(([\w-]+)\s*:\s*([^()]*)\)/g))
          if (colourProperty(match[1])) colour ??= rawColour(match[2]);
        colour ??= rawColour(text, { named: false });
      }
    } else if (/^@apply\b/i.test(text)) {
      colour = rawTailwindColour(text.slice(6));
    } else {
      const declaration = text.match(/^([\w-]+)\s*:([\s\S]*)$/);
      if (declaration) {
        const property = cssUnescape(declaration[1]);
        // Functions and hex also fail in custom definitions and shorthand
        // declarations; named colours only matter in colour-bearing properties.
        colour = rawColour(declaration[2], { named: colourProperty(property) });
      }
    }
    if (!colour) return;
    const offset = start + fragment.search(/\S/);
    const before = source.slice(0, offset);
    findings.push({
      line: before.split("\n").length,
      column: offset - before.lastIndexOf("\n"),
      colour,
    });
  };
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (comment) {
      if (char === "*" && source[index + 1] === "/") {
        comment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (char === "\\") index += 1;
      else if (char === quote) quote = "";
      continue;
    }
    if (char === "/" && source[index + 1] === "*") {
      comment = true;
      index += 1;
    } else if (char === '"' || char === "'") quote = char;
    else if (char === "\\") index += 1;
    else if (char === "(") parentheses += 1;
    else if (char === ")") parentheses -= 1;
    else if (char === "[") brackets += 1;
    else if (char === "]") brackets -= 1;
    else if (!parentheses && !brackets && ["{", "}", ";"].includes(char)) {
      inspect(index, char === "{");
      start = index + 1;
    }
  }
  inspect(source.length, false);
  return findings;
}

export async function scanCSSDirectory(directory) {
  const findings = [];
  const palette = resolve(directory, "styles/globals.css");
  async function visit(path) {
    const entries = await readdir(path, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const file = join(path, entry.name);
      if (entry.isDirectory()) await visit(file);
      else if (entry.isFile() && entry.name.endsWith(".css") && resolve(file) !== palette) {
        for (const finding of scanCSSColours(await readFile(file, "utf8")))
          findings.push({ file, ...finding });
      }
    }
  }
  await visit(directory);
  return findings;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../src");
  try {
    const findings = await scanCSSDirectory(root);
    for (const { file, line, column, colour } of findings)
      console.error(
        `${file}:${line}:${column}: Raw colour ${colour}; use a semantic token from styles/globals.css.`,
      );
    if (findings.length) process.exitCode = 1;
  } catch (error) {
    console.error(`CSS colour scan failed: ${error.message}`);
    process.exitCode = 1;
  }
}
