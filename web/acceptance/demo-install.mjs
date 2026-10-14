// SPDX-License-Identifier: Apache-2.0

// The demo uses the console's customer installer, not a second package recipe.
import { enrollmentInstallScript } from "../src/features/enrollment/snippets.ts";

let input = "";
for await (const chunk of process.stdin) {
  input += chunk;
  if (input.length > 1024 * 1024) throw new Error("demo instructions exceed bound");
}
const { instructions, platform } = JSON.parse(input);
const selected = instructions.platforms.find((entry) => entry.id === platform);
const script = enrollmentInstallScript(instructions, selected);
if (!script) throw new Error("customer installation is not ready for selected platform");
process.stdout.write(script);
