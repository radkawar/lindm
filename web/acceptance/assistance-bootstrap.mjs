#!/usr/bin/env node
import { startupFailure, startupStage } from "./assistance-startup.mjs";

// Static dependencies of the runner can fail before its command loop exists.
// Keep this boundary free of Playwright/esbuild imports so that failure still
// reaches the private protocol. argv[2] remains the private configuration path.
startupStage("module_load");
try {
  await import("./assistance.mjs");
} catch (error) {
  await new Promise((done) =>
    process.stdout.write(
      JSON.stringify({ id: 0, ok: false, error: startupFailure(error, "module_load") }) + "\n",
      done,
    ),
  );
  process.exit(1);
}
