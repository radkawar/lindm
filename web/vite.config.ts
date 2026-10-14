// SPDX-License-Identifier: Apache-2.0

import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import { defineConfig } from "vite";
import { projectLicense } from "../test/tooling/project-license.mjs";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  root,
  base: "/",
  plugins: [
    tanstackRouter({
      target: "react",
      autoCodeSplitting: true,
      routesDirectory: "./src/routes",
      generatedRouteTree: "./src/routeTree.gen.ts",
      routeTreeFileHeader: [
        `// SPDX-License-Identifier: ${projectLicense}`,
        "",
        "/* eslint-disable */",
        "// @ts-nocheck",
        "// noinspection JSUnusedGlobalSymbols",
      ],
    }),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  oxc: {
    jsx: {
      runtime: "automatic",
      importSource: "react",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Acceptance imports the actual loaded auth client for an invalid-request
    // origin-policy probe; preserve its named exports without a test-only API.
    rolldownOptions: {
      output: { minifyInternalExports: false },
    },
  },
});
