import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

const featureNames = ["auth", "devices", "enrollment", "audit", "profiles"];
const compositionImports = {
  group: ["@/app/**", "@/routes/**", "**/app/**", "**/routes/**"],
  message: "Application composition and routes depend on features, not the reverse.",
};

export default defineConfig([
  { ignores: ["web/gen/**", "web/dist/**", "web/src/routeTree.gen.ts"] },
  {
    files: ["web/src/**/*.{ts,tsx}"],
    extends: [js.configs.recommended, tseslint.configs.recommended],
    languageOptions: { globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",
    },
  },
  {
    files: ["web/src/{components,lib,hooks}/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            compositionImports,
            {
              group: ["@/features/**", "**/features/**"],
              message: "Shared modules must not import product feature internals.",
            },
          ],
        },
      ],
    },
  },
  ...featureNames.map((feature) => ({
    files: [`web/src/features/${feature}/**/*.{ts,tsx}`],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            compositionImports,
            {
              regex: `^@/features/(?!${feature}(?:/|$))`,
              message: "Compose separate features in routes instead of importing their internals.",
            },
            {
              regex: `^(?:\\.\\./)+(?:${featureNames.filter((name) => name !== feature).join("|")})(?:/|$)`,
              message: "Do not reach into another feature through relative imports.",
            },
          ],
        },
      ],
    },
  })),
]);
