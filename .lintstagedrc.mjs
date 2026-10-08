export default {
  "*.{md,json,jsonc,yaml,yml,js,mjs,ts,tsx,css,html}": "prettier --check",
  "*.md": "markdownlint",
  "*.{ts,tsx}": "eslint --no-warn-ignored --max-warnings=0",
  "*.go": ".tools/bin/golangci-lint fmt",
  "*.proto": (files) => [
    ...files.map((file) => `.tools/bin/buf format -w ${JSON.stringify(file)}`),
    ".tools/bin/buf lint",
  ],
};
