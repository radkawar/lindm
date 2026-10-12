// Startup evidence is a closed vocabulary, never an exception message, stack,
// launch command, environment or credential-bearing observation. A failure
// once the console is loaded adds only a bounded observation of what the page
// showed and how its same-origin requests ended (startupObservation).
const stages = [
  "module_load",
  "configuration",
  "chromium_launch",
  "browser_setup",
  "navigation",
  "authenticator",
  "enrollment",
  "sign_in",
];
const errorTypes = new Set([
  "Error",
  "TypeError",
  "SyntaxError",
  "ReferenceError",
  "RangeError",
  "TimeoutError",
  "AggregateError",
]);
const nodeCodes = new Map([
  ["ERR_MODULE_NOT_FOUND", "module_not_found"],
  ["MODULE_NOT_FOUND", "module_not_found"],
  ["ERR_UNKNOWN_FILE_EXTENSION", "module_extension_unsupported"],
  ["ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX", "typescript_syntax_unsupported"],
  ["ERR_PACKAGE_PATH_NOT_EXPORTED", "module_export_unavailable"],
  ["ERR_PACKAGE_IMPORT_NOT_DEFINED", "module_import_undefined"],
  ["ERR_DLOPEN_FAILED", "native_library_load_failed"],
  ["ENOENT", "resource_not_found"],
  ["EACCES", "permission_denied"],
  ["EPERM", "permission_denied"],
]);
const configurationCodes = new Set([
  "private_config_path_required",
  "required_configuration_missing",
  "https_origin_required",
  "private_owned_directory_required",
  "private_owned_bounded_json_required",
  "invalid_turn_tcp_only",
  "invalid_native_file_picker",
]);
// Our own UI driver's refusals once the console page exists, and Playwright's
// fixed phrases for a page that navigated (e.g. the console reloading itself
// after an aborted route chunk) under a step; anything else stays unclassified.
const pageStages = new Set(["navigation", "authenticator", "enrollment", "sign_in"]);
const uiCodes = new Set(["ui_condition_timeout", "ambiguous_ui_locator", "ambiguous_ui_scope"]);
const pageSignatures = [
  ["Execution context was destroyed", "page_navigated_during_step"],
  ["Navigation interrupted the evaluation", "page_navigated_during_step"],
  ["Element is not attached to the DOM", "element_detached_during_step"],
];
const launchSignatures = [
  ["Executable doesn't exist at", "chromium_executable_missing"],
  ["Host system is missing dependencies", "chromium_dependencies_missing"],
  ["error while loading shared libraries:", "chromium_library_missing"],
  ["Missing X server or $DISPLAY", "chromium_display_unavailable"],
  [
    "Authorization required, but no authorization protocol specified",
    "chromium_display_authority_rejected",
  ],
  ["Invalid MIT-MAGIC-COOKIE-1 key", "chromium_display_authority_rejected"],
  ["No usable sandbox!", "chromium_sandbox_unavailable"],
  ["Target page, context or browser has been closed", "chromium_closed_during_launch"],
];

export function startupFailure(error, stage) {
  const errorType = errorTypes.has(error?.name) ? error.name : "Error";
  // Even classification inspects only a bounded prefix; none of it is returned.
  const message = typeof error?.message === "string" ? error.message.slice(0, 16_384) : "";
  let code = nodeCodes.get(error?.code);
  let netError;
  if (!code && stage === "configuration" && configurationCodes.has(message)) code = message;
  if (!code && stage === "chromium_launch")
    code = launchSignatures.find(([signature]) => message.includes(signature))?.[1];
  if (!code && pageStages.has(stage) && uiCodes.has(message)) code = message;
  if (!code && pageStages.has(stage))
    code = pageSignatures.find(([signature]) => message.includes(signature))?.[1];
  if (!code && pageStages.has(stage)) {
    // Chromium's own net error names (net::ERR_NETWORK_CHANGED) are a fixed
    // vocabulary; the surrounding message (URL, call log) is never returned.
    netError = /\bnet::(ERR_[A-Z0-9_]{1,64})\b/.exec(message)?.[1];
    if (netError) code = "browser_network_error";
  }
  if (!code && errorType === "SyntaxError") code = "javascript_syntax_error";
  if (!code && errorType === "TimeoutError") code = "startup_timeout";
  return {
    code: code ?? "browser_startup_failed",
    errorType,
    stage: stages.includes(stage) ? stage : "unknown",
    ...(netError ? { netError } : {}),
  };
}

// visibleOutcome runs in the page: the console's own visible alert, status and
// heading text (never input values) and its support codes, which name the
// refusal a person would see.
export function visibleOutcome() {
  const visible = (node) =>
    node.getClientRects().length > 0 && getComputedStyle(node).visibility !== "hidden";
  const texts = (selector) =>
    [...document.querySelectorAll(selector)].filter(visible).map((node) => node.innerText ?? "");
  return {
    alerts: texts('[role="alert"]'),
    statuses: texts('[role="status"]'),
    headings: texts("h1,h2"),
    support: [...document.querySelectorAll('[data-slot="support-details"]')].map((node) => {
      const field = (label) =>
        [...node.querySelectorAll("dt")]
          .find((term) => term.textContent.trim() === `${label}:`)
          ?.nextElementSibling?.textContent.trim() ?? "";
      return { code: field("Code"), reason: field("Reason") };
    }),
  };
}

// startupObservation keeps only the expected fields, bounded in count and
// length, and removes the runner's own credentials wherever they appear, so a
// page that echoed one still cannot carry it into lab evidence.
export function startupObservation(raw, secrets = []) {
  const hidden = secrets.filter((secret) => typeof secret === "string" && secret.length >= 4);
  const scrub = (value, limit) => {
    let text = typeof value === "string" ? value : "";
    for (const secret of hidden) text = text.replaceAll(secret, "[redacted]");
    return text.replace(/\s+/g, " ").trim().slice(0, limit);
  };
  const list = (value, count) => (Array.isArray(value) ? value.slice(0, count) : []);
  const texts = (value) =>
    list(value, 5)
      .map((text) => scrub(text, 300))
      .filter(Boolean);
  const path = (value) => {
    const text = scrub(value, 200);
    return /^\/[^?#]*$|^[a-z]+:$/.test(text) ? text : "";
  };
  const identifier = (value) => {
    const text = scrub(value, 80);
    return /^[A-Za-z][A-Za-z0-9_]*$/.test(text) ? text : "";
  };
  const count = (value, max) => (Number.isInteger(value) && value >= 0 ? Math.min(value, max) : 0);
  const network = raw?.network ?? {};
  const page = raw?.page;
  return {
    location: path(network.location),
    navigations: list(network.navigations, 5).map(path),
    httpErrors: list(network.httpErrors, 20).map((entry) => ({
      path: path(entry?.path),
      status:
        Number.isInteger(entry?.status) && entry.status >= 100 && entry.status < 600
          ? entry.status
          : 0,
    })),
    failed: list(network.failed, 20).map((entry) => ({
      path: path(entry?.path),
      error: /^net::ERR_[A-Z0-9_]{1,64}$/.test(entry?.error ?? "") ? entry.error : "other",
    })),
    pending: list(network.pending, 20).map((entry) => ({
      path: path(entry?.path),
      ageMs: count(entry?.ageMs, 3_600_000),
    })),
    pendingCount: count(network.pendingCount, 100_000),
    pageErrors: list(network.pageErrors, 10).map((name) => (errorTypes.has(name) ? name : "Error")),
    ...(page
      ? {
          alerts: texts(page.alerts),
          statuses: texts(page.statuses),
          headings: texts(page.headings),
          support: list(page.support, 5).map((entry) => ({
            code: identifier(entry?.code),
            reason: identifier(entry?.reason),
          })),
        }
      : { pageUnavailable: true }),
  };
}

export function startupStage(stage) {
  if (!stages.includes(stage)) throw new Error("invalid_browser_startup_stage");
  process.stdout.write(JSON.stringify({ id: 0, startupStage: stage }) + "\n");
}
