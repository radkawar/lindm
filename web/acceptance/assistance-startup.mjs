// Startup evidence is a closed vocabulary, never an exception message, stack,
// launch command, environment, page body or credential-bearing observation.
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
  if (!code && stage === "configuration" && configurationCodes.has(message)) code = message;
  if (!code && stage === "chromium_launch")
    code = launchSignatures.find(([signature]) => message.includes(signature))?.[1];
  if (!code && errorType === "SyntaxError") code = "javascript_syntax_error";
  if (!code && errorType === "TimeoutError") code = "startup_timeout";
  return {
    code: code ?? "browser_startup_failed",
    errorType,
    stage: stages.includes(stage) ? stage : "unknown",
  };
}

export function startupStage(stage) {
  if (!stages.includes(stage)) throw new Error("invalid_browser_startup_stage");
  process.stdout.write(JSON.stringify({ id: 0, startupStage: stage }) + "\n");
}
